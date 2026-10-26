//! ECDSA adaptor signatures on secp256k1 (Part B), after Aumayr et al., *Generalized Channels
//! from Limited Blockchain Scripts and Adaptor Signatures*, Fig. 5.
//!
//! Signer key a, A = a·G. Statement Y = y·G (here: Y_chain, y = x).
//! - pSign(a, m, Y):  k random, R = k·G, R' = k·Y, r = x(R') mod n, s' = k⁻¹(z + r·a),
//!                    plus a DLEQ proof that log_G R = log_Y R' (= k).
//! - pVerify:         R == z·s'⁻¹·G + r·s'⁻¹·A, r == x(R') mod n, DLEQ proof valid.
//! - Adapt(σ̂, y):    s = s'·y⁻¹. Then s⁻¹(z·G + r·A) = y·R = R', so (r, s) is an ordinary ECDSA
//!                    signature under A.
//! - Extract(σ, σ̂, Y): y = s'·s⁻¹, or its negation if s was low-s normalised (s → n − s, as
//!                    Bitcoin and Ethereum require); checked against Y.
//!
//! Algebra uses arkworks; `to_k256` converts for verification with an independent, standard
//! ECDSA implementation (`k256`), which is what a chain would run.

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand, Zero};
use ark_secp256k1::{Affine, Fr, Projective};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use sha2::{Digest, Sha256};

/// A pre-signature: (r, s', R, R', DLEQ proof (c, z)).
#[derive(Clone, Copy)]
pub struct PreSignature {
    pub r: Fr,
    pub s_pre: Fr,
    pub big_r: Projective,
    pub big_r_prime: Projective,
    pub dleq_c: Fr,
    pub dleq_z: Fr,
}

/// An ordinary ECDSA signature (r, s).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature {
    pub r: Fr,
    pub s: Fr,
}

/// ECDSA message scalar z from a 32-byte digest (big-endian, reduced mod n — as k256 does).
pub fn msg_scalar(digest: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(digest)
}

/// x-coordinate of a point, reduced mod n.
fn x_mod_n(p: &Projective) -> Fr {
    let x = p.into_affine().x().unwrap();
    Fr::from_be_bytes_mod_order(&x.into_bigint().to_bytes_be())
}

fn dleq_challenge(y: &Projective, r: &Projective, r_prime: &Projective, t1: &Projective, t2: &Projective) -> Fr {
    let mut h = Sha256::new();
    h.update(b"ORBIT/ecdsa-adaptor/dleq/v1");
    for p in [Projective::generator(), *y, *r, *r_prime, *t1, *t2] {
        let mut buf = Vec::new();
        p.into_affine().serialize_compressed(&mut buf).unwrap();
        h.update(&buf);
    }
    Fr::from_be_bytes_mod_order(&h.finalize())
}

pub fn p_sign<R: Rng>(a: Fr, digest: &[u8; 32], y: &Projective, rng: &mut R) -> PreSignature {
    let g = Projective::generator();
    let z = msg_scalar(digest);
    loop {
        let k = Fr::rand(rng);
        let big_r = g * k;
        let big_r_prime = *y * k;
        let r = x_mod_n(&big_r_prime);
        let s_pre = k.inverse().unwrap() * (z + r * a);
        if r.is_zero() || s_pre.is_zero() {
            continue;
        }
        let t = Fr::rand(rng);
        let dleq_c = dleq_challenge(y, &big_r, &big_r_prime, &(g * t), &(*y * t));
        let dleq_z = t + dleq_c * k;
        return PreSignature { r, s_pre, big_r, big_r_prime, dleq_c, dleq_z };
    }
}

pub fn p_verify(pk: &Projective, digest: &[u8; 32], y: &Projective, ps: &PreSignature) -> bool {
    let g = Projective::generator();
    let Some(s_inv) = ps.s_pre.inverse() else { return false };
    let z = msg_scalar(digest);
    let r_ok = ps.big_r == g * (z * s_inv) + *pk * (ps.r * s_inv);
    let x_ok = ps.r == x_mod_n(&ps.big_r_prime) && !ps.r.is_zero();
    let t1 = g * ps.dleq_z - ps.big_r * ps.dleq_c;
    let t2 = *y * ps.dleq_z - ps.big_r_prime * ps.dleq_c;
    let dleq_ok = ps.dleq_c == dleq_challenge(y, &ps.big_r, &ps.big_r_prime, &t1, &t2);
    r_ok && x_ok && dleq_ok
}

/// Complete the pre-signature with the witness y. Returns the raw (possibly high-s) signature.
pub fn adapt(ps: &PreSignature, y: Fr) -> Signature {
    Signature { r: ps.r, s: ps.s_pre * y.inverse().unwrap() }
}

/// s > n/2?
pub fn is_high_s(s: &Fr) -> bool {
    s.into_bigint() > Fr::MODULUS_MINUS_ONE_DIV_TWO
}

/// Low-s normalisation (s → n − s), as Bitcoin policy and Ethereum transaction rules require.
pub fn normalize(sig: Signature) -> Signature {
    if is_high_s(&sig.s) { Signature { r: sig.r, s: -sig.s } } else { sig }
}

/// Recover the witness from a published signature and the pre-signature.
pub fn extract(sig: &Signature, ps: &PreSignature, y: &Projective) -> Option<Fr> {
    if sig.r != ps.r {
        return None;
    }
    let cand = ps.s_pre * sig.s.inverse()?;
    let g = Projective::generator();
    [cand, -cand].into_iter().find(|c| g * c == *y)
}

// ---- conversion to k256 (the independent verifier) ----

fn fr_be(x: &Fr) -> [u8; 32] {
    x.into_bigint().to_bytes_be().try_into().unwrap()
}

pub fn to_k256_sig(sig: &Signature) -> Option<k256::ecdsa::Signature> {
    k256::ecdsa::Signature::from_scalars(fr_be(&sig.r), fr_be(&sig.s)).ok()
}

/// SEC1 uncompressed encoding 0x04 || x || y.
pub fn sec1_uncompressed(p: &Projective) -> [u8; 65] {
    let a: Affine = p.into_affine();
    let mut out = [0u8; 65];
    out[0] = 4;
    out[1..33].copy_from_slice(&a.x.into_bigint().to_bytes_be());
    out[33..].copy_from_slice(&a.y.into_bigint().to_bytes_be());
    out
}

pub fn to_k256_key(p: &Projective) -> k256::ecdsa::VerifyingKey {
    k256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1_uncompressed(p)).unwrap()
}

/// Standard ECDSA verification with k256 (rejects high-s, like Bitcoin).
pub fn k256_verify(pk: &Projective, digest: &[u8; 32], sig: &Signature) -> bool {
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    match to_k256_sig(sig) {
        Some(s) => to_k256_key(pk).verify_prehash(digest, &s).is_ok(),
        None => false,
    }
}

/// Ethereum address: last 20 bytes of keccak256(x || y).
pub fn eth_address(pk: &Projective) -> [u8; 20] {
    use sha3::{Digest as _, Keccak256};
    let h = Keccak256::digest(&sec1_uncompressed(pk)[1..]);
    h[12..].try_into().unwrap()
}

/// What Ethereum's `ecrecover` would return for (digest, r, s, v), via k256 recovery; tries
/// both recovery ids, returns the addresses that recover.
pub fn ecrecover_addresses(digest: &[u8; 32], sig: &Signature) -> Vec<[u8; 20]> {
    let Some(s) = to_k256_sig(sig) else { return vec![] };
    [false, true]
        .into_iter()
        .filter_map(|odd| {
            let id = k256::ecdsa::RecoveryId::new(odd, false);
            k256::ecdsa::VerifyingKey::recover_from_prehash(digest, &s, id).ok()
        })
        .map(|vk| {
            use sha3::{Digest as _, Keccak256};
            let pt = vk.to_encoded_point(false);
            Keccak256::digest(&pt.as_bytes()[1..])[12..].try_into().unwrap()
        })
        .collect()
}
