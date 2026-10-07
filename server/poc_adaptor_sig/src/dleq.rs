//! Cross-group discrete-log equality (Part A, Step 4).
//!
//! Proves that Y_a = x·G_a (group A, e.g. secp256k1) and Y_b = x·G_b (group B, e.g. BN254 G1)
//! share the same x, for x < 2^BITS, without revealing x. Bit-decomposition technique (as in
//! Monero↔Bitcoin atomic swaps, MRL-0010):
//! - For each bit x_i, Pedersen-commit in both groups: C_a = x_i·G_a + r_a·H_a,
//!   C_b = x_i·G_b + r_b·H_b. Blinders are chosen so Σ 2^i·r = 0 in each group, hence
//!   Σ 2^i·C_a = Y_a and Σ 2^i·C_b = Y_b.
//! - For each bit, a CDS OR-proof that (C_a, C_b) both open to 0 or both open to 1, i.e.
//!   knowledge of (r_a, r_b) with C_a - j·G_a = r_a·H_a and C_b - j·G_b = r_b·H_b for j ∈ {0,1}.
//!   The two groups have different orders, so challenges are 128-bit integers (smaller than
//!   both) and the OR-split is XOR.
//! - Fiat-Shamir: one SHA-256 challenge over the statement and all commitments/announcements.
//!
//! The commitment sums only pin x modulo each group order; the bit proofs pin each digit to
//! {0,1}, so the committed value is the same integer x < 2^BITS < both orders in both groups.

use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use sha2::{Digest, Sha256};

/// Bit length of x; 2^252 is below both the secp256k1 (~2^256) and BN254 (~2^254) orders.
pub const BITS: usize = 252;

/// Pedersen bases for one group. `h` must have an unknown discrete log w.r.t. `g`.
#[derive(Clone, Copy)]
pub struct Bases<P: SWCurveConfig> {
    pub g: Projective<P>,
    pub h: Projective<P>,
}

#[derive(Clone, Copy)]
pub struct BitProof<A: SWCurveConfig, B: SWCurveConfig> {
    pub ca: Projective<A>,
    pub cb: Projective<B>,
    pub e0: u128,
    pub e1: u128,
    pub z0a: A::ScalarField,
    pub z0b: B::ScalarField,
    pub z1a: A::ScalarField,
    pub z1b: B::ScalarField,
}

#[derive(Clone)]
pub struct Proof<A: SWCurveConfig, B: SWCurveConfig> {
    pub bits: Vec<BitProof<A, B>>,
}

impl<A: SWCurveConfig, B: SWCurveConfig> Proof<A, B> {
    /// Size with compressed points and 32-byte scalars.
    pub fn size_bytes(&self) -> usize {
        self.bits
            .iter()
            .map(|p| {
                p.ca.into_affine().compressed_size()
                    + p.cb.into_affine().compressed_size()
                    + 16 * 2
                    + p.z0a.compressed_size() * 2
                    + p.z0b.compressed_size() * 2
            })
            .sum()
    }
}

/// Try-and-increment hash to curve (both target curves have cofactor 1). Nothing-up-my-sleeve
/// second generator: nobody knows its discrete log w.r.t. the standard one.
pub fn hash_to_curve<P: SWCurveConfig>(domain: &[u8]) -> Projective<P> {
    for ctr in 0u32.. {
        let digest = Sha256::new().chain_update(domain).chain_update(ctr.to_be_bytes()).finalize();
        let Some(x) = P::BaseField::from_random_bytes(&digest) else { continue };
        let Some(p) = Affine::<P>::get_point_from_x_unchecked(x, false) else { continue };
        let p = p.clear_cofactor();
        if !p.is_zero() {
            return p.into_group();
        }
    }
    unreachable!()
}

/// x as little-endian bytes; `None` if x ≥ 2^BITS.
fn bits_of(x: &[u8; 32]) -> Option<Vec<bool>> {
    let bits: Vec<bool> = (0..256).map(|i| (x[i / 8] >> (i % 8)) & 1 == 1).collect();
    if bits[BITS..].iter().any(|&b| b) {
        return None;
    }
    Some(bits[..BITS].to_vec())
}

/// Blinders r_0..r_{BITS-1} with Σ 2^i·r_i = 0.
fn zero_sum_blinders<F: PrimeField, R: Rng>(rng: &mut R) -> Vec<F> {
    let two = F::from(2u64);
    let mut r: Vec<F> = (0..BITS - 1).map(|_| F::rand(rng)).collect();
    let partial: F = r.iter().enumerate().map(|(i, ri)| two.pow([i as u64]) * ri).sum();
    r.push(-partial * two.pow([(BITS - 1) as u64]).inverse().unwrap());
    r
}

fn absorb<T: CanonicalSerialize>(h: &mut Sha256, v: &T) {
    let mut buf = Vec::new();
    v.serialize_compressed(&mut buf).unwrap();
    h.update(&buf);
}

/// Announcements for one bit: (R_a, R_b) for branch 0 and branch 1.
type Announce<A, B> = [(Projective<A>, Projective<B>); 2];

fn challenge<A: SWCurveConfig, B: SWCurveConfig>(
    sa: &Bases<A>, sb: &Bases<B>, ya: &Projective<A>, yb: &Projective<B>,
    commits: &[(Projective<A>, Projective<B>)], announces: &[Announce<A, B>],
) -> u128 {
    let mut h = Sha256::new();
    h.update(b"ORBIT/cross-group-dleq/v1");
    for p in [sa.g, sa.h, *ya] { absorb(&mut h, &p.into_affine()); }
    for p in [sb.g, sb.h, *yb] { absorb(&mut h, &p.into_affine()); }
    for ((ca, cb), ann) in commits.iter().zip(announces) {
        absorb(&mut h, &ca.into_affine());
        absorb(&mut h, &cb.into_affine());
        for (ra, rb) in ann {
            absorb(&mut h, &ra.into_affine());
            absorb(&mut h, &rb.into_affine());
        }
    }
    u128::from_le_bytes(h.finalize()[..16].try_into().unwrap())
}

/// Prover. Returns `None` if x ≥ 2^BITS (x would not fit both groups' scalar fields as one
/// integer).
pub fn prove<A: SWCurveConfig, B: SWCurveConfig, R: Rng>(
    sa: &Bases<A>, sb: &Bases<B>, x: &[u8; 32], rng: &mut R,
) -> Option<Proof<A, B>> {
    let bits = bits_of(x)?;
    let ra = zero_sum_blinders::<A::ScalarField, _>(rng);
    let rb = zero_sum_blinders::<B::ScalarField, _>(rng);
    let ya = sa.g * A::ScalarField::from_le_bytes_mod_order(x);
    let yb = sb.g * B::ScalarField::from_le_bytes_mod_order(x);

    let mut commits = Vec::with_capacity(BITS);
    let mut announces = Vec::with_capacity(BITS);
    // Per bit: real nonces (ka, kb) and the simulated branch's (e, za, zb).
    let mut secrets = Vec::with_capacity(BITS);
    for i in 0..BITS {
        let bit = bits[i] as usize;
        let ca = sa.g * A::ScalarField::from(bit as u64) + sa.h * ra[i];
        let cb = sb.g * B::ScalarField::from(bit as u64) + sb.h * rb[i];
        let (ka, kb) = (A::ScalarField::rand(rng), B::ScalarField::rand(rng));
        let sim = 1 - bit;
        let (es, zsa, zsb): (u128, _, _) = (rng.gen(), A::ScalarField::rand(rng), B::ScalarField::rand(rng));
        let mut ann = [(Projective::<A>::zero(), Projective::<B>::zero()); 2];
        ann[bit] = (sa.h * ka, sb.h * kb);
        ann[sim] = (
            sa.h * zsa - (ca - sa.g * A::ScalarField::from(sim as u64)) * A::ScalarField::from(es),
            sb.h * zsb - (cb - sb.g * B::ScalarField::from(sim as u64)) * B::ScalarField::from(es),
        );
        commits.push((ca, cb));
        announces.push(ann);
        secrets.push((ka, kb, es, zsa, zsb));
    }

    let e = challenge(sa, sb, &ya, &yb, &commits, &announces);
    let proofs = (0..BITS)
        .map(|i| {
            let bit = bits[i];
            let (ka, kb, es, zsa, zsb) = secrets[i];
            let er = e ^ es;
            let zra = ka + A::ScalarField::from(er) * ra[i];
            let zrb = kb + B::ScalarField::from(er) * rb[i];
            let (ca, cb) = commits[i];
            if bit {
                BitProof { ca, cb, e0: es, e1: er, z0a: zsa, z0b: zsb, z1a: zra, z1b: zrb }
            } else {
                BitProof { ca, cb, e0: er, e1: es, z0a: zra, z0b: zrb, z1a: zsa, z1b: zsb }
            }
        })
        .collect();
    Some(Proof { bits: proofs })
}

/// Verifier: accepts iff the proof shows Y_a and Y_b share one x < 2^BITS.
pub fn verify<A: SWCurveConfig, B: SWCurveConfig>(
    sa: &Bases<A>, sb: &Bases<B>, ya: &Projective<A>, yb: &Projective<B>, proof: &Proof<A, B>,
) -> bool {
    if proof.bits.len() != BITS {
        return false;
    }
    let (two_a, two_b) = (A::ScalarField::from(2u64), B::ScalarField::from(2u64));
    let sum_a: Projective<A> = proof.bits.iter().enumerate().map(|(i, p)| p.ca * two_a.pow([i as u64])).sum();
    let sum_b: Projective<B> = proof.bits.iter().enumerate().map(|(i, p)| p.cb * two_b.pow([i as u64])).sum();
    if sum_a != *ya || sum_b != *yb {
        return false;
    }

    let commits: Vec<_> = proof.bits.iter().map(|p| (p.ca, p.cb)).collect();
    let announces: Vec<Announce<A, B>> = proof
        .bits
        .iter()
        .map(|p| {
            let branch = |j: u64, e: u128, za: A::ScalarField, zb: B::ScalarField| {
                (
                    sa.h * za - (p.ca - sa.g * A::ScalarField::from(j)) * A::ScalarField::from(e),
                    sb.h * zb - (p.cb - sb.g * B::ScalarField::from(j)) * B::ScalarField::from(e),
                )
            };
            [branch(0, p.e0, p.z0a, p.z0b), branch(1, p.e1, p.z1a, p.z1b)]
        })
        .collect();
    let e = challenge(sa, sb, ya, yb, &commits, &announces);
    proof.bits.iter().all(|p| p.e0 ^ p.e1 == e)
}

/// Uniform x < 2^BITS as little-endian bytes.
pub fn random_x<R: Rng>(rng: &mut R) -> [u8; 32] {
    let mut x: [u8; 32] = rng.gen();
    x[31] &= 0x0f; // clear bits 252..255
    x
}
