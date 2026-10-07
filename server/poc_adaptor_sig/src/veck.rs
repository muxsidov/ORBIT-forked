//! The Step 3 encrypted-key offer and verifier, shared by Step 4 onwards (the Step 3 binary
//! keeps its own copy so it stays exactly as recorded in `thesis_log/test-results.md`).

use crate::{h_of_id, ParamWaters};
use ark_bn254::{Bn254, Fr as ScalarField, G1Projective as G, G2Projective as G2};
use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use ark_std::UniformRand;

/// What the Bank sends Alice: sk1, sk2 in the clear, commitments to k, the hint, the ciphertext.
#[derive(Clone, Copy)]
pub struct Offer {
    pub sk1: G,
    pub sk2: G,
    pub y_g1: G,
    pub y_bn254: G2,
    pub t: G,
    pub c1: G2,
    pub c2: G2,
}

/// Bank's side: encrypt (sk1, sk2, sk3) for `tag` under exponent k.
pub fn make_offer<R: Rng>(param: &ParamWaters, tag: &str, key: (G, G, G2), k: ScalarField, rng: &mut R) -> Offer {
    let (sk1, sk2, sk3) = key;
    let b = ScalarField::rand(rng);
    let y_bn254 = param.g2 * k;
    Offer {
        sk1,
        sk2,
        y_g1: param.g * k,
        y_bn254,
        t: h_of_id(param, tag) * k,
        c1: param.g2 * b,
        c2: y_bn254 * b + sk3,
    }
}

/// Alice's side: consistency, hint, check 1 and check 2 on the encrypted sk3.
pub fn verify(param: &ParamWaters, tag: &str, o: &Offer) -> bool {
    let h_tag = h_of_id(param, tag);
    let consistent = Bn254::pairing(o.y_g1, param.g2) == Bn254::pairing(param.g, o.y_bn254);
    let hint = Bn254::pairing(o.t, param.g2) == Bn254::pairing(h_tag, o.y_bn254);
    let check1 = Bn254::pairing(o.sk2, param.g2)
        == Bn254::pairing(param.g, o.c2) - Bn254::pairing(o.y_g1, o.c1);
    let check2 = Bn254::pairing(o.sk1, param.g2)
        == Bn254::pairing(param.g_alpha, param.g2_beta) + Bn254::pairing(h_tag, o.c2)
            - Bn254::pairing(o.t, o.c1);
    consistent && hint && check1 && check2
}

pub fn decrypt(o: &Offer, k: ScalarField) -> G2 {
    o.c2 - o.c1 * k
}
