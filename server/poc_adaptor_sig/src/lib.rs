//! Shared Waters helpers for the Part A step binaries (Step 2 onwards). Step 1 keeps its own
//! inline copy so it stays exactly as recorded in the thesis log.

pub mod adaptor;
pub mod btc;
pub mod dleq;
pub mod veck;

use ark_bn254::{Bn254, Fr as ScalarField, G1Projective as G, G2Projective as G2};
use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use ark_std::UniformRand;

pub struct ParamWaters {
    pub beta_secret: ScalarField,
    pub g: G,
    pub g_alpha: G,
    pub g2: G2,
    pub g2_beta: G2,
    pub h_vec: Vec<G>,
    pub h_0: G,
}

// Mirrors generate_params_waters() in server/rustcode/src/lib.rs.
pub fn generate_params<R: Rng + ?Sized>(rng: &mut R) -> ParamWaters {
    let alpha_secret = ScalarField::rand(rng);
    let beta_secret = alpha_secret;
    let g = G::rand(rng);
    let g_alpha = g * alpha_secret;
    let g2 = G2::rand(rng);
    let g2_beta = g2 * beta_secret;
    let h_0 = G::rand(rng);
    let h_vec = (0..256).map(|_| G::rand(rng)).collect();
    ParamWaters { beta_secret, g, g_alpha, g2, g2_beta, h_vec, h_0 }
}

// Mirrors h_of_id() in server/rustcode/src/lib.rs.
pub fn h_of_id(param: &ParamWaters, id: &str) -> G {
    id.bytes()
        .enumerate()
        .flat_map(|(byte_idx, byte)| {
            (0u8..8)
                .filter(move |bit| (byte >> bit) & 1 == 1)
                .map(move |bit| byte_idx * 8 + bit as usize)
        })
        .fold(param.h_0, |acc, i| acc + param.h_vec[i])
}

// Mirrors water_derive_ak() in server/rustcode/src/lib.rs.
pub fn derive_waters_key<R: Rng + ?Sized>(param: &ParamWaters, tag: &str, rng: &mut R) -> (G, G, G2) {
    let rand_r = ScalarField::rand(rng);
    let h_tag = h_of_id(param, tag);
    let sk1 = (param.g_alpha * param.beta_secret) + (h_tag * rand_r);
    let sk2 = param.g * rand_r;
    let sk3 = param.g2 * rand_r;
    assert!(waters_checks_pass(param, tag, sk1, sk2, sk3), "ground-truth Waters key invalid");
    (sk1, sk2, sk3)
}

/// Check 1: e(sk2,g2) == e(g,sk3). Check 2: e(g_alpha,g2_beta)·e(h_tag,sk3) == e(sk1,g2).
pub fn waters_checks_pass(param: &ParamWaters, tag: &str, sk1: G, sk2: G, sk3: G2) -> bool {
    let h_tag = h_of_id(param, tag);
    let check1 = Bn254::pairing(sk2, param.g2) == Bn254::pairing(param.g, sk3);
    let lhs = Bn254::pairing(param.g_alpha, param.g2_beta) + Bn254::pairing(h_tag, sk3);
    let check2 = lhs == Bn254::pairing(sk1, param.g2);
    check1 && check2
}
