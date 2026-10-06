//! Part A / Step 1 (baseline) — plain ElGamal-in-G2 masking of a real Waters `sk3`,
//! decrypted with the masking scalar known directly. No pairing-hiding trick yet, no
//! secp256k1 two-hop witness yet — this only establishes the group-type-correct floor:
//! that masking/unmasking `sk3` this way round-trips exactly, and that the recovered key
//! still passes both Waters pairing checks used elsewhere in this codebase
//! (see `water_derive_ak` in server/rustcode/src/lib.rs).
//!
//! Run with: cargo run --bin step1_baseline_elgamal

use ark_bn254::{Bn254, Fr as ScalarField, G1Projective as G, G2Projective as G2};
use ark_ec::pairing::Pairing;
use ark_ec::PrimeGroup;
use ark_std::rand::Rng;
use ark_std::UniformRand;

struct ParamWaters {
    beta_secret: ScalarField,
    g: G,
    g_alpha: G,
    g2: G2,
    g2_beta: G2,
    h_vec: Vec<G>,
    h_0: G,
}

// Mirrors generate_params_waters() in server/rustcode/src/lib.rs.
fn generate_params<R: Rng + ?Sized>(rng: &mut R) -> ParamWaters {
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
fn h_of_id(param: &ParamWaters, id: &str) -> G {
    id.bytes()
        .enumerate()
        .flat_map(|(byte_idx, byte)| {
            (0u8..8)
                .filter(move |bit| (byte >> bit) & 1 == 1)
                .map(move |bit| byte_idx * 8 + bit as usize)
        })
        .fold(param.h_0, |acc, i| acc + param.h_vec[i])
}

// Mirrors water_derive_ak() in server/rustcode/src/lib.rs — ground-truth key generation,
// including its own internal sanity asserts (pre-masking).
fn derive_waters_key<R: Rng + ?Sized>(param: &ParamWaters, tag: &str, rng: &mut R) -> (G, G, G2) {
    let rand_r = ScalarField::rand(rng);
    let h_tag = h_of_id(param, tag);

    let sk1 = (param.g_alpha * param.beta_secret) + (h_tag * rand_r);
    let sk2 = param.g * rand_r;
    let sk3 = param.g2 * rand_r;

    let lhs = Bn254::pairing(param.g_alpha, param.g2_beta) + Bn254::pairing(h_tag, sk3);
    let rhs = Bn254::pairing(sk1, param.g2);
    assert_eq!(lhs, rhs, "ground-truth check 1 failed");
    assert_eq!(
        Bn254::pairing(sk2, param.g2),
        Bn254::pairing(param.g, sk3),
        "ground-truth check 2 failed"
    );

    (sk1, sk2, sk3)
}

fn waters_checks_pass(param: &ParamWaters, tag: &str, sk1: G, sk2: G, sk3: G2) -> bool {
    let h_tag = h_of_id(param, tag);
    let check1 = Bn254::pairing(sk2, param.g2) == Bn254::pairing(param.g, sk3);
    let lhs = Bn254::pairing(param.g_alpha, param.g2_beta) + Bn254::pairing(h_tag, sk3);
    let check2 = lhs == Bn254::pairing(sk1, param.g2);
    check1 && check2
}

fn main() {
    let mut rng = ark_std::test_rng();
    let param = generate_params(&mut rng);
    let tag = "001_042";

    let (sk1, sk2, sk3) = derive_waters_key(&param, tag, &mut rng);
    println!("[ok] ground-truth Waters key passes both checks pre-masking");

    // --- Baseline ElGamal-in-G2 masking of sk3 ---
    // x is the Bank's secret; Y = g2^x is its public commitment. Both x and Y live in G2
    // here, matching sk3's own group — deliberately the simplest possible version, with
    // no attempt yet at verifying anything about sk3 before it is decrypted.
    let x = ScalarField::rand(&mut rng);
    let g2_gen = G2::generator();
    let y = g2_gen * x;

    let b = ScalarField::rand(&mut rng);
    let c1 = g2_gen * b;
    let c2 = y * b + sk3; // c2 = Y^b . sk3, written additively

    // "Reveal" x (simulates the on-chain adaptor-signature reveal) and decrypt.
    let recovered_sk3 = c2 - c1 * x;
    assert_eq!(recovered_sk3, sk3, "decryption did not recover the original sk3");
    println!("[ok] baseline ElGamal-in-G2 round trip recovers sk3 exactly");

    assert!(
        waters_checks_pass(&param, tag, sk1, sk2, recovered_sk3),
        "recovered key failed the Waters checks"
    );
    println!("[ok] recovered (sk1, sk2, sk3) passes both Waters pairing checks");

    println!("\nStep 1 PASSED: baseline masking/unmasking is sound.");
    println!(
        "NOT yet tested: verifying either Waters check *before* decrypting sk3 (the actual \
         VECK property CLAUDE_replace_HTLC.md's design depends on) — that's Step 2."
    );
}
