//! Part A / Step 2 — verify Waters check 1 on an *encrypted* sk3, from public values only.
//!
//! The Bank publishes Y_G1 = g^k and Y_bn254 = g2^k (same exponent k, on the Waters params'
//! own generators) and the ciphertext (c1, c2) = (g2^b, Y_bn254^b · sk3). Alice checks
//!   consistency:  e(Y_G1, g2) == e(g, Y_bn254)
//!   check 1:      e(sk2, g2)  == e(g, c2) · e(Y_G1, c1)^{-1}
//! The right-hand side of check 1 equals e(g, c2 · c1^{-k}) = e(g, Dec), so passing it pins
//! Dec = g2^r for any c1. Check 2 (h_tag) is Step 3; the cross-group link to Y_chain is Step 4.
//!
//! Run with: cargo run --bin step2_check1_encrypted

use ark_bn254::{Bn254, Fr as ScalarField, G1Projective as G, G2Projective as G2};
use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use poc_adaptor_sig::{derive_waters_key, generate_params, waters_checks_pass, ParamWaters};

/// What the Bank sends Alice for check 1 (sk1 is unused until Step 3).
#[derive(Clone, Copy)]
struct Offer {
    sk2: G,
    y_g1: G,
    y_bn254: G2,
    c1: G2,
    c2: G2,
}

/// Alice's side: public values only — no k, no b, no sk3.
fn verify_check1(param: &ParamWaters, o: &Offer) -> bool {
    let consistent = Bn254::pairing(o.y_g1, param.g2) == Bn254::pairing(param.g, o.y_bn254);
    // GT is written additively in arkworks: e(g,c2)·e(Y_G1,c1)^{-1} → e(g,c2) - e(Y_G1,c1).
    let rhs = Bn254::pairing(param.g, o.c2) - Bn254::pairing(o.y_g1, o.c1);
    let check1 = Bn254::pairing(o.sk2, param.g2) == rhs;
    consistent && check1
}

fn decrypt(o: &Offer, k: ScalarField) -> G2 {
    o.c2 - o.c1 * k
}

fn expect(name: &str, got: bool, want: bool) {
    assert_eq!(got, want, "{name}: verifier returned {got}, expected {want}");
    println!("[ok] {name}: verifier {}", if got { "accepts" } else { "rejects" });
}

fn main() {
    let mut rng = ark_std::test_rng();
    let param = generate_params(&mut rng);
    let tag = "001_042";
    let (sk1, sk2, sk3) = derive_waters_key(&param, tag, &mut rng);

    // --- Bank: commit to k, encrypt sk3 ---
    let k = ScalarField::rand(&mut rng);
    let b = ScalarField::rand(&mut rng);
    let y_bn254 = param.g2 * k;
    let honest = Offer {
        sk2,
        y_g1: param.g * k,
        y_bn254,
        c1: param.g2 * b,
        c2: y_bn254 * b + sk3,
    };

    // --- Positive ---
    expect("honest offer", verify_check1(&param, &honest), true);
    let dec = decrypt(&honest, k);
    assert_eq!(dec, sk3);
    assert!(waters_checks_pass(&param, tag, sk1, sk2, dec));
    println!("[ok] honest offer decrypts to sk3 after k is revealed");

    // Arbitrary c1: check 1 doesn't need c1 well-formed — if c2 = c1^k · sk3 it still passes
    // and still decrypts correctly.
    let c1_rand = G2::rand(&mut rng);
    let odd_c1 = Offer { c1: c1_rand, c2: c1_rand * k + sk3, ..honest };
    expect("arbitrary c1, consistent c2", verify_check1(&param, &odd_c1), true);
    assert_eq!(decrypt(&odd_c1, k), sk3);
    println!("[ok] arbitrary-c1 offer still decrypts to sk3");

    // --- Negative: a cheating Bank must be caught before Alice pays ---
    let tampered = Offer { c2: honest.c2 + G2::rand(&mut rng), ..honest };
    expect("tampered c2", verify_check1(&param, &tampered), false);

    let (_, _, other_sk3) = derive_waters_key(&param, tag, &mut rng);
    let wrong_key = Offer { c2: y_bn254 * b + other_sk3, ..honest };
    expect("encrypts a different key's sk3", verify_check1(&param, &wrong_key), false);

    let k_other = ScalarField::rand(&mut rng);
    let mismatched = Offer { y_g1: param.g * k_other, ..honest };
    expect("Y_G1 with a different exponent", verify_check1(&param, &mismatched), false);

    // Y_G1/Y_bn254 consistent with each other, but c2 masked under a different k:
    // decrypting with the advertised k would give garbage.
    let other_mask = Offer { c2: param.g2 * (k_other * b) + sk3, ..honest };
    expect("c2 masked under a different k", verify_check1(&param, &other_mask), false);

    // Commitments on curve generators instead of param.g/param.g2 (the Step 1 shortcut).
    let gen_commit = Offer {
        y_g1: <G as ark_ec::PrimeGroup>::generator() * k,
        y_bn254: <G2 as ark_ec::PrimeGroup>::generator() * k,
        c1: <G2 as ark_ec::PrimeGroup>::generator() * b,
        c2: <G2 as ark_ec::PrimeGroup>::generator() * (k * b) + sk3,
        ..honest
    };
    expect("commitments on curve generators", verify_check1(&param, &gen_commit), false);

    println!("\nStep 2 PASSED: Waters check 1 verifies on the encrypted sk3 from public values.");
    println!("NOT yet tested: check 2 (h_tag, sk1) — Step 3; Y_chain link — Step 4.");
}
