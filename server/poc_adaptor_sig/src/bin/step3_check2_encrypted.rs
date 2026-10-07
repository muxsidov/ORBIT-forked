//! Part A / Step 3 — verify *both* Waters checks on an encrypted sk3, from public values only.
//!
//! Step 2 showed check 1 works encrypted, but check 1 alone accepts any self-consistent
//! (g^{r'}, g2^{r'}). Check 2 ties r to sk1 and the tag, and needs e(h_tag, Dec). h_tag is not a
//! power of g, so the Bank adds a per-tag hint T = h_tag^k. Alice computes h_tag herself from
//! her own tag and checks
//!   consistency:  e(Y_G1, g2) == e(g, Y_bn254)
//!   hint:         e(T, g2)    == e(h_tag, Y_bn254)
//!   check 1:      e(sk2, g2)  == e(g, c2) · e(Y_G1, c1)^{-1}
//!   check 2:      e(sk1, g2)  == e(g_alpha, g2_beta) · e(h_tag, c2) · e(T, c1)^{-1}
//! With T = h_tag^k, e(h_tag, c2) · e(T, c1)^{-1} = e(h_tag, c2 · c1^{-k}) = e(h_tag, Dec).
//! The cross-group link to Y_chain is Step 4.
//!
//! Run with: cargo run --release --bin step3_check2_encrypted

use ark_bn254::{Bn254, Fr as ScalarField, G1Projective as G, G2Projective as G2};
use ark_ec::pairing::Pairing;
use ark_std::UniformRand;
use poc_adaptor_sig::{derive_waters_key, generate_params, h_of_id, waters_checks_pass, ParamWaters};
use std::time::Instant;

/// What the Bank sends Alice: sk1, sk2 in the clear, commitments to k, the hint, the ciphertext.
#[derive(Clone, Copy)]
struct Offer {
    sk1: G,
    sk2: G,
    y_g1: G,
    y_bn254: G2,
    t: G,
    c1: G2,
    c2: G2,
}

/// Alice's side: public values plus her own tag — no k, no b, no sk3.
/// GT is written additively in arkworks, so a·b^{-1} becomes a - b.
fn verify(param: &ParamWaters, tag: &str, o: &Offer) -> bool {
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

fn decrypt(o: &Offer, k: ScalarField) -> G2 {
    o.c2 - o.c1 * k
}

fn expect(name: &str, got: bool, want: bool) {
    assert_eq!(got, want, "{name}: verifier returned {got}, expected {want}");
    println!("[ok] {name}: verifier {}", if got { "accepts" } else { "rejects" });
}

/// Bank's side: encrypt a given (sk1, sk2, sk3) for `tag` under exponent k.
fn make_offer<R: ark_std::rand::Rng>(
    param: &ParamWaters, tag: &str, key: (G, G, G2), k: ScalarField, rng: &mut R,
) -> Offer {
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

fn main() {
    let mut rng = ark_std::test_rng();
    let param = generate_params(&mut rng);
    let tag = "001_042";
    let other_tag = "001_043";
    let key = derive_waters_key(&param, tag, &mut rng);
    let (sk1, _, sk3) = key;
    let k = ScalarField::rand(&mut rng);
    let k_other = ScalarField::rand(&mut rng);

    // --- Positive ---
    let honest = make_offer(&param, tag, key, k, &mut rng);
    let start = Instant::now();
    let ok = verify(&param, tag, &honest);
    let elapsed = start.elapsed();
    expect("honest offer", ok, true);
    let dec = decrypt(&honest, k);
    assert_eq!(dec, sk3);
    assert!(waters_checks_pass(&param, tag, honest.sk1, honest.sk2, dec));
    println!("[ok] honest offer decrypts to sk3 after k is revealed");
    println!("     verifier: 11 pairings (1 constant), {:.1} ms (release, single run)", elapsed.as_secs_f64() * 1e3);

    // --- Negative: the hint ---
    let random_t = Offer { t: G::rand(&mut rng), ..honest };
    expect("random T", verify(&param, tag, &random_t), false);

    let t_other_tag = Offer { t: h_of_id(&param, other_tag) * k, ..honest };
    expect("T computed for a different tag", verify(&param, tag, &t_other_tag), false);

    let t_other_k = Offer { t: h_of_id(&param, tag) * k_other, ..honest };
    expect("T under a different exponent", verify(&param, tag, &t_other_k), false);

    // --- Negative: the key itself ---
    // The Step 2 gap: self-consistent (g^{r'}, g2^{r'}) passes check 1 but not check 2.
    let r_prime = ScalarField::rand(&mut rng);
    let fake_r = make_offer(&param, tag, (sk1, param.g * r_prime, param.g2 * r_prime), k, &mut rng);
    assert!(Bn254::pairing(fake_r.sk2, param.g2)
        == Bn254::pairing(param.g, fake_r.c2) - Bn254::pairing(fake_r.y_g1, fake_r.c1));
    println!("[ok] (Step 2 gap reproduced: self-consistent (g^r', g2^r') passes check 1 alone)");
    expect("self-consistent (sk2', sk3') with the original sk1", verify(&param, tag, &fake_r), false);

    let tampered_sk1 = Offer { sk1: sk1 + G::rand(&mut rng), ..honest };
    expect("tampered sk1", verify(&param, tag, &tampered_sk1), false);

    // A fully valid key, honestly encrypted — but for someone else's tag.
    let other_key = derive_waters_key(&param, other_tag, &mut rng);
    let wrong_tag_key = make_offer(&param, other_tag, other_key, k, &mut rng);
    expect("valid key for a different tag", verify(&param, tag, &wrong_tag_key), false);

    let tampered_c2 = Offer { c2: honest.c2 + G2::rand(&mut rng), ..honest };
    expect("tampered c2", verify(&param, tag, &tampered_c2), false);

    println!("\nStep 3 PASSED: both Waters checks verify on the encrypted sk3 from public values.");
    println!("NOT yet tested: that Y_chain on secp256k1 hides the same secret as Y_bn254 — Step 4.");
}
