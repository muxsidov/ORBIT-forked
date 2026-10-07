//! Part A / Step 4 — link the on-chain secret to the encrypted Waters key, across curves.
//!
//! With k = x, the Bank publishes Y_chain = x·G on secp256k1 (the adaptor-signature statement
//! the chain will see) next to the Step 3 offer (Y_G1 = g^x, Y_bn254 = g2^x, T, c1, c2), plus a
//! cross-group DLEQ proof that Y_chain and Y_G1 hide the same x < 2^252 (`dleq.rs`). Step 3's
//! consistency check already ties Y_G1 to Y_bn254, so a passing offer guarantees: the x that
//! the Bank must reveal on-chain to get paid decrypts sk3.
//!
//! Run with: cargo run --release --bin step4_cross_group_link

use ark_bn254::{g1::Config as Bn254G1, Fr as BnFr};
use ark_ec::PrimeGroup;
use ark_ff::{BigInteger, PrimeField};
use ark_secp256k1::{Config as Secp, Fr as SecpFr, Projective as SecpPoint};
use poc_adaptor_sig::dleq::{self, Bases, Proof};
use poc_adaptor_sig::veck::{self, Offer};
use poc_adaptor_sig::{derive_waters_key, generate_params, waters_checks_pass, ParamWaters};
use std::time::Instant;

/// Everything the Bank sends Alice in Step 4.
#[derive(Clone)]
struct LinkedOffer {
    offer: Offer,
    y_chain: SecpPoint,
    proof: Proof<Secp, Bn254G1>,
}

/// Alice's full check: Step 3 checks on the ciphertext, plus the cross-group link.
fn verify(param: &ParamWaters, tag: &str, sa: &Bases<Secp>, sb: &Bases<Bn254G1>, lo: &LinkedOffer) -> bool {
    veck::verify(param, tag, &lo.offer) && dleq::verify(sa, sb, &lo.y_chain, &lo.offer.y_g1, &lo.proof)
}

fn expect(name: &str, got: bool, want: bool) {
    assert_eq!(got, want, "{name}: verifier returned {got}, expected {want}");
    println!("[ok] {name}: verifier {}", if got { "accepts" } else { "rejects" });
}

fn main() {
    let mut rng = ark_std::test_rng();
    let param = generate_params(&mut rng);
    let tag = "001_042";
    let key = derive_waters_key(&param, tag, &mut rng);
    let sk3 = key.2;

    // Pedersen bases: standard generator + hashed second generator on secp256k1; the Waters
    // param.g + hashed second generator on BN254 G1 (so the BN254 side sums to Y_G1 = g^x).
    let sa = Bases::<Secp> { g: SecpPoint::generator(), h: dleq::hash_to_curve::<Secp>(b"ORBIT/dleq/secp256k1/H") };
    let sb = Bases::<Bn254G1> { g: param.g, h: dleq::hash_to_curve::<Bn254G1>(b"ORBIT/dleq/bn254-g1/H") };

    let x = dleq::random_x(&mut rng);
    let x_secp = SecpFr::from_le_bytes_mod_order(&x);
    let x_bn = BnFr::from_le_bytes_mod_order(&x);
    let x_other = dleq::random_x(&mut rng);
    let x_other_bn = BnFr::from_le_bytes_mod_order(&x_other);

    // --- Gap: without the link, Step 3's verifier can't see a mismatched Y_chain ---
    let mismatched_offer = veck::make_offer(&param, tag, key, x_other_bn, &mut rng);
    assert!(veck::verify(&param, tag, &mismatched_offer));
    assert_ne!(veck::decrypt(&mismatched_offer, x_bn), sk3);
    println!("[ok] (gap reproduced: offer encrypted under x' passes Step 3; revealing the chain's x does not decrypt it)");

    // --- Positive ---
    let start = Instant::now();
    let proof = dleq::prove(&sa, &sb, &x, &mut rng).expect("x < 2^252");
    let t_prove = start.elapsed();
    let honest = LinkedOffer {
        offer: veck::make_offer(&param, tag, key, x_bn, &mut rng),
        y_chain: sa.g * x_secp,
        proof,
    };
    let start = Instant::now();
    let ok = dleq::verify(&sa, &sb, &honest.y_chain, &honest.offer.y_g1, &honest.proof);
    let t_verify = start.elapsed();
    expect("honest linked offer", ok && verify(&param, tag, &sa, &sb, &honest), true);
    // Simulated on-chain reveal: Alice learns x as a secp256k1 scalar and re-reads it in BN254.
    let revealed = BnFr::from_le_bytes_mod_order(&x_secp.into_bigint().to_bytes_le());
    let dec = veck::decrypt(&honest.offer, revealed);
    assert_eq!(dec, sk3);
    assert!(waters_checks_pass(&param, tag, honest.offer.sk1, honest.offer.sk2, dec));
    println!("[ok] x revealed as a secp256k1 scalar decrypts sk3; key passes both Waters checks");
    println!(
        "     DLEQ: {} bits, proof {:.1} KB, prove {:.0} ms, verify {:.0} ms (release, single run)",
        dleq::BITS, honest.proof.size_bytes() as f64 / 1024.0,
        t_prove.as_secs_f64() * 1e3, t_verify.as_secs_f64() * 1e3
    );

    // --- Negative: the link ---
    let wrong_chain = LinkedOffer { y_chain: sa.g * SecpFr::from_le_bytes_mod_order(&x_other), ..honest.clone() };
    expect("Y_chain for a different x, honest proof", verify(&param, tag, &sa, &sb, &wrong_chain), false);

    // The cheat from the gap above, now with a genuine proof for x' (chain side x).
    let proof_other = dleq::prove(&sa, &sb, &x_other, &mut rng).unwrap();
    let cheat = LinkedOffer { offer: mismatched_offer, y_chain: honest.y_chain, proof: proof_other.clone() };
    expect("offer under x', valid proof for x', Y_chain for x", verify(&param, tag, &sa, &sb, &cheat), false);

    let replay = LinkedOffer { proof: proof_other, ..honest.clone() };
    expect("proof replayed from another statement", verify(&param, tag, &sa, &sb, &replay), false);

    let mut big_x = x;
    big_x[31] |= 0x10; // bit 252 set
    assert!(dleq::prove(&sa, &sb, &big_x, &mut rng).is_none());
    println!("[ok] x ≥ 2^252: prover refuses");

    // --- Negative: tampered proof ---
    let mut t = honest.clone();
    t.proof.bits[0].ca += sa.g;
    expect("bit commitment changed (secp side)", verify(&param, tag, &sa, &sb, &t), false);

    // Shift weight between two bits so the sums still match Y_chain / Y_G1: bit 0 commitment
    // +2·G, bit 1 commitment −G (in both groups). Only the bit proofs can catch this.
    let mut t = honest.clone();
    t.proof.bits[0].ca += sa.g + sa.g;
    t.proof.bits[1].ca -= sa.g;
    t.proof.bits[0].cb += sb.g + sb.g;
    t.proof.bits[1].cb -= sb.g;
    expect("non-binary digits with matching sums", verify(&param, tag, &sa, &sb, &t), false);

    let mut t = honest.clone();
    t.proof.bits[5].z1b += BnFr::from(1u64);
    expect("response changed", verify(&param, tag, &sa, &sb, &t), false);

    let mut t = honest.clone();
    t.proof.bits[7].e0 ^= 1;
    t.proof.bits[7].e1 ^= 1;
    expect("challenge split changed (XOR still matches)", verify(&param, tag, &sa, &sb, &t), false);

    let mut t = honest.clone();
    t.proof.bits.pop();
    expect("proof truncated to 251 bits", verify(&param, tag, &sa, &sb, &t), false);

    println!("\nStep 4 PASSED: the on-chain secret provably decrypts the verified encrypted key.");
    println!("NOT yet tested: a real on-chain reveal via an adaptor signature — Part B.");
}
