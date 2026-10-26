//! Part B / Step B1 — ECDSA adaptor signature on secp256k1, end to end with the Part A offer.
//!
//! Alice pre-signs a transaction paying the Bank, under the statement Y_chain = x·G from the
//! Step 4 offer. The Bank completes it with x (the only way to get a valid signature); the
//! completed signature is checked by an independent standard ECDSA verifier (k256, low-s rule
//! as in Bitcoin) and by Ethereum-style address recovery (ecrecover). Alice extracts x from the
//! published signature and decrypts her Waters key.
//!
//! Run with: cargo run --release --bin b1_ecdsa_adaptor

use ark_bn254::{g1::Config as Bn254G1, Fr as BnFr};
use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_secp256k1::{Config as Secp, Fr as SecpFr, Projective as SecpPoint};
use poc_adaptor_sig::adaptor::{self, PreSignature, Signature};
use poc_adaptor_sig::dleq::{self, Bases};
use poc_adaptor_sig::{derive_waters_key, generate_params, veck, waters_checks_pass};
use sha2::{Digest, Sha256};
use std::time::Instant;

fn expect(name: &str, got: bool, want: bool) {
    assert_eq!(got, want, "{name}: got {got}, expected {want}");
    println!("[ok] {name}: {}", if got { "accepted" } else { "rejected" });
}

fn tx_digest(desc: &str) -> [u8; 32] {
    Sha256::digest(desc.as_bytes()).into()
}

fn main() {
    let mut rng = ark_std::test_rng();

    // --- Part A setup (Step 4): Bank's offer, verified by Alice ---
    let param = generate_params(&mut rng);
    let tag = "001_042";
    let key = derive_waters_key(&param, tag, &mut rng);
    let sk3 = key.2;
    let sa = Bases::<Secp> { g: SecpPoint::generator(), h: dleq::hash_to_curve::<Secp>(b"ORBIT/dleq/secp256k1/H") };
    let sb = Bases::<Bn254G1> { g: param.g, h: dleq::hash_to_curve::<Bn254G1>(b"ORBIT/dleq/bn254-g1/H") };
    let x = dleq::random_x(&mut rng);
    let x_secp = SecpFr::from_le_bytes_mod_order(&x);
    let offer = veck::make_offer(&param, tag, key, BnFr::from_le_bytes_mod_order(&x), &mut rng);
    let y_chain = sa.g * x_secp;
    let proof = dleq::prove(&sa, &sb, &x, &mut rng).unwrap();
    assert!(veck::verify(&param, tag, &offer) && dleq::verify(&sa, &sb, &y_chain, &offer.y_g1, &proof));
    println!("[ok] setup: Alice verified the Part A offer (Step 3 checks + cross-group DLEQ)");

    // --- Alice's chain key and the payment transaction ---
    let a = SecpFr::rand(&mut rng);
    let alice_pk = SecpPoint::generator() * a;
    let digest = tx_digest("ORBIT B1 demo: spend lock #1, pay 0.01 to Bank address");

    // --- B1.1 positive: pre-sign → pVerify → adapt → standard verify → extract → decrypt ---
    let start = Instant::now();
    let ps = adaptor::p_sign(a, &digest, &y_chain, &mut rng);
    let t_psign = start.elapsed();
    let start = Instant::now();
    let pv = adaptor::p_verify(&alice_pk, &digest, &y_chain, &ps);
    let t_pverify = start.elapsed();
    expect("B1.1 pVerify of Alice's honest pre-signature", pv, true);

    let sig = adaptor::normalize(adaptor::adapt(&ps, x_secp));
    expect("B1.1 adapted signature, standard ECDSA verify (k256)", adaptor::k256_verify(&alice_pk, &digest, &sig), true);
    let alice_addr = adaptor::eth_address(&alice_pk);
    expect(
        "B1.1 adapted signature, ecrecover yields Alice's Ethereum address",
        adaptor::ecrecover_addresses(&digest, &sig).contains(&alice_addr),
        true,
    );
    let extracted = adaptor::extract(&sig, &ps, &y_chain).expect("extract");
    assert_eq!(extracted, x_secp);
    let k_bn = BnFr::from_le_bytes_mod_order(&extracted.into_bigint().to_bytes_le());
    let dec = veck::decrypt(&offer, k_bn);
    assert_eq!(dec, sk3);
    assert!(waters_checks_pass(&param, tag, offer.sk1, offer.sk2, dec));
    println!("[ok] B1.1 Alice extracts x from the published signature; it decrypts sk3; key valid");
    println!(
        "     pSign {:.2} ms, pVerify {:.2} ms (release, single run)",
        t_psign.as_secs_f64() * 1e3, t_pverify.as_secs_f64() * 1e3
    );

    // --- B1.2 / B1.3: low-s normalisation. Find pre-signatures whose raw adapted s is high
    //     and low; check the standard verifier and extraction for both. ---
    let (mut seen_high, mut seen_low) = (false, false);
    while !(seen_high && seen_low) {
        let ps = adaptor::p_sign(a, &digest, &y_chain, &mut rng);
        let raw = adaptor::adapt(&ps, x_secp);
        let norm = adaptor::normalize(raw);
        if adaptor::is_high_s(&raw.s) && !seen_high {
            seen_high = true;
            expect("B1.2 raw high-s adapted signature, standard verify", adaptor::k256_verify(&alice_pk, &digest, &raw), false);
            expect("B1.2 same signature low-s normalised, standard verify", adaptor::k256_verify(&alice_pk, &digest, &norm), true);
            expect("B1.2 extract from the normalised signature", adaptor::extract(&norm, &ps, &y_chain) == Some(x_secp), true);
        } else if !adaptor::is_high_s(&raw.s) && !seen_low {
            seen_low = true;
            expect("B1.3 raw low-s adapted signature, standard verify", adaptor::k256_verify(&alice_pk, &digest, &raw), true);
            expect("B1.3 extract from it", adaptor::extract(&raw, &ps, &y_chain) == Some(x_secp), true);
        }
    }

    // --- Negative: pVerify (the Bank checks Alice's pre-signature before relying on it) ---
    let other_y = SecpPoint::generator() * SecpFr::rand(&mut rng);
    let ps_other_y = adaptor::p_sign(a, &digest, &other_y, &mut rng);
    expect("B1.4 pre-signature under a different statement Y", adaptor::p_verify(&alice_pk, &digest, &y_chain, &ps_other_y), false);
    let other_digest = tx_digest("ORBIT B1 demo: spend lock #1, pay 0.01 to Alice address");
    expect("B1.5 pre-signature checked against a different transaction", adaptor::p_verify(&alice_pk, &other_digest, &y_chain, &ps), false);
    let other_pk = SecpPoint::generator() * SecpFr::rand(&mut rng);
    expect("B1.6 pre-signature checked against a different key", adaptor::p_verify(&other_pk, &digest, &y_chain, &ps), false);
    let tampered = PreSignature { s_pre: ps.s_pre + SecpFr::from(1u64), ..ps };
    expect("B1.7 tampered s'", adaptor::p_verify(&alice_pk, &digest, &y_chain, &tampered), false);

    // B1.8 gap / B1.9: Alice builds R' ≠ k·Y but recomputes r and s' consistently. Everything
    // except the DLEQ proof checks out, and the completed signature would be invalid — the Bank
    // would reveal nothing useful and never get paid. Only the DLEQ proof catches it.
    let k = SecpFr::rand(&mut rng);
    let big_r = SecpPoint::generator() * k;
    let fake_r_prime = y_chain * k + SecpPoint::generator();
    let r = SecpFr::from_be_bytes_mod_order(&fake_r_prime.into_affine().x.into_bigint().to_bytes_be());
    let s_pre = k.inverse().unwrap() * (adaptor::msg_scalar(&digest) + r * a);
    let fake = PreSignature { r, s_pre, big_r, big_r_prime: fake_r_prime, dleq_c: SecpFr::rand(&mut rng), dleq_z: SecpFr::rand(&mut rng) };
    let s_inv = s_pre.inverse().unwrap();
    let without_dleq = big_r == SecpPoint::generator() * (adaptor::msg_scalar(&digest) * s_inv) + alice_pk * (r * s_inv);
    let bad_sig = adaptor::normalize(adaptor::adapt(&fake, x_secp));
    assert!(without_dleq && !adaptor::k256_verify(&alice_pk, &digest, &bad_sig));
    println!("[ok] B1.8 (gap reproduced: R' ≠ k·Y passes all checks but DLEQ; its completion is not a valid signature)");
    expect("B1.9 same pre-signature, full pVerify", adaptor::p_verify(&alice_pk, &digest, &y_chain, &fake), false);

    // --- Negative: adapt / extract ---
    let wrong = adaptor::normalize(adaptor::adapt(&ps, x_secp + SecpFr::from(1u64)));
    expect("B1.10 completed with a wrong witness, standard verify", adaptor::k256_verify(&alice_pk, &digest, &wrong), false);
    expect("B1.11 completed with a wrong witness, ecrecover yields Alice", adaptor::ecrecover_addresses(&digest, &wrong).contains(&alice_addr), false);
    let ps2 = adaptor::p_sign(a, &digest, &y_chain, &mut rng);
    expect("B1.12 extract using an unrelated pre-signature", adaptor::extract(&sig, &ps2, &y_chain).is_some(), false);
    let plain = Signature { r: sig.r, s: sig.s + SecpFr::from(1u64) };
    expect("B1.13 extract from a signature not made by Adapt", adaptor::extract(&plain, &ps, &y_chain).is_some(), false);

    println!("\nB1 PASSED: a standard secp256k1 ECDSA signature reveals x and unlocks the Waters key.");
    println!("NOT yet tested: the two-signature bonding transaction and front-running — B2.");
}
