// Part C of CLAUDE_replace_HTLC.md: buying a coin by fair exchange on Bitcoin, instead of the
// zfairexchange.sol HTLC. The Bank sends Alice an encrypted Waters key (VECK offer) plus a proof
// that x unlocks it; Alice locks BTC in a two-signature P2WSH output and pre-signs the Bank's
// claim under Y_chain = x·G; the Bank's claim reveals x on-chain, and Alice decrypts sk3.
//
// Thin PyO3 wrappers over server/poc_adaptor_sig, where the crypto and the lock were tested
// (Part A, B1–B3, thesis_log/test-results.md). Bank-side functions are used by server.py;
// Alice-side ones by test_fde_regtest() and, later, the Android app. Wire format: JSON with hex
// strings; BN254 points arkworks-compressed, secp256k1 points SEC1-compressed, secp256k1
// scalars 32-byte big-endian, x 32-byte little-endian (x < 2^252, read in both groups).
// Per-coin secrets (Waters r, x, b, nonces) use rand::thread_rng(). Regtest only.

use std::str::FromStr;

use ark_bn254::{g1::Config as Bn254G1, Fr as BnFr, G1Projective as G, G2Projective as G2};
use ark_ec::PrimeGroup;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_secp256k1::{Config as Secp, Fr as SecpFr, Projective as SecpPoint};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Address, Amount, CompressedPublicKey, Network, OutPoint, ScriptBuf, Transaction, Txid};
use poc_adaptor_sig::adaptor::{self, PreSignature, Signature};
use poc_adaptor_sig::btc::{self, Lock, Policy};
use poc_adaptor_sig::dleq::{self, Bases, Proof};
use poc_adaptor_sig::veck::{self, Offer};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{ark_de, ParamWaters};

const NETWORK: Network = Network::Regtest;

type PoCParams = poc_adaptor_sig::ParamWaters;

fn err<E: std::fmt::Display>(e: E) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn ser<T: CanonicalSerialize>(t: &T) -> String {
    let mut v = Vec::new();
    t.serialize_compressed(&mut v).unwrap();
    hex::encode(v)
}

fn de<T: CanonicalDeserialize>(v: &Value, field: &str) -> PyResult<T> {
    let s = v[field].as_str().ok_or_else(|| err(format!("missing field {field}")))?;
    T::deserialize_compressed(&hex::decode(s).map_err(err)?[..]).map_err(|e| err(format!("{field}: {e}")))
}

fn point(hex_str: &str) -> PyResult<SecpPoint> {
    btc::point_from_sec1(&hex::decode(hex_str).map_err(err)?).ok_or_else(|| err("not a secp256k1 point"))
}

fn scalar(hex_str: &str) -> PyResult<SecpFr> {
    btc::scalar_from_be(&hex::decode(hex_str).map_err(err)?).ok_or_else(|| err("scalar must be 32 bytes"))
}

fn x_le(hex_str: &str) -> PyResult<[u8; 32]> {
    hex::decode(hex_str).map_err(err)?.try_into().map_err(|_| err("x must be 32 bytes"))
}

fn digest32(hex_str: &str) -> PyResult<[u8; 32]> {
    hex::decode(hex_str).map_err(err)?.try_into().map_err(|_| err("digest must be 32 bytes"))
}

fn address(s: &str) -> PyResult<Address> {
    s.parse::<Address<NetworkUnchecked>>().map_err(err)?.require_network(NETWORK).map_err(err)
}

fn tx(hex_str: &str) -> PyResult<Transaction> {
    deserialize_hex(hex_str).map_err(err)
}

/// Waters params without beta_secret: all Alice has (res/raw/waters_params.json).
#[derive(Deserialize)]
struct PublicParams {
    #[serde(deserialize_with = "ark_de")]
    g: G,
    #[serde(deserialize_with = "ark_de")]
    g_alpha: G,
    #[serde(deserialize_with = "ark_de")]
    g2: G2,
    #[serde(deserialize_with = "ark_de")]
    g2_beta: G2,
    #[serde(deserialize_with = "ark_de")]
    h_vec: Vec<G>,
    #[serde(deserialize_with = "ark_de")]
    h_0: G,
}

fn public_params(param_str: &str) -> PyResult<PoCParams> {
    let p: PublicParams = serde_json::from_str(param_str).map_err(err)?;
    Ok(PoCParams { beta_secret: BnFr::from(0u64), g: p.g, g_alpha: p.g_alpha, g2: p.g2, g2_beta: p.g2_beta, h_vec: p.h_vec, h_0: p.h_0 })
}

fn secret_params(param_str: &str) -> PyResult<PoCParams> {
    let p: ParamWaters = serde_json::from_str(param_str).map_err(err)?;
    Ok(PoCParams { beta_secret: p.beta_secret, g: p.g, g_alpha: p.g_alpha, g2: p.g2, g2_beta: p.g2_beta, h_vec: p.h_vec, h_0: p.h_0 })
}

/// Pedersen bases of the cross-group proof (as in the Part A/B binaries).
fn dleq_bases(param: &PoCParams) -> (Bases<Secp>, Bases<Bn254G1>) {
    (
        Bases { g: SecpPoint::generator(), h: dleq::hash_to_curve::<Secp>(b"ORBIT/dleq/secp256k1/H") },
        Bases { g: param.g, h: dleq::hash_to_curve::<Bn254G1>(b"ORBIT/dleq/bn254-g1/H") },
    )
}

fn offer_from_json(v: &Value) -> PyResult<Offer> {
    Ok(Offer {
        sk1: de(v, "sk1")?, sk2: de(v, "sk2")?, y_g1: de(v, "y_g1")?, y_bn254: de(v, "y_bn254")?,
        t: de(v, "t")?, c1: de(v, "c1")?, c2: de(v, "c2")?,
    })
}

fn presig_to_json(ps: &PreSignature) -> String {
    let s = |x: &SecpFr| hex::encode(btc::scalar_to_be(x));
    let p = |q: &SecpPoint| hex::encode(btc::sec1_compressed(q));
    json!({
        "r": s(&ps.r), "s_pre": s(&ps.s_pre), "R": p(&ps.big_r), "R_prime": p(&ps.big_r_prime),
        "dleq_c": s(&ps.dleq_c), "dleq_z": s(&ps.dleq_z),
    })
    .to_string()
}

fn presig_from_json(presig_json: &str) -> PyResult<PreSignature> {
    let v: Value = serde_json::from_str(presig_json).map_err(err)?;
    let f = |k: &str| v[k].as_str().ok_or_else(|| err(format!("missing field {k}")));
    Ok(PreSignature {
        r: scalar(f("r")?)?, s_pre: scalar(f("s_pre")?)?, big_r: point(f("R")?)?,
        big_r_prime: point(f("R_prime")?)?, dleq_c: scalar(f("dleq_c")?)?, dleq_z: scalar(f("dleq_z")?)?,
    })
}

/// The lock as both parties reconstruct it from a claim/refund transaction's input.
fn lock_for(tx: &Transaction, script_hex: &str, amount_sat: u64) -> PyResult<Lock> {
    let input = tx.input.first().ok_or_else(|| err("transaction has no input"))?;
    Ok(Lock {
        script: ScriptBuf::from_hex(script_hex).map_err(err)?,
        outpoint: input.previous_output,
        amount: Amount::from_sat(amount_sat),
        timelock: 0, // not needed for signing
    })
}

// ---------- keys and offer authentication ----------

/// Fresh secp256k1 key pair: (sk, pk) as hex.
#[pyfunction]
pub fn fde_keypair() -> (String, String) {
    let sk = SecpFr::rand(&mut rand::thread_rng());
    (hex::encode(btc::scalar_to_be(&sk)), hex::encode(btc::sec1_compressed(&(SecpPoint::generator() * sk))))
}

#[pyfunction]
pub fn fde_pubkey(sk_hex: &str) -> PyResult<String> {
    Ok(hex::encode(btc::sec1_compressed(&(SecpPoint::generator() * scalar(sk_hex)?))))
}

/// ECDSA signature (r ‖ s, hex) over SHA-256(msg): the Bank signs each offer it issues.
#[pyfunction]
pub fn fde_sign(sk_hex: &str, msg: &str) -> PyResult<String> {
    let d: [u8; 32] = Sha256::digest(msg.as_bytes()).into();
    let sig = btc::plain_sign(scalar(sk_hex)?, &d, &mut rand::thread_rng());
    Ok(hex::encode([btc::scalar_to_be(&sig.r), btc::scalar_to_be(&sig.s)].concat()))
}

#[pyfunction]
pub fn fde_verify_sig(pk_hex: &str, msg: &str, sig_hex: &str) -> PyResult<bool> {
    let raw = hex::decode(sig_hex).map_err(err)?;
    if raw.len() != 64 {
        return Ok(false);
    }
    let sig = Signature { r: scalar(&hex::encode(&raw[..32]))?, s: scalar(&hex::encode(&raw[32..]))? };
    let d: [u8; 32] = Sha256::digest(msg.as_bytes()).into();
    Ok(adaptor::k256_verify(&point(pk_hex)?, &d, &sig))
}

// ---------- the offer (Part A) ----------

/// Bank: a fresh Waters key for `tag`, encrypted under a fresh x, with Y_chain = x·G and the
/// cross-group proof. Returns {"offer": {...public...}, "x": <secret, 32-byte LE hex>}.
#[pyfunction]
pub fn fde_make_offer(param_str: &str, tag: &str) -> PyResult<String> {
    let param = secret_params(param_str)?;
    let rng = &mut rand::thread_rng();
    let key = poc_adaptor_sig::derive_waters_key(&param, tag, rng);
    let xb = dleq::random_x(rng);
    let o = veck::make_offer(&param, tag, key, BnFr::from_le_bytes_mod_order(&xb), rng);
    let (sa, sb) = dleq_bases(&param);
    let y_chain = sa.g * SecpFr::from_le_bytes_mod_order(&xb);
    let proof = dleq::prove(&sa, &sb, &xb, rng).ok_or_else(|| err("x out of range"))?;
    Ok(json!({
        "offer": {
            "sk1": ser(&o.sk1), "sk2": ser(&o.sk2), "y_g1": ser(&o.y_g1), "y_bn254": ser(&o.y_bn254),
            "t": ser(&o.t), "c1": ser(&o.c1), "c2": ser(&o.c2),
            "y_chain": hex::encode(btc::sec1_compressed(&y_chain)),
            "dleq": hex::encode(proof.to_bytes()),
        },
        "x": hex::encode(xb),
    })
    .to_string())
}

/// Alice: the encrypted key is a valid Waters key for `tag` (11 pairings, no decryption), and
/// Y_chain hides the same x that decrypts it (cross-group proof). Public params suffice.
#[pyfunction]
pub fn fde_verify_offer(public_param_str: &str, tag: &str, offer_json: &str) -> PyResult<bool> {
    let param = public_params(public_param_str)?;
    let v: Value = serde_json::from_str(offer_json).map_err(err)?;
    let Ok(o) = offer_from_json(&v) else { return Ok(false) };
    let Some(y_chain) = v["y_chain"].as_str().and_then(|s| btc::point_from_sec1(&hex::decode(s).ok()?)) else { return Ok(false) };
    let Some(proof) = v["dleq"].as_str().and_then(|s| Proof::<Secp, Bn254G1>::from_bytes(&hex::decode(s).ok()?)) else { return Ok(false) };
    let (sa, sb) = dleq_bases(&param);
    Ok(veck::verify(&param, tag, &o) && dleq::verify(&sa, &sb, &y_chain, &o.y_g1, &proof))
}

// ---------- the lock and its transactions (Part B) ----------

/// The two-signature P2WSH lock: {"script": hex, "address": regtest bech32}.
#[pyfunction]
pub fn btc_lock(alice_pk_hex: &str, bank_pk_hex: &str, timelock: u32) -> PyResult<String> {
    let script = btc::lock_script(&btc::btc_key(&point(alice_pk_hex)?), &btc::btc_key(&point(bank_pk_hex)?), timelock, Policy::TwoOfTwo);
    Ok(json!({"script": script.to_hex_string(), "address": Address::p2wsh(&script, NETWORK).to_string()}).to_string())
}

/// P2WPKH address of a key (the Bank's payout address, Alice's refund address).
#[pyfunction]
pub fn btc_p2wpkh_address(pk_hex: &str) -> PyResult<String> {
    let pk = CompressedPublicKey::from_slice(&hex::decode(pk_hex).map_err(err)?).map_err(err)?;
    Ok(Address::p2wpkh(&pk, NETWORK).to_string())
}

/// Unsigned spend of the whole lock output to `to_address`, and the digest both parties sign:
/// {"tx": hex, "sighash": hex}. `lock_time` is 0 for the claim, the timelock for the refund.
#[pyfunction]
pub fn btc_spend(script_hex: &str, txid: &str, vout: u32, amount_sat: u64, to_address: &str, fee: u64, lock_time: u32) -> PyResult<String> {
    let lock = Lock {
        script: ScriptBuf::from_hex(script_hex).map_err(err)?,
        outpoint: OutPoint { txid: Txid::from_str(txid).map_err(err)?, vout },
        amount: Amount::from_sat(amount_sat),
        timelock: lock_time,
    };
    if fee >= amount_sat {
        return Err(err("fee exceeds the locked amount"));
    }
    let t = btc::spend(&lock, &address(to_address)?.script_pubkey(), fee, lock_time);
    Ok(json!({"tx": serialize_hex(&t), "sighash": hex::encode(btc::sighash(&t, &lock))}).to_string())
}

/// Alice: adaptor pre-signature on the claim's sighash under Y_chain.
#[pyfunction]
pub fn fde_presign(sk_hex: &str, sighash_hex: &str, y_chain_hex: &str) -> PyResult<String> {
    let ps = adaptor::p_sign(scalar(sk_hex)?, &digest32(sighash_hex)?, &point(y_chain_hex)?, &mut rand::thread_rng());
    Ok(presig_to_json(&ps))
}

/// Bank: check Alice's pre-signature on its own claim transaction, complete it with x, add its
/// own signature. Returns the broadcastable claim. ValueError if the pre-signature is invalid.
#[pyfunction]
pub fn fde_complete_claim(tx_hex: &str, script_hex: &str, amount_sat: u64, alice_pk_hex: &str, y_chain_hex: &str, presig_json: &str, x_hex: &str, bank_sk_hex: &str) -> PyResult<String> {
    let mut t = tx(tx_hex)?;
    let lock = lock_for(&t, script_hex, amount_sat)?;
    let d = btc::sighash(&t, &lock);
    let (alice_pk, y_chain) = (point(alice_pk_hex)?, point(y_chain_hex)?);
    let ps = presig_from_json(presig_json)?;
    if !adaptor::p_verify(&alice_pk, &d, &y_chain, &ps) {
        return Err(err("pre-signature invalid for this claim"));
    }
    let x = SecpFr::from_le_bytes_mod_order(&x_le(x_hex)?);
    if SecpPoint::generator() * x != y_chain {
        return Err(err("x does not match Y_chain"));
    }
    let alice = adaptor::normalize(adaptor::adapt(&ps, x));
    let bank = btc::plain_sign(scalar(bank_sk_hex)?, &d, &mut rand::thread_rng());
    btc::set_claim_witness(&mut t, &lock, &alice, Some(&bank));
    Ok(serialize_hex(&t))
}

/// Alice: sign the refund (built with btc_spend, lock_time = timelock).
#[pyfunction]
pub fn btc_sign_refund(tx_hex: &str, script_hex: &str, amount_sat: u64, sk_hex: &str) -> PyResult<String> {
    let mut t = tx(tx_hex)?;
    let lock = lock_for(&t, script_hex, amount_sat)?;
    let sig = btc::plain_sign(scalar(sk_hex)?, &btc::sighash(&t, &lock), &mut rand::thread_rng());
    btc::set_refund_witness(&mut t, &lock, &sig);
    Ok(serialize_hex(&t))
}

/// Alice: x from the Bank's claim as seen on-chain (or in the mempool), then sk3 = c2 − x·c1.
/// Returns {"x": hex LE, "sk1", "sk2", "sk3": compressed hex}. ValueError if the transaction
/// does not carry the completion of her pre-signature.
#[pyfunction]
pub fn fde_extract_decrypt(claim_tx_hex: &str, presig_json: &str, offer_json: &str) -> PyResult<String> {
    let t = tx(claim_tx_hex)?;
    let v: Value = serde_json::from_str(offer_json).map_err(err)?;
    let o = offer_from_json(&v)?;
    let y_chain = point(v["y_chain"].as_str().ok_or_else(|| err("missing field y_chain"))?)?;
    let ps = presig_from_json(presig_json)?;
    let x = btc::alice_sig_in(&t)
        .and_then(|s| adaptor::extract(&s, &ps, &y_chain))
        .ok_or_else(|| err("no completion of the pre-signature in this transaction"))?;
    let xb: [u8; 32] = x.into_bigint().to_bytes_le().try_into().unwrap();
    let sk3 = veck::decrypt(&o, BnFr::from_le_bytes_mod_order(&xb));
    Ok(json!({"x": hex::encode(xb), "sk1": ser(&o.sk1), "sk2": ser(&o.sk2), "sk3": ser(&sk3)}).to_string())
}
