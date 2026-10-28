//! Part B / Step B3 — the two-signature lock as a real Bitcoin script, on a local regtest node.
//!
//! B2's simulated ledger, replaced by Bitcoin Core: the lock is a P2WSH output with
//!   IF   <Alice> CHECKSIGVERIFY <Bank> CHECKSIG        (claim: adapted sig + Bank sig)
//!   ELSE <timelock> CHECKLOCKTIMEVERIFY DROP <Alice> CHECKSIG   (refund after the timelock)
//!   ENDIF
//! Both parties sign the BIP143 sighash of the claim transaction; Alice's signature is the
//! ECDSA adaptor pre-signature under Y_chain, completed by the Bank with x. Script, low-s,
//! timelock and mempool (full-RBF) rules are Bitcoin Core's own, not re-implemented here. Alice
//! learns x only by reading the spend of her lock from the node's mempool or a block.
//!
//! Prerequisite (never without -regtest):
//!   bitcoind -regtest -datadir=$HOME/btc-regtest -daemon -fallbackfee=0.0001
//! Run with: cargo run --release --bin b3_bitcoin_regtest

use std::process::Command;

use ark_bn254::{g1::Config as Bn254G1, Fr as BnFr};
use ark_ec::PrimeGroup;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_secp256k1::{Config as Secp, Fr as SecpFr, Projective as SecpPoint};
use ark_std::rand::Rng;
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Address, Amount, Block, Network, OutPoint, ScriptBuf, Transaction};
use poc_adaptor_sig::adaptor::{self, PreSignature, Signature};
use poc_adaptor_sig::btc::{alice_sig_in, bank_sig_in, btc_key, lock_script, plain_sign, set_claim_witness, set_refund_witness, sighash, spend, Lock, Policy};
use poc_adaptor_sig::dleq::{self, Bases};
use poc_adaptor_sig::veck::{self, Offer};
use poc_adaptor_sig::{derive_waters_key, generate_params, waters_checks_pass, ParamWaters};

const WALLET: &str = "orbit";
const AMOUNT: u64 = 1_000_000; // sats, 0.01 BTC (denomination 1)
const FEE: u64 = 1_000;
/// A redirect or refund racing the claim pays more, so the node prefers it under full-RBF.
const RACE_FEE: u64 = 10_000;
const TIMELOCK_DELTA: u32 = 10;
const CLAIM_MARGIN: u32 = 3;

// ---------- bitcoin-cli ----------

fn cli(args: &[&str], wallet: bool) -> Result<String, String> {
    let datadir = std::env::var("BTC_DATADIR").unwrap_or_else(|_| format!("{}/btc-regtest", std::env::var("HOME").unwrap()));
    let mut cmd = Command::new("bitcoin-cli");
    cmd.arg("-regtest").arg(format!("-datadir={datadir}"));
    if wallet {
        cmd.arg(format!("-rpcwallet={WALLET}"));
    }
    let out = cmd.args(args).output().expect("bitcoin-cli not found");
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().replace('\n', " "))
    }
}

fn rpc(args: &[&str]) -> String {
    cli(args, false).unwrap_or_else(|e| panic!("bitcoin-cli {args:?}: {e}"))
}

fn wallet(args: &[&str]) -> String {
    cli(args, true).unwrap_or_else(|e| panic!("bitcoin-cli {args:?}: {e}"))
}

fn height() -> u32 {
    rpc(&["getblockcount"]).parse().unwrap()
}

fn new_spk() -> ScriptBuf {
    let a: Address<NetworkUnchecked> = wallet(&["getnewaddress", "", "bech32"]).parse().unwrap();
    a.require_network(Network::Regtest).unwrap().script_pubkey()
}

/// Mine `n` blocks containing the mempool.
fn mine(n: u32) {
    let addr = wallet(&["getnewaddress"]);
    rpc(&["generatetoaddress", &n.to_string(), &addr]);
}

/// Mine one block that leaves the mempool out (a miner ignoring, or congestion delaying, a tx).
fn mine_empty() {
    let addr = wallet(&["getnewaddress"]);
    rpc(&["generateblock", &addr, "[]"]);
}

fn mine_to(h: u32) {
    let now = height();
    if h > now {
        mine(h - now);
    }
}

fn send(tx: &Transaction) -> Result<String, String> {
    cli(&["sendrawtransaction", &serialize_hex(tx)], false)
}

/// Wallet with mature coins.
fn init_node() {
    if cli(&["createwallet", WALLET], false).is_err() {
        let _ = cli(&["loadwallet", WALLET], false); // exists; may already be loaded
    }
    if wallet(&["getbalance"]).parse::<f64>().unwrap() < 1.0 {
        mine(101);
    }
}

/// A spend of `outpoint` in the mempool, as Alice watching the network would see it.
fn mempool_spend(outpoint: &OutPoint) -> Option<Transaction> {
    let txids: Vec<String> = serde_json::from_str(&rpc(&["getrawmempool"])).unwrap();
    txids
        .iter()
        .map(|id| deserialize_hex::<Transaction>(&rpc(&["getrawtransaction", id])).unwrap())
        .find(|tx| tx.input.iter().any(|i| i.previous_output == *outpoint))
}

/// A spend of `outpoint` in the tip block.
fn block_spend(outpoint: &OutPoint) -> Option<Transaction> {
    let block: Block = deserialize_hex(&rpc(&["getblock", &rpc(&["getbestblockhash"]), "0"])).unwrap();
    block.txdata.into_iter().find(|tx| tx.input.iter().any(|i| i.previous_output == *outpoint))
}

/// Alice funds a P2WSH lock with AMOUNT, confirmed in one block.
fn fund_lock(w: &World, policy: Policy) -> Lock {
    let timelock = height() + 1 + TIMELOCK_DELTA;
    let script = lock_script(&btc_key(&w.alice_pk), &btc_key(&w.bank_pk), timelock, policy);
    let addr = Address::p2wsh(&script, Network::Regtest);
    let txid = wallet(&["sendtoaddress", &addr.to_string(), &Amount::from_sat(AMOUNT).to_btc().to_string()]);
    let funding: Transaction = deserialize_hex(&rpc(&["getrawtransaction", &txid])).unwrap();
    let vout = funding.output.iter().position(|o| o.script_pubkey == addr.script_pubkey()).unwrap();
    mine(1);
    Lock { script, outpoint: OutPoint { txid: funding.compute_txid(), vout: vout as u32 }, amount: Amount::from_sat(AMOUNT), timelock }
}

// ---------- parties (as in B2) ----------

struct World {
    param: ParamWaters,
    tag: &'static str,
    sk3: ark_bn254::G2Projective,
    offer: Offer,
    x: SecpFr,
    y_chain: SecpPoint,
    a: SecpFr,
    alice_pk: SecpPoint,
    bank_sk: SecpFr,
    bank_pk: SecpPoint,
}

/// Part A + B1 setup: the Bank's verified offer and both parties' chain keys.
fn setup<R: Rng>(rng: &mut R) -> World {
    let param = generate_params(rng);
    let tag = "001_042";
    let key = derive_waters_key(&param, tag, rng);
    let sa = Bases::<Secp> { g: SecpPoint::generator(), h: dleq::hash_to_curve::<Secp>(b"ORBIT/dleq/secp256k1/H") };
    let sb = Bases::<Bn254G1> { g: param.g, h: dleq::hash_to_curve::<Bn254G1>(b"ORBIT/dleq/bn254-g1/H") };
    let xb = dleq::random_x(rng);
    let x = SecpFr::from_le_bytes_mod_order(&xb);
    let offer = veck::make_offer(&param, tag, key, BnFr::from_le_bytes_mod_order(&xb), rng);
    let y_chain = sa.g * x;
    let proof = dleq::prove(&sa, &sb, &xb, rng).unwrap();
    assert!(veck::verify(&param, tag, &offer) && dleq::verify(&sa, &sb, &y_chain, &offer.y_g1, &proof));
    let (a, bank_sk) = (SecpFr::rand(rng), SecpFr::rand(rng));
    World {
        sk3: key.2, param, tag, offer, x, y_chain, a,
        alice_pk: SecpPoint::generator() * a, bank_sk, bank_pk: SecpPoint::generator() * bank_sk,
    }
}

/// Alice reads a claim from the chain or mempool, extracts x and decrypts her key.
fn alice_decrypts(w: &World, tx: &Transaction, ps: &PreSignature) -> bool {
    let Some(x) = alice_sig_in(tx).and_then(|s| adaptor::extract(&s, ps, &w.y_chain)) else { return false };
    let dec = veck::decrypt(&w.offer, BnFr::from_le_bytes_mod_order(&x.into_bigint().to_bytes_le()));
    dec == w.sk3 && waters_checks_pass(&w.param, w.tag, w.offer.sk1, w.offer.sk2, dec)
}

/// Alice pre-signs the claim to the Bank; the Bank checks it and completes it with `y`.
fn bank_claim<R: Rng>(w: &World, lock: &Lock, bank_spk: &ScriptBuf, y: SecpFr, rng: &mut R) -> (Transaction, PreSignature) {
    let mut tx = spend(lock, bank_spk, FEE, 0);
    let d = sighash(&tx, lock);
    let ps = adaptor::p_sign(w.a, &d, &w.y_chain, rng); // Alice → Bank
    assert!(adaptor::p_verify(&w.alice_pk, &d, &w.y_chain, &ps)); // Bank checks
    let bank = plain_sign(w.bank_sk, &d, rng);
    set_claim_witness(&mut tx, lock, &adaptor::normalize(adaptor::adapt(&ps, y)), Some(&bank));
    (tx, ps)
}

fn alice_refund<R: Rng>(w: &World, lock: &Lock, to: &ScriptBuf, fee: u64, lock_time: u32, rng: &mut R) -> Transaction {
    let mut tx = spend(lock, to, fee, lock_time);
    let sig = plain_sign(w.a, &sighash(&tx, lock), rng);
    set_refund_witness(&mut tx, lock, &sig);
    tx
}

fn expect(name: &str, r: Result<String, String>, want_ok: bool) {
    assert_eq!(r.is_ok(), want_ok, "{name}: got {r:?}");
    match r {
        Ok(txid) => println!("[ok] {name}: accepted ({}…)", &txid[..16]),
        Err(e) => println!("[ok] {name}: rejected ({e})"),
    }
}

fn pays(tx: &Transaction, spk: &ScriptBuf) -> bool {
    tx.output[0].script_pubkey == *spk
}

fn main() {
    init_node();
    let mut rng = ark_std::test_rng();
    let w = setup(&mut rng);
    let (bank_spk, alice_spk) = (new_spk(), new_spk());
    println!("[ok] setup: regtest at height {}; Part A offer verified by Alice; chain keys for Alice and the Bank", height());

    // ---------- B3.1–B3.2 honest claim; Alice's front-run attempt ----------
    let lock = fund_lock(&w, Policy::TwoOfTwo);
    println!("[ok] lock funded: {} ({} sat, timelock {}), witness script {} bytes",
        lock.outpoint, AMOUNT, lock.timelock, lock.script.len());
    let (claim, ps) = bank_claim(&w, &lock, &bank_spk, w.x, &mut rng);
    println!("[ok] claim tx: {} vbytes, witness {} bytes", claim.vsize(), claim.input[0].witness.size());
    expect("B3.1 Bank's claim (adapted sig + Bank sig) to the mempool", send(&claim), true);
    let seen = mempool_spend(&lock.outpoint).unwrap();
    assert!(alice_decrypts(&w, &seen, &ps)); // x is public from here on
    let mut steal = spend(&lock, &alice_spk, RACE_FEE, 0);
    let d = sighash(&steal, &lock);
    let seen_bank = bank_sig_in(&seen).unwrap(); // the only Bank signature Alice has seen
    set_claim_witness(&mut steal, &lock, &plain_sign(w.a, &d, &mut rng), Some(&seen_bank));
    expect("B3.2 Alice's higher-fee redirect reusing the Bank's signature", send(&steal), false);
    // The mempool reports a policy flag (NULLFAIL); a colluding miner skips the mempool, so
    // also check consensus: a block containing the redirect.
    let addr = wallet(&["getnewaddress"]);
    let txs = format!("[\"{}\"]", serialize_hex(&steal));
    expect("B3.2 a miner putting the redirect directly into a block", cli(&["generateblock", &addr, &txs], false), false);
    mine(1);
    let confirmed = block_spend(&lock.outpoint).unwrap();
    assert!(pays(&confirmed, &bank_spk) && alice_decrypts(&w, &confirmed, &ps));
    println!("[ok] B3.1 claim confirmed, Bank paid; Alice extracts x from the block and decrypts sk3");

    // ---------- B3.3 gap: naive lock, Alice front-runs via full-RBF ----------
    let lock = fund_lock(&w, Policy::AliceOnly);
    let mut claim = spend(&lock, &bank_spk, FEE, 0);
    let ps = adaptor::p_sign(w.a, &sighash(&claim, &lock), &w.y_chain, &mut rng);
    set_claim_witness(&mut claim, &lock, &adaptor::normalize(adaptor::adapt(&ps, w.x)), None);
    expect("B3.3 Bank's claim on the Alice-only lock", send(&claim), true);
    let seen = mempool_spend(&lock.outpoint).unwrap();
    assert!(alice_decrypts(&w, &seen, &ps));
    let mut steal = spend(&lock, &alice_spk, RACE_FEE, 0);
    let d = sighash(&steal, &lock);
    set_claim_witness(&mut steal, &lock, &plain_sign(w.a, &d, &mut rng), None);
    expect("B3.3 Alice's higher-fee redirect replaces it", send(&steal), true);
    mine(1);
    assert!(pays(&block_spend(&lock.outpoint).unwrap(), &alice_spk));
    println!("[ok] B3.3 (gap reproduced on Bitcoin: with an Alice-only lock, Alice front-runs the claim, keeps the money and decrypts sk3)");

    // ---------- B3.4–B3.6 the Bank can't take the money without revealing x ----------
    let lock = fund_lock(&w, Policy::TwoOfTwo);
    let base = spend(&lock, &bank_spk, FEE, 0);
    let d = sighash(&base, &lock);
    let ps = adaptor::p_sign(w.a, &d, &w.y_chain, &mut rng);
    let bank = plain_sign(w.bank_sk, &d, &mut rng);

    let mut t = base.clone();
    set_claim_witness(&mut t, &lock, &adaptor::normalize(Signature { r: ps.r, s: ps.s_pre }), Some(&bank));
    expect("B3.4 claim with the un-adapted pre-signature", send(&t), false);

    let mut t = base.clone();
    set_claim_witness(&mut t, &lock, &adaptor::normalize(adaptor::adapt(&ps, w.x + SecpFr::from(1u64))), Some(&bank));
    expect("B3.5 claim completed with a wrong witness", send(&t), false);

    // The Bank reuses Alice's adapted signature (made for `base`) on a transaction with a
    // different fee; it signs that one itself.
    let mut t = spend(&lock, &bank_spk, FEE / 2, 0);
    let bank2 = plain_sign(w.bank_sk, &sighash(&t, &lock), &mut rng);
    set_claim_witness(&mut t, &lock, &adaptor::normalize(adaptor::adapt(&ps, w.x)), Some(&bank2));
    expect("B3.6 Alice's adapted signature reused on a different transaction", send(&t), false);

    // ---------- B3.7–B3.9 timelock ----------
    let r = alice_refund(&w, &lock, &alice_spk, FEE, lock.timelock, &mut rng);
    expect("B3.7 Alice's refund before the timelock", send(&r), false);
    let r = alice_refund(&w, &lock, &alice_spk, FEE, height(), &mut rng);
    expect("B3.7 Alice's refund with nLockTime below the script's timelock", send(&r), false);
    mine_to(lock.timelock);
    let r = alice_refund(&w, &lock, &alice_spk, FEE, lock.timelock, &mut rng);
    expect("B3.8 Alice's refund at the timelock (Bank never claimed)", send(&r), true);
    mine(1);
    assert!(pays(&block_spend(&lock.outpoint).unwrap(), &alice_spk));
    let mut t = base.clone();
    set_claim_witness(&mut t, &lock, &adaptor::normalize(adaptor::adapt(&ps, w.x)), Some(&bank));
    expect("B3.9 Bank's valid claim after Alice refunded", send(&t), false);

    // ---------- B3.10 gap: late claim, Alice's refund replaces it ----------
    // The claim branch has no deadline. After the timelock a claim reveals x in the mempool
    // while Alice's refund is also valid, and full-RBF lets the higher-fee refund win.
    let lock = fund_lock(&w, Policy::TwoOfTwo);
    mine_to(lock.timelock + 2);
    let (claim, ps) = bank_claim(&w, &lock, &bank_spk, w.x, &mut rng);
    expect("B3.10 Bank's late claim after expiry", send(&claim), true);
    assert!(alice_decrypts(&w, &mempool_spend(&lock.outpoint).unwrap(), &ps));
    let r = alice_refund(&w, &lock, &alice_spk, RACE_FEE, lock.timelock, &mut rng);
    expect("B3.10 Alice's higher-fee refund replaces the claim", send(&r), true);
    mine(1);
    assert!(pays(&block_spend(&lock.outpoint).unwrap(), &alice_spk));
    println!("[ok] B3.10 (gap reproduced on Bitcoin: late claim, refund replaces it — Alice keeps the money and decrypts sk3)");

    // ---------- B3.11 the margin rule: the claim must CONFIRM before the timelock ----------
    let bank_may_claim = |h: u32, timelock: u32| h + CLAIM_MARGIN < timelock;
    let lock = fund_lock(&w, Policy::TwoOfTwo);
    mine_to(lock.timelock - CLAIM_MARGIN - 1);
    assert!(bank_may_claim(height(), lock.timelock));
    let (claim, _) = bank_claim(&w, &lock, &bank_spk, w.x, &mut rng);
    expect("B3.11a Bank's claim inside the safety window", send(&claim), true);
    mine(1);
    mine_to(lock.timelock);
    let r = alice_refund(&w, &lock, &alice_spk, RACE_FEE, lock.timelock, &mut rng);
    expect("B3.11a Alice's refund at the timelock (claim confirmed earlier)", send(&r), false);

    // Same window, but no block includes the claim before the timelock (congestion, or a miner
    // ignoring it): broadcasting inside the window is not enough.
    let lock = fund_lock(&w, Policy::TwoOfTwo);
    mine_to(lock.timelock - CLAIM_MARGIN - 1);
    assert!(bank_may_claim(height(), lock.timelock));
    let (claim, ps) = bank_claim(&w, &lock, &bank_spk, w.x, &mut rng);
    expect("B3.11b Bank's claim inside the safety window", send(&claim), true);
    while height() < lock.timelock {
        mine_empty();
    }
    assert!(alice_decrypts(&w, &mempool_spend(&lock.outpoint).unwrap(), &ps));
    let r = alice_refund(&w, &lock, &alice_spk, RACE_FEE, lock.timelock, &mut rng);
    expect("B3.11b Alice's refund replaces the still-unconfirmed claim", send(&r), true);
    mine(1);
    assert!(pays(&block_spend(&lock.outpoint).unwrap(), &alice_spk));
    println!("[ok] B3.11b (gap: claim broadcast {} blocks early but unconfirmed at the timelock — Alice keeps the money and decrypts sk3)", CLAIM_MARGIN + 1);

    println!("\nB3 PASSED on Bitcoin Core regtest (height {}): the two-signature P2WSH lock pays the Bank only by revealing x,", height());
    println!("Alice recovers x from the chain and decrypts sk3, and front-running is rejected by Bitcoin's own script rules.");
    println!("Fairness needs the claim CONFIRMED before the timelock (B3.10, B3.11b): CLAIM_MARGIN must cover confirmation delay.");
}
