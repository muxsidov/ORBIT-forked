//! Part B / Step B2 — the two-signature bonding transaction on a simulated ledger.
//!
//! Lock (CLAUDE_AandFD.md §B.2, ECDSA variant): Alice locks funds that can be spent
//!   - claim:  any time while unspent, with BOTH Alice's signature (the adapted one) and the
//!             Bank's ordinary signature on the same spending transaction;
//!   - refund: once height ≥ timelock, with Alice's signature alone.
//! Like Bitcoin script, the ledger can enforce "refund only after the timelock" but not "claim
//! only before it". Signatures are checked with k256 (standard ECDSA, low-s), as a chain would.
//! The ledger has a public mempool and a miner who may order transactions adversarially.
//!
//! Run with: cargo run --release --bin b2_bonding_ledger

use ark_bn254::{g1::Config as Bn254G1, Fr as BnFr};
use ark_ec::PrimeGroup;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_secp256k1::{Config as Secp, Fr as SecpFr, Projective as SecpPoint};
use ark_std::rand::Rng;
use poc_adaptor_sig::adaptor::{self, PreSignature, Signature};
use poc_adaptor_sig::dleq::{self, Bases};
use poc_adaptor_sig::veck::{self, Offer};
use poc_adaptor_sig::{derive_waters_key, generate_params, waters_checks_pass, ParamWaters};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Party { Alice, Bank }

#[derive(Clone, Copy, PartialEq, Eq)]
enum Policy {
    /// Claim needs Alice's and the Bank's signatures (the §B.2 design).
    TwoOfTwo,
    /// Naive variant: claim needs only Alice's (adapted) signature.
    AliceOnly,
}

#[derive(Clone, Copy)]
enum Path { Claim, Refund }

#[derive(Clone, Copy)]
struct SpendTx {
    lock: usize,
    path: Path,
    to: Party,
    amount: u64,
    alice_sig: Option<Signature>,
    bank_sig: Option<Signature>,
}

impl SpendTx {
    /// What both parties sign: everything except the signatures.
    fn digest(&self) -> [u8; 32] {
        let path = match self.path { Path::Claim => "claim", Path::Refund => "refund" };
        Sha256::digest(format!("lock={};path={};to={:?};amount={}", self.lock, path, self.to, self.amount)).into()
    }
}

struct Lock {
    amount: u64,
    alice: SecpPoint,
    bank: SecpPoint,
    timelock: u64,
    policy: Policy,
    spent: bool,
}

#[derive(Default)]
struct Ledger {
    height: u64,
    locks: Vec<Lock>,
    mempool: Vec<SpendTx>,
    confirmed: Vec<SpendTx>,
    balance_alice: u64,
    balance_bank: u64,
}

impl Ledger {
    fn lock(&mut self, amount: u64, alice: SecpPoint, bank: SecpPoint, timelock: u64, policy: Policy) -> usize {
        self.locks.push(Lock { amount, alice, bank, timelock, policy, spent: false });
        self.locks.len() - 1
    }

    fn valid(&self, tx: &SpendTx) -> Result<(), &'static str> {
        let l = &self.locks[tx.lock];
        if l.spent { return Err("lock already spent"); }
        if tx.amount != l.amount { return Err("amount mismatch"); }
        let d = tx.digest();
        let sig_ok = |pk: &SecpPoint, s: Option<Signature>| s.is_some_and(|s| adaptor::k256_verify(pk, &d, &s));
        match tx.path {
            Path::Claim => {
                if !sig_ok(&l.alice, tx.alice_sig) { return Err("claim: Alice's signature invalid"); }
                if l.policy == Policy::TwoOfTwo && !sig_ok(&l.bank, tx.bank_sig) {
                    return Err("claim: Bank's signature invalid");
                }
            }
            Path::Refund => {
                if self.height < l.timelock { return Err("refund: timelock not reached"); }
                if !sig_ok(&l.alice, tx.alice_sig) { return Err("refund: Alice's signature invalid"); }
            }
        }
        Ok(())
    }

    fn broadcast(&mut self, tx: SpendTx) { self.mempool.push(tx); }

    /// Mine one block. `order` lets the miner pick transaction order (adversarial ordering).
    /// Returns the result for each mempool transaction in the order processed.
    fn mine(&mut self, order: &[usize]) -> Vec<Result<(), &'static str>> {
        let pool = std::mem::take(&mut self.mempool);
        let mut results = Vec::new();
        for &i in order {
            let tx = pool[i];
            let r = self.valid(&tx);
            if r.is_ok() {
                self.locks[tx.lock].spent = true;
                match tx.to {
                    Party::Alice => self.balance_alice += tx.amount,
                    Party::Bank => self.balance_bank += tx.amount,
                }
                self.confirmed.push(tx);
            }
            results.push(r);
        }
        self.height += 1;
        results
    }
}

fn expect(name: &str, r: Result<(), &str>, want_ok: bool) {
    assert_eq!(r.is_ok(), want_ok, "{name}: got {r:?}");
    match r {
        Ok(()) => println!("[ok] {name}: accepted"),
        Err(e) => println!("[ok] {name}: rejected ({e})"),
    }
}

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

/// Ordinary ECDSA signature (an adaptor pre-signature completed with the trivial witness 1).
fn plain_sign<R: Rng>(sk: SecpFr, digest: &[u8; 32], rng: &mut R) -> Signature {
    let ps = adaptor::p_sign(sk, digest, &SecpPoint::generator(), rng);
    adaptor::normalize(adaptor::adapt(&ps, SecpFr::from(1u64)))
}

/// Alice reads a confirmed/mempool claim, extracts x and decrypts her key.
fn alice_decrypts(w: &World, tx: &SpendTx, ps: &PreSignature) -> bool {
    let Some(x) = tx.alice_sig.and_then(|s| adaptor::extract(&s, ps, &w.y_chain)) else { return false };
    let dec = veck::decrypt(&w.offer, BnFr::from_le_bytes_mod_order(&x.into_bigint().to_bytes_le()));
    dec == w.sk3 && waters_checks_pass(&w.param, w.tag, w.offer.sk1, w.offer.sk2, dec)
}

const AMOUNT: u64 = 1_000; // e.g. 0.01 ETH in units of 1e-5
const TIMELOCK: u64 = 10;
/// Blocks before the timelock after which the Bank must no longer reveal x (B2.13). On a real
/// chain this has to cover the time for the claim to confirm, e.g. several blocks.
const CLAIM_MARGIN: u64 = 3;

fn claim_tx(lock: usize) -> SpendTx {
    SpendTx { lock, path: Path::Claim, to: Party::Bank, amount: AMOUNT, alice_sig: None, bank_sig: None }
}

fn main() {
    let mut rng = ark_std::test_rng();
    let w = setup(&mut rng);
    println!("[ok] setup: Part A offer verified by Alice; chain keys for Alice and the Bank");

    // ---------- B2.1 honest run ----------
    let mut chain = Ledger::default();
    let lock = chain.lock(AMOUNT, w.alice_pk, w.bank_pk, TIMELOCK, Policy::TwoOfTwo);
    let mut tx = claim_tx(lock);
    let ps = adaptor::p_sign(w.a, &tx.digest(), &w.y_chain, &mut rng); // Alice → Bank
    assert!(adaptor::p_verify(&w.alice_pk, &tx.digest(), &w.y_chain, &ps)); // Bank checks
    tx.alice_sig = Some(adaptor::normalize(adaptor::adapt(&ps, w.x)));
    tx.bank_sig = Some(plain_sign(w.bank_sk, &tx.digest(), &mut rng));
    chain.broadcast(tx);
    expect("B2.1 Bank's claim (adapted sig + Bank sig)", chain.mine(&[0])[0], true);
    assert_eq!((chain.balance_bank, chain.balance_alice), (AMOUNT, 0));
    assert!(alice_decrypts(&w, &chain.confirmed[0], &ps));
    println!("[ok] B2.1 Bank paid; Alice extracts x from the confirmed transaction and decrypts sk3");

    // ---------- B2.2 gap: naive lock, Alice front-runs the Bank ----------
    let mut chain = Ledger::default();
    let lock = chain.lock(AMOUNT, w.alice_pk, w.bank_pk, TIMELOCK, Policy::AliceOnly);
    let mut tx = claim_tx(lock);
    let ps = adaptor::p_sign(w.a, &tx.digest(), &w.y_chain, &mut rng);
    tx.alice_sig = Some(adaptor::normalize(adaptor::adapt(&ps, w.x)));
    chain.broadcast(tx);
    // Alice sees the claim in the mempool, extracts x, and races a payment to herself.
    let seen = chain.mempool[0];
    assert!(alice_decrypts(&w, &seen, &ps));
    let mut steal = SpendTx { to: Party::Alice, ..claim_tx(lock) };
    steal.alice_sig = Some(plain_sign(w.a, &steal.digest(), &mut rng));
    chain.broadcast(steal);
    let r = chain.mine(&[1, 0]); // miner takes Alice's higher-fee transaction first
    assert!(r[0].is_ok() && r[1].is_err() && chain.balance_alice == AMOUNT && chain.balance_bank == 0);
    println!("[ok] B2.2 (gap reproduced: with an Alice-only lock, Alice front-runs the claim, keeps the money and decrypts sk3)");

    // ---------- B2.3 the same front-run against the two-signature lock ----------
    let mut chain = Ledger::default();
    let lock = chain.lock(AMOUNT, w.alice_pk, w.bank_pk, TIMELOCK, Policy::TwoOfTwo);
    let mut tx = claim_tx(lock);
    let ps = adaptor::p_sign(w.a, &tx.digest(), &w.y_chain, &mut rng);
    tx.alice_sig = Some(adaptor::normalize(adaptor::adapt(&ps, w.x)));
    tx.bank_sig = Some(plain_sign(w.bank_sk, &tx.digest(), &mut rng));
    chain.broadcast(tx);
    let mut steal = SpendTx { to: Party::Alice, ..claim_tx(lock) };
    steal.alice_sig = Some(plain_sign(w.a, &steal.digest(), &mut rng));
    steal.bank_sig = tx.bank_sig; // the only Bank signature Alice has seen
    chain.broadcast(steal);
    let r = chain.mine(&[1, 0]);
    expect("B2.3 Alice's redirect, ordered first by the miner", r[0], false);
    expect("B2.3 Bank's claim, ordered second", r[1], true);
    assert_eq!((chain.balance_bank, chain.balance_alice), (AMOUNT, 0));

    // ---------- B2.4–B2.6 the Bank can't take the money without revealing x ----------
    let mut chain = Ledger::default();
    let lock = chain.lock(AMOUNT, w.alice_pk, w.bank_pk, TIMELOCK, Policy::TwoOfTwo);
    let base = claim_tx(lock);
    let ps = adaptor::p_sign(w.a, &base.digest(), &w.y_chain, &mut rng);

    let mut t = base;
    t.bank_sig = Some(plain_sign(w.bank_sk, &t.digest(), &mut rng));
    t.alice_sig = Some(ps_as_sig(&ps)); // the pre-signature itself, used as if it were a signature
    chain.broadcast(t);
    expect("B2.4 claim with the un-adapted pre-signature", chain.mine(&[0])[0], false);

    let mut t = base;
    t.alice_sig = Some(adaptor::normalize(adaptor::adapt(&ps, w.x + SecpFr::from(1u64))));
    t.bank_sig = Some(plain_sign(w.bank_sk, &t.digest(), &mut rng));
    chain.broadcast(t);
    expect("B2.5 claim completed with a wrong witness", chain.mine(&[0])[0], false);

    // The Bank reuses Alice's adapted signature (made for `base`) on a different transaction.
    let mut changed = SpendTx {
        path: Path::Refund,
        alice_sig: Some(adaptor::normalize(adaptor::adapt(&ps, w.x))),
        ..base
    };
    changed.bank_sig = Some(plain_sign(w.bank_sk, &changed.digest(), &mut rng));
    chain.height = TIMELOCK; // even where the refund path is open
    chain.broadcast(changed);
    expect("B2.6 Alice's adapted signature reused on a different transaction", chain.mine(&[0])[0], false);

    // ---------- B2.7–B2.10 timelock ----------
    let mut chain = Ledger::default();
    let lock = chain.lock(AMOUNT, w.alice_pk, w.bank_pk, TIMELOCK, Policy::TwoOfTwo);
    let mut refund = SpendTx { lock, path: Path::Refund, to: Party::Alice, amount: AMOUNT, alice_sig: None, bank_sig: None };
    refund.alice_sig = Some(plain_sign(w.a, &refund.digest(), &mut rng));
    chain.broadcast(refund);
    expect("B2.7 Alice's refund before the timelock", chain.mine(&[0])[0], false);
    chain.height = TIMELOCK;
    chain.broadcast(refund);
    expect("B2.8 Alice's refund after the timelock (Bank never claimed)", chain.mine(&[0])[0], true);
    assert_eq!((chain.balance_alice, chain.balance_bank), (AMOUNT, 0));

    let mut late = claim_tx(lock);
    let ps = adaptor::p_sign(w.a, &late.digest(), &w.y_chain, &mut rng);
    late.alice_sig = Some(adaptor::normalize(adaptor::adapt(&ps, w.x)));
    late.bank_sig = Some(plain_sign(w.bank_sk, &late.digest(), &mut rng));
    chain.broadcast(late);
    expect("B2.9 Bank's claim after Alice refunded", chain.mine(&[0])[0], false);

    // Late claim racing the refund after expiry, claim mined first. Fair only because of the
    // order — B2.12 is the same race with the refund mined first.
    let mut chain = Ledger::default();
    let lock = chain.lock(AMOUNT, w.alice_pk, w.bank_pk, TIMELOCK, Policy::TwoOfTwo);
    chain.height = TIMELOCK + 5;
    let mut late = claim_tx(lock);
    let ps = adaptor::p_sign(w.a, &late.digest(), &w.y_chain, &mut rng);
    late.alice_sig = Some(adaptor::normalize(adaptor::adapt(&ps, w.x)));
    late.bank_sig = Some(plain_sign(w.bank_sk, &late.digest(), &mut rng));
    let mut refund = SpendTx { lock, path: Path::Refund, to: Party::Alice, amount: AMOUNT, alice_sig: None, bank_sig: None };
    refund.alice_sig = Some(plain_sign(w.a, &refund.digest(), &mut rng));
    chain.broadcast(late);
    chain.broadcast(refund);
    let r = chain.mine(&[0, 1]);
    expect("B2.10 Bank's late claim after expiry, mined first", r[0], true);
    expect("B2.10 Alice's racing refund, mined second", r[1], false);
    assert!(alice_decrypts(&w, &chain.confirmed[0], &ps));
    println!("[ok] B2.10 Bank paid late, and Alice extracts x and decrypts sk3 (fair in this order only)");

    // Double spend.
    let mut again = late;
    again.bank_sig = Some(plain_sign(w.bank_sk, &again.digest(), &mut rng));
    chain.broadcast(again);
    expect("B2.11 second claim on the same lock", chain.mine(&[0])[0], false);

    // ---------- B2.12 gap: the same late race, refund mined first ----------
    // Once the claim is broadcast, x is public in the mempool. After expiry Alice's refund is
    // also valid; if the miner picks it, Alice keeps her money AND decrypts the key.
    let mut chain = Ledger::default();
    let lock = chain.lock(AMOUNT, w.alice_pk, w.bank_pk, TIMELOCK, Policy::TwoOfTwo);
    chain.height = TIMELOCK + 5;
    let mut late = claim_tx(lock);
    let ps = adaptor::p_sign(w.a, &late.digest(), &w.y_chain, &mut rng);
    late.alice_sig = Some(adaptor::normalize(adaptor::adapt(&ps, w.x)));
    late.bank_sig = Some(plain_sign(w.bank_sk, &late.digest(), &mut rng));
    chain.broadcast(late);
    assert!(alice_decrypts(&w, &chain.mempool[0], &ps)); // x read from the mempool
    let mut refund = SpendTx { lock, path: Path::Refund, to: Party::Alice, amount: AMOUNT, alice_sig: None, bank_sig: None };
    refund.alice_sig = Some(plain_sign(w.a, &refund.digest(), &mut rng));
    chain.broadcast(refund);
    let r = chain.mine(&[1, 0]);
    assert!(r[0].is_ok() && r[1].is_err() && chain.balance_alice == AMOUNT && chain.balance_bank == 0);
    println!("[ok] B2.12 (gap reproduced: late claim after expiry, refund mined first — Alice keeps the money and decrypts sk3)");

    // ---------- B2.13 the fix: the Bank never reveals x within a safety margin of expiry ----------
    // Protocol rule (as in atomic swaps), not a chain rule: the Bank completes the signature
    // only while height + CLAIM_MARGIN < timelock, so its claim confirms before a refund is valid.
    let bank_may_claim = |height: u64| height + CLAIM_MARGIN < TIMELOCK;
    let mut chain = Ledger::default();
    let lock = chain.lock(AMOUNT, w.alice_pk, w.bank_pk, TIMELOCK, Policy::TwoOfTwo);
    chain.height = TIMELOCK - CLAIM_MARGIN; // too close to expiry
    assert!(!bank_may_claim(chain.height));
    println!("[ok] B2.13 Bank declines to claim {} blocks before expiry: x never leaves the Bank", TIMELOCK - chain.height);
    chain.height = TIMELOCK;
    let mut refund = SpendTx { lock, path: Path::Refund, to: Party::Alice, amount: AMOUNT, alice_sig: None, bank_sig: None };
    refund.alice_sig = Some(plain_sign(w.a, &refund.digest(), &mut rng));
    chain.broadcast(refund);
    expect("B2.13 Alice's refund after expiry (Bank stayed silent; Alice has no x)", chain.mine(&[0])[0], true);

    chain = Ledger::default();
    let lock = chain.lock(AMOUNT, w.alice_pk, w.bank_pk, TIMELOCK, Policy::TwoOfTwo);
    chain.height = TIMELOCK - CLAIM_MARGIN - 1; // inside the window
    assert!(bank_may_claim(chain.height));
    let mut tx = claim_tx(lock);
    let ps = adaptor::p_sign(w.a, &tx.digest(), &w.y_chain, &mut rng);
    tx.alice_sig = Some(adaptor::normalize(adaptor::adapt(&ps, w.x)));
    tx.bank_sig = Some(plain_sign(w.bank_sk, &tx.digest(), &mut rng));
    chain.broadcast(tx);
    expect("B2.13 Bank's claim inside the safety window", chain.mine(&[0])[0], true);
    let mut refund = SpendTx { lock, path: Path::Refund, to: Party::Alice, amount: AMOUNT, alice_sig: None, bank_sig: None };
    refund.alice_sig = Some(plain_sign(w.a, &refund.digest(), &mut rng));
    chain.height = TIMELOCK;
    chain.broadcast(refund);
    expect("B2.13 Alice's refund once the timelock passes (lock already claimed)", chain.mine(&[0])[0], false);

    println!("\nB2 PASSED: the two-signature lock pays the Bank only by revealing x, and resists front-running.");
    println!("Fairness requires the Bank to claim at least {CLAIM_MARGIN} blocks before the timelock (B2.12/B2.13).");
    println!("NOT yet tested: a real chain (Bitcoin script / EVM contract on a testnet).");
}

/// Treat a pre-signature's (r, s') as if it were a finished signature.
fn ps_as_sig(ps: &PreSignature) -> Signature {
    adaptor::normalize(Signature { r: ps.r, s: ps.s_pre })
}
