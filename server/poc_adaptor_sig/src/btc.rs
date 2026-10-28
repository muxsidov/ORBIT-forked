//! The two-signature lock as Bitcoin transactions (Part B, B3), shared by the regtest binary and
//! the server (Part C). No RPC here: building, hashing and parsing only.
//!
//! Lock: P2WSH with the witness script
//!   IF   <Alice> CHECKSIGVERIFY <Bank> CHECKSIG                   (claim: adapted sig + Bank sig)
//!   ELSE <timelock> CHECKLOCKTIMEVERIFY DROP <Alice> CHECKSIG     (refund after the timelock)
//!   ENDIF
//! Both parties sign the BIP143 SIGHASH_ALL digest of the claim transaction.

use ark_ec::{AffineRepr, PrimeGroup};
use ark_ff::PrimeField;
use ark_secp256k1::{Affine, Fq, Fr, Projective};
use ark_std::rand::Rng;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CLTV, OP_DROP, OP_ELSE, OP_ENDIF, OP_IF};
use bitcoin::script::Builder;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{absolute, transaction, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::adaptor::{self, Signature};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Claim needs Alice's and the Bank's signatures (the §B.2 design).
    TwoOfTwo,
    /// Naive variant: claim needs only Alice's (adapted) signature. B3 uses it to show the gap.
    AliceOnly,
}

/// A funded lock output, as both parties know it.
#[derive(Clone)]
pub struct Lock {
    pub script: ScriptBuf,
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub timelock: u32,
}

/// Compressed public key for script.
pub fn btc_key(p: &Projective) -> PublicKey {
    PublicKey::from_slice(adaptor::to_k256_key(p).to_encoded_point(true).as_bytes()).unwrap()
}

/// Parse a SEC1 (compressed or uncompressed) point; None if not on the curve.
pub fn point_from_sec1(bytes: &[u8]) -> Option<Projective> {
    let pk = k256::PublicKey::from_sec1_bytes(bytes).ok()?;
    let enc = k256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&pk, false);
    let (x, y) = (Fq::from_be_bytes_mod_order(enc.x()?), Fq::from_be_bytes_mod_order(enc.y()?));
    let p = Affine::new_unchecked(x, y);
    (p.is_on_curve() && !p.is_zero()).then(|| p.into_group())
}

pub fn sec1_compressed(p: &Projective) -> Vec<u8> {
    btc_key(p).to_bytes()
}

pub fn scalar_from_be(bytes: &[u8]) -> Option<Fr> {
    (bytes.len() == 32).then(|| Fr::from_be_bytes_mod_order(bytes))
}

pub fn scalar_to_be(x: &Fr) -> [u8; 32] {
    use ark_ff::BigInteger;
    x.into_bigint().to_bytes_be().try_into().unwrap()
}

pub fn lock_script(alice: &PublicKey, bank: &PublicKey, timelock: u32, policy: Policy) -> ScriptBuf {
    let b = Builder::new().push_opcode(OP_IF);
    let b = match policy {
        Policy::TwoOfTwo => b.push_key(alice).push_opcode(OP_CHECKSIGVERIFY).push_key(bank).push_opcode(OP_CHECKSIG),
        Policy::AliceOnly => b.push_key(alice).push_opcode(OP_CHECKSIG),
    };
    b.push_opcode(OP_ELSE)
        .push_int(timelock as i64)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_key(alice)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script()
}

/// Unsigned spend of the whole lock to `to`; `lock_time` > 0 only for the refund.
pub fn spend(lock: &Lock, to: &ScriptBuf, fee: u64, lock_time: u32) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::from_height(lock_time).unwrap(),
        input: vec![TxIn {
            previous_output: lock.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut { value: lock.amount - Amount::from_sat(fee), script_pubkey: to.clone() }],
    }
}

/// What both parties sign: the BIP143 SIGHASH_ALL digest for the witness script.
pub fn sighash(tx: &Transaction, lock: &Lock) -> [u8; 32] {
    SighashCache::new(tx)
        .p2wsh_signature_hash(0, &lock.script, lock.amount, EcdsaSighashType::All)
        .unwrap()
        .to_byte_array()
}

/// Ordinary ECDSA signature (an adaptor pre-signature completed with the trivial witness 1).
pub fn plain_sign<R: Rng>(sk: Fr, digest: &[u8; 32], rng: &mut R) -> Signature {
    let ps = adaptor::p_sign(sk, digest, &Projective::generator(), rng);
    adaptor::normalize(adaptor::adapt(&ps, Fr::from(1u64)))
}

pub fn der(sig: &Signature) -> Vec<u8> {
    let mut v = adaptor::to_k256_sig(sig).unwrap().to_der().as_bytes().to_vec();
    v.push(EcdsaSighashType::All as u8);
    v
}

pub fn set_claim_witness(tx: &mut Transaction, lock: &Lock, alice: &Signature, bank: Option<&Signature>) {
    let mut items: Vec<Vec<u8>> = bank.map(der).into_iter().collect();
    items.extend([der(alice), vec![1], lock.script.to_bytes()]);
    tx.input[0].witness = Witness::from_slice(&items);
}

pub fn set_refund_witness(tx: &mut Transaction, lock: &Lock, alice: &Signature) {
    tx.input[0].witness = Witness::from_slice(&[der(alice), vec![], lock.script.to_bytes()]);
}

/// The signature `back` items from the end of the first input's witness
/// (claim witness: [<bank>] <alice> 1 <script>, so Alice's is 3 and the Bank's 4).
pub fn witness_sig(tx: &Transaction, back: usize) -> Option<Signature> {
    let wit: Vec<&[u8]> = tx.input.first()?.witness.iter().collect();
    let item = wit.get(wit.len().checked_sub(back)?)?;
    let s = k256::ecdsa::Signature::from_der(item.get(..item.len().checked_sub(1)?)?).ok()?;
    let fr = |b: &[u8]| Fr::from_be_bytes_mod_order(b);
    Some(Signature { r: fr(&s.r().to_bytes()), s: fr(&s.s().to_bytes()) })
}

pub fn alice_sig_in(tx: &Transaction) -> Option<Signature> {
    witness_sig(tx, 3)
}

pub fn bank_sig_in(tx: &Transaction) -> Option<Signature> {
    witness_sig(tx, 4)
}
