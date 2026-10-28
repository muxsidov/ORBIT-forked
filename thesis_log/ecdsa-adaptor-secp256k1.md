# ECDSA Adaptor Signature on secp256k1 (Part B)

Tracks Part B of `CLAUDE_replace_HTLC.md`: enforcing "pay whoever reveals `x`" with an ECDSA
adaptor signature on secp256k1 and a two-signature bonding transaction, without any pairing
on-chain.

## 2026-10-07 — B1 and B2: adaptor signature and two-signature lock, on a simulated ledger

**Attempt:** Implemented the ECDSA adaptor signature of Aumayr et al. (*Generalized Channels*,
Fig. 5) on secp256k1 and connected it to the Part A offer:
- **B1:** Alice pre-signs a payment to the Bank under `Y_chain`. The Bank completes the
  signature with `x`, and Alice extracts `x` and decrypts.
- **B2:** the bonding transaction of `CLAUDE_AandFD.md` §B.2 on a simulated ledger with a
  public mempool, adversarial transaction ordering and a timelock.

**Result:** Success. 34/34 cases pass (`test-results.md`, run 2026-10-07 (3)), and Part A still
passes.

**Details:**
- **Code:** `server/poc_adaptor_sig/src/adaptor.rs` (`p_sign`, `p_verify`, `adapt`, `extract`,
  low-s `normalize`, k256 conversion, Ethereum address and recovery),
  `src/bin/b1_ecdsa_adaptor.rs`, `src/bin/b2_bonding_ledger.rs`. New dependencies: `k256 0.13`,
  `sha3 0.10`.
- **Pre-signature:** `(r, s', R, R', π)` with `R = k·G`, `R' = k·Y`, `r = x(R') mod n`,
  `s' = k⁻¹(z + r·a)`, where `π` is a Chaum-Pedersen proof that `log_G R = log_Y R'`.
- **Adapt:** `s = s'·x⁻¹`. **Extract:** `x = ±s'·s⁻¹`, with the sign fixed by checking against
  `Y`.
- **Chain compatibility** was checked with an independent implementation: the completed
  signature passes k256's standard ECDSA verification and recovers to Alice's Ethereum
  address.
  - k256 rejects high-s signatures, as Bitcoin policy and Ethereum's transaction rules do. The
    Bank must therefore normalise `s → n − s` before broadcasting.
  - Extraction must allow for that negation, which is why `extract` tries both signs. A raw
    high-s completion is rejected by k256 (B1.2a).
- **Cost:** `pSign` 0.66 ms, `pVerify` 0.95 ms.
- **Ledger semantics:** the claim branch has no deadline (Bitcoin script can enforce "refund
  only after", not "claim only before"). The B2.10 race after expiry shows this is still fair:
  if the Bank's late claim wins, it reveals `x`.

**Why:**
- **Why `Adapt` works:** `s⁻¹(z·G + r·A) = x·s'⁻¹(z·G + r·A) = x·R = R'`, so `(r, s)` is an
  ordinary ECDSA signature under Alice's key. Publishing it reveals `x = s'/s` to anyone holding
  the pre-signature.
- **Why the proof `π` is needed:** without it, Alice can choose `R' ≠ k·Y` with `r` and `s'`
  made consistent. Every other check passes, but the completion is invalid (B1.8), so the Bank
  would reveal `x` and still not be paid.
- **Why two signatures:** in the ECDSA variant the completed signature verifies under Alice's
  own key, so an Alice-only lock is spendable by Alice at will. B2.2 reproduces the paper's
  front-running race: Alice extracts `x` from the mempool and redirects the funds. The Bank's
  signature on the exact transaction removes this (B2.3).

**Implication:** Q3 of `multichain-feasibility.md` is answered yes at the protocol level: a
chain needs only standard secp256k1 ECDSA verification and a 2-of-2-with-timelock condition.
Bitcoin script expresses this directly (two `CHECKSIG`s, `CHECKLOCKTIMEVERIFY` refund). On
an EVM chain it is a small contract using `ecrecover` twice, with no BN254 precompile.

Still simulated: the ledger, transaction encoding and script. Real deployment is the next step.

One constraint for Part C: Alice's pre-signing key must be a secp256k1 wallet key. AndroidKeyStore
supports secp256r1 (P-256) but not secp256k1, so this key cannot live in the same hardware
keystore as the ORBIT attestation key; it must be held as a software key on the phone.

## 2026-10-26 — Threat review: late-claim race (correction), channel, authentication, identity binding

**Attempt:** Reviewed the Part A + B protocol against two questions: can Alice obtain `x`
without paying, and can a third party (Bob) impersonate Alice or the Bank? Added cases
B2.12–B2.13 to `b2_bonding_ledger.rs` for the one attack that is testable on the simulated
ledger.

**Result:** Partial. Fairness between Alice and the Bank holds under one added protocol rule (a
claim safety margin). Three requirements outside the cryptography are not yet specified, and
one of them (identity binding) is a real design gap.

**Details:**
- **Correction to the 2026-10-07 entry and test B2.10.** The earlier entry called a late claim
  after the timelock "still fair". That holds only if the claim is mined before Alice's refund.
  Once the Bank broadcasts a claim, `x` is public in the mempool to anyone holding the
  pre-signature. After expiry, Alice's refund is also valid. If a miner includes the refund
  first, Alice keeps her money and decrypts `sk3`. B2.12 reproduces this.
- **Fix (B2.13).** As in atomic swaps, the Bank completes the signature only while
  `height + CLAIM_MARGIN < timelock`, so its claim confirms before any refund becomes valid. If
  the window is missed, the Bank stays silent, `x` never leaks, and Alice is refunded. In the
  simulation `CLAIM_MARGIN = 3`; on a real chain it must cover realistic confirmation delay.
- **Alice cannot get `x` from the offer.** She would have to solve a discrete logarithm. The
  cross-group proof is zero-knowledge, and the hiding of `sk3` rests on the co-CDH-style
  assumption already listed in `open-questions.md`. The in-protocol cheats are already rejected
  (B1.8–B1.9 sabotaged pre-signature, B2.3 front-running).
- **Eavesdropping.** After the claim, computing `x` requires the published signature and the
  pre-signature `s'`, and `x` is useful only with the ciphertext `(c1, c2)`. A party who
  intercepts both obtains `sk3`. The Bank-to-Alice messages must therefore travel over a
  confidential channel, which the design does not yet state.
- **Impersonating the Bank.** The cross-group proof ties `Y_chain` to the ciphertext, so a man
  in the middle cannot substitute his own `x` without failing Alice's checks. Two things still
  need authentication:
  - the offer itself, which the Bank should sign;
  - the Bank's chain key used in the lock. Otherwise Alice could be induced to lock funds
    payable to an attacker.
- **Impersonating Alice: the identity-binding gap.** In the current ORBIT design the dormant
  key is a garbled circuit bound to Alice's attested AndroidKeyStore key, so only her hardware
  can activate it. In the FDE design `sk3` is encrypted only under `x`, so whoever pays and
  obtains `x` and the ciphertext holds a working key for Alice's tag. An impostor still has to
  pay, but the key is not bound to Alice's device.

**Why:** Adaptor signatures make *payment* and *revelation of `x`* atomic. They say nothing
about *when* the claim happens relative to the refund path, *who* sees the messages, or *who*
the counterparty is. These come from protocol rules, channel security and authentication, as in
any atomic-swap deployment.

**Implication:** The fairness claim must be stated as "fair, provided the Bank claims at least
`CLAIM_MARGIN` blocks before the timelock". Before Part C the design needs:
- a confidential, authenticated Bank–Alice channel, with a signed offer and a known Bank chain
  key;
- a decision on identity binding. Options: the Bank checks Alice's attestation before issuing
  an offer; or `sk3` is additionally encrypted to Alice's attested hardware key, so `x` alone is
  not sufficient. The second keeps ORBIT's hardware-binding property but may conflict with the
  pairing-based verification and needs analysis.

## 2026-10-26 — B3: the two-signature lock on Bitcoin Core regtest

**Attempt:** The simulated ledger of B2 was replaced by a local Bitcoin Core v31.1.0 node in
regtest mode (`server/poc_adaptor_sig/src/bin/b3_bitcoin_regtest.rs`, `bitcoin 0.32` crate for
transactions and BIP143 sighashes, RPC through `bitcoin-cli`). The lock is a P2WSH output with
the witness script
`IF <Alice> CHECKSIGVERIFY <Bank> CHECKSIG ELSE <timelock> CHECKLOCKTIMEVERIFY DROP <Alice> CHECKSIG ENDIF`.
The B2 cases were re-run against Bitcoin Core's own script, timelock and mempool rules.

**Result:** Success. 14/14 cases as expected (`test-results.md`, run 2026-10-26 (4)), on two
consecutive runs. Three cases reproduce known gaps on purpose.

**Details:**
- *Compatibility.* Alice's adaptor pre-signature, made with `adaptor::p_sign` over the BIP143
  `SIGHASH_ALL` digest and completed by the Bank with `x` (low-s normalised), is accepted by
  Bitcoin Core's consensus and standardness rules (strict DER, low-s, NULLFAIL, MINIMALIF)
  with no change to `src/adaptor.rs`. The claim transaction is 148 vbytes, i.e. an ordinary
  two-signature P2WSH spend. The chain sees no BN254 material.
- *Extraction from the chain.* Alice locates the spend of her lock outpoint in the tip block
  (or in `getrawmempool`), parses her signature from the witness (`<bank> <alice> 1 <script>`),
  runs `extract`, and decrypts `sk3`, which passes both Waters checks (B3.1).
- *Front-running.* Alice's redirect to herself, reusing the Bank's signature from the mempool
  claim, is rejected by the mempool (B3.2a, NULLFAIL policy flag) and also by consensus: a block
  containing it fails `TestBlockValidity` (B3.2b). A colluding miner therefore cannot help her.
  With the naive Alice-only lock the same redirect replaces the Bank's claim through full-RBF,
  which is on by default since Bitcoin Core 28 (B3.3), so the second signature is necessary on
  a real chain, not only in the model.
- *Timelock.* Refund before the timelock fails as `non-final` (policy) and, with a
  falsified nLockTime, as `Locktime requirement not satisfied` (script, B3.7). Refund at the
  timelock succeeds; a later claim fails as already spent (B3.8, B3.9).
- *Late claim.* After expiry the claim is still accepted into the mempool (the claim branch has
  no deadline), and Alice's higher-fee refund replaces it after she has read `x` from it (B3.10),
  confirming the B2.12 correction on a real node.
- *Margin.* A claim broadcast `CLAIM_MARGIN + 1` = 4 blocks before the timelock and mined in
  the next block is safe: the refund later fails as already spent (B3.11a). The same claim, left
  out of 4 consecutive blocks (`generateblock` with an empty list, standing in for congestion
  or a censoring miner), is replaced by Alice's refund at the timelock (B3.11b).

**Why:** The ECDSA adaptor construction produces a standard ECDSA signature, so Bitcoin needs
no new opcode; the 2-of-2 condition and CLTV are ordinary script. Fairness in the late case is
lost because, once `x` is in the mempool, the claim and the refund are both valid and the
miners pick the higher fee. The Bank cannot raise the claim's fee by itself, since Alice's
signature commits to the whole transaction (`SIGHASH_ALL`), including the fee; it could only
add a child transaction (CPFP), which Alice can outbid with up to the full locked amount.

**Implication:**
- Part B is done on a real Bitcoin node. The claim in `CLAUDE_replace_HTLC.md` that the
  on-chain part needs only the chain's native ECDSA holds for Bitcoin.
- The margin rule must be stated as "the claim is **confirmed** before the timelock", not
  "broadcast before". `CLAIM_MARGIN` has to cover the worst expected confirmation delay at the
  fee Alice pre-signed. Proposed for a public chain (not measured): a timelock of about one day
  (144 blocks) after the lock confirms, the Bank claims as soon as the lock has 1–2
  confirmations, and stops trying `CLAIM_MARGIN` ≈ 12 blocks (about 2 h) before expiry.
  Alice should also pre-sign the claim at a generous fee rate, or at several fee rates (each
  variant reveals the same `x`, so offering several is safe), or with a CPFP anchor output.
- Remaining before Part C: a public testnet run to measure real confirmation delays (optional
  for the thesis); an EVM variant is not needed to show multi-chain readiness, since the same
  signature type would be checked by `ecrecover` (B1).

## 2026-10-26 — Part C: the FDE coin purchase wired into the server, on Bitcoin regtest

**Attempt:** The tested Part A/B code was exposed to the Flask server, alongside the
`zfairexchange.sol` HTLC path, which is unchanged. Three choices were made for this round:
- target Bitcoin regtest;
- bind offers to the device by an attestation gate, not by encryption;
- implement the server side plus a Python end-to-end test, with no Android work yet.

Implementation:
- `server/rustcode/src/fde.rs` wraps `server/poc_adaptor_sig` (path dependency) in 13 PyO3
  functions;
- B3's transaction code moved into the PoC library as `src/btc.rs`, so the regtest binary and
  the server share one implementation;
- `src/dleq.rs` gained a wire format for the cross-group proof;
- `server.py` gained three endpoints:
  - `GET /api/fde/bank` publishes the Bank's chain key and lock parameters;
  - `POST /api/fde/offer`: an attested device receives a Bank-signed offer;
  - `POST /api/fde/claim`: the Bank checks the lock on-chain and Alice's pre-signature, then
    claims, revealing `x`.

**Result:** Success. `test_fde_regtest` passes 26/26 checks (`test-results.md`, run
2026-10-26 (5)). The existing server tests and B3 still pass.

**Details:**
- *Flow.*
  - Alice pins `bank_pk` and requests an offer with her attestation and her secp256k1 key.
  - She checks the Bank's signature over the canonical terms and rebuilds the lock address
    herself from her key, the pinned Bank key and the timelock. She then verifies the encrypted
    key and the cross-group proof with the public Waters parameters only (235 ms).
  - She funds the P2WSH lock from her wallet and pre-signs the claim transaction that the terms
    fix (payout address, fee).
  - The Bank completes the claim. Alice reads it from the block, extracts `x`, and decrypts a
    key that passes both Waters checks for her tag.
- *Bank-side checks before revealing `x`:*
  - the output exists, is unspent, has the agreed address and amount (C7, underfunding), and is
    confirmed (C5);
  - `height + 12 < timelock`, otherwise the offer is marked expired and `x` is never used (C10);
  - Alice's pre-signature verifies on the Bank's own claim transaction (C6);
  - one claim per offer (C9).
- *What Alice never receives:* `beta_secret`, or any secret other than the decrypted key. `x`
  stays in the server's offer record until the claim publishes it.
- *Identity binding (gate).*
  - `/api/fde/offer` calls the existing `verify_attestation`; a rejected chain gives 403.
  - The signed terms record the SHA-256 of the attested AndroidKeyStore public key, so an offer
    is attributable to one device.
  - This is a policy check by the Bank. The decrypted key itself is not tied to the device.
- *Parameters.*
  - Timelock: 144 blocks after the offer.
  - Claim margin: 12 blocks.
  - Claim fee: 1 000 sat, fixed in the pre-signed transaction.
  - Amounts: `_DENOM_SAT`, the `_DENOM_ETH` nominal values in BTC.
  - The Bank key comes from `BTC_BANK_KEY`, or a fresh key per run.
- *Sizes.*
  - The offer is 114 211 bytes as JSON: the 55.4 KB cross-group proof, hex-encoded.
  - The pre-signature is 6 values, about 0.4 KB.
- *Observation.* Two offers issued to the same Alice key in the same block have the same lock
  script and address. This is harmless: each pre-signature commits to one outpoint and one
  `Y_chain`, so one funding output can pay for at most one offer.

**Why:** The algorithms needed no change between the PoC and the server. All the Bitcoin
specifics are in the lock script and the BIP143 digest, both already tested in B3. The server
adds only the checks a careful Bank must make before revealing `x`.

**Implication:**
- Part C is done for the server and a scripted Alice. The FDE purchase now runs end to end
  against a real Bitcoin node, alongside the Sepolia HTLC demo.
- Still open:
  - the Android client (a software secp256k1 key, offer verification in JNI, a transport for
    the 114 KB offer);
  - a confidential channel (plain HTTP today);
  - cryptographic identity binding, which the gate does not provide;
  - re-delegation over FDE;
  - persistence of offers across server restarts.
