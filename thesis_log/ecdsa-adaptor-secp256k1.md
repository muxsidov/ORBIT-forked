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
