# Test Results

Raw pass/fail record of the research test programs, for the thesis Evaluation chapter. One
table row per test case. Append-only: each run gets its own dated section with the exact
command, commit and environment, and earlier runs are never edited. When a test that used to
pass fails (or the reverse), the new run records it, and the why goes in the matching topic
entry (`elgamal-sk3-veck.md`, `multichain-feasibility.md`).

**Column meanings**
- **Kind:** *positive* (honest behaviour must be accepted / must work), *negative* (a
  cheating Bank or a corrupted message must be rejected), *gap* (documents a known weakness:
  the "expected" result is the insecure one, kept to show why a later step is needed).
- **Simulates:** the real-world situation or attack the case stands for.
- **Expected / Observed:** what the verifier should do and what it did.
- **Result:** PASS when observed = expected, FAIL otherwise.

---

## Run 2026-10-07 — Part A, Steps 1–3

- **Code:** `server/poc_adaptor_sig/`, commit `7f95ba4` plus uncommitted
  `src/lib.rs`, `src/bin/step2_check1_encrypted.rs`, `src/bin/step3_check2_encrypted.rs`.
- **Environment:** WSL2 (Linux 6.18), rustc 1.94.1, `--release`, arkworks 0.5 (`ark-bn254`).
- **Randomness:** `ark_std::test_rng()` (fixed seed; results are reproducible).
- **Command:** `cargo run -q --release --bin <name>` for each binary below; all exited 0.
- **Totals:** 19 cases (6 positive, 12 negative, 1 gap), 19 PASS, 0 FAIL.

### Step 1 — baseline ElGamal-in-G2 round trip (`step1_baseline_elgamal`)

Masks `sk3` as `(c1, c2) = (g2^b, Y^b · sk3)` and decrypts with the secret known directly. No
verification before decryption.

| # | Kind | Case | Simulates | Expected | Observed | Result |
|---|---|---|---|---|---|---|
| 1.1 | positive | Ground-truth Waters key | Key generated as the server does (`water_derive_ak`) | Both Waters checks hold | Both hold | PASS |
| 1.2 | positive | Encrypt then decrypt `sk3` | Bank encrypts, secret later revealed | Decryption equals `sk3` | Equal | PASS |
| 1.3 | positive | Waters checks on the decrypted key | Alice uses the recovered key | Both checks hold | Both hold | PASS |

### Step 2 — Waters check 1 on the encrypted `sk3` (`step2_check1_encrypted`)

Alice checks `e(Y_G1, g2) == e(g, Y_bn254)` and `e(sk2, g2) == e(g, c2) · e(Y_G1, c1)^{-1}`
from public values only.

| # | Kind | Case | Simulates | Expected | Observed | Result |
|---|---|---|---|---|---|---|
| 2.1 | positive | Honest offer | Honest Bank | Accept; decrypts to `sk3`; key valid | Accept; decrypts; valid | PASS |
| 2.2 | positive | Random `c1`, `c2 = c1^k · sk3` | Ciphertext not built the standard way, but correct | Accept; decrypts to `sk3` | Accept; decrypts | PASS |
| 2.3 | negative | Random G2 element added to `c2` | Corrupted or tampered ciphertext | Reject | Reject | PASS |
| 2.4 | negative | `c2` encrypts a different key's `sk3` | Bank sells a key that doesn't match `sk2` | Reject | Reject | PASS |
| 2.5 | negative | `Y_G1` with a different exponent than `Y_bn254` | Bank advertises inconsistent commitments | Reject | Reject | PASS |
| 2.6 | negative | `c2` masked under a different `k` | Revealed secret would not decrypt the ciphertext | Reject | Reject | PASS |
| 2.7 | negative | Commitments on the curve's default generators | Implementation bug: wrong generators (the Step 1 shortcut) | Reject | Reject | PASS |

### Step 3 — both Waters checks on the encrypted `sk3` (`step3_check2_encrypted`)

Adds the hint `T = h_tag^k`. Alice computes `h_tag` from her own tag and also checks
`e(T, g2) == e(h_tag, Y_bn254)` and
`e(sk1, g2) == e(g_alpha, g2_beta) · e(h_tag, c2) · e(T, c1)^{-1}`.

| # | Kind | Case | Simulates | Expected | Observed | Result |
|---|---|---|---|---|---|---|
| 3.1 | positive | Honest offer | Honest Bank | Accept; decrypts to `sk3`; key valid | Accept; decrypts; valid | PASS |
| 3.2 | negative | Random `T` | Bank sends a garbage hint | Reject | Reject | PASS |
| 3.3 | negative | `T` computed for tag `001_043` instead of `001_042` | Hint for someone else's coin | Reject | Reject | PASS |
| 3.4 | negative | `T` under a different exponent | Hint inconsistent with the commitments | Reject | Reject | PASS |
| 3.5 | gap | Fake `(g^{r'}, g2^{r'})` with the real `sk1`, check 1 only | The Step 2 weakness: check 1 alone accepts a key unrelated to `sk1` | Check 1 accepts | Accepts | PASS |
| 3.6 | negative | Same fake key, full verifier | Same attack against the Step 3 verifier | Reject | Reject | PASS |
| 3.7 | negative | Random G1 element added to `sk1` | Tampered `sk1` | Reject | Reject | PASS |
| 3.8 | negative | Valid key, honestly encrypted, for tag `001_043` | Bank sells a valid key bound to the wrong identity | Reject | Reject | PASS |
| 3.9 | negative | Random G2 element added to `c2` | Corrupted or tampered ciphertext | Reject | Reject | PASS |

Step 2's 2.1–2.2 and Step 3's 3.1 count the "decrypts to `sk3`" and "key valid" checks as
part of the same case.

**Measurement:** the Step 3 verifier evaluates 11 pairings (1 constant and cacheable). Single
runs on this machine: 12.0, 12.5, 12.7, 12.1 ms. Not a benchmark (no warm-up, no repetition
statistics); repeat properly before quoting in the thesis.

**Not covered by this run:** whether `Y_chain` (the on-chain secret on secp256k1) hides the same
secret as `Y_bn254` (Part A Step 4), and on-chain enforcement (Part B).

---

## Run 2026-10-07 (2) — Part A, Step 4 (plus regression of Steps 1–3)

- **Code:** `server/poc_adaptor_sig/`, commit `7f95ba4` plus uncommitted `src/lib.rs`,
  `src/dleq.rs`, `src/veck.rs`, `src/bin/step2_*`, `step3_*`, `step4_cross_group_link.rs`,
  and new dependencies `ark-secp256k1 0.5`, `ark-serialize 0.5`, `sha2 0.10`.
- **Environment:** WSL2 (Linux 6.18), rustc 1.94.1, `--release`, arkworks 0.5.
- **Randomness:** `ark_std::test_rng()` (fixed seed).
- **Command:** `cargo run -q --release --bin <name>`; all four binaries exited 0.
- **Regression:** Steps 1–3 re-run after the library change: unchanged, all 19 cases PASS (see
  the previous run's tables).
- **Totals for Step 4:** 11 cases (1 positive, 9 negative, 1 gap), 11 PASS, 0 FAIL.

### Step 4 — cross-group link between `Y_chain` and the encrypted key (`step4_cross_group_link`)

With `k = x` (`x < 2^252`), the Bank adds `Y_chain = x·G` on secp256k1 and a cross-group
discrete-log equality (DLEQ) proof that `Y_chain` and `Y_G1 = g^x` (BN254 G1) share `x`. Alice
runs the Step 3 checks plus the proof check.

| # | Kind | Case | Simulates | Expected | Observed | Result |
|---|---|---|---|---|---|---|
| 4.1 | gap | Offer encrypted under `x'`, checked with the Step 3 verifier only | Bank gets paid for `x` but encrypted under a different secret | Step 3 accepts; revealing `x` does not decrypt | Accepts; decryption ≠ `sk3` | PASS |
| 4.2 | positive | Honest offer with proof; `x` revealed as a secp256k1 scalar | Honest Bank; on-chain reveal | Accept; decrypts to `sk3`; key valid | Accept; decrypts; valid | PASS |
| 4.3 | negative | `Y_chain` for a different `x`, honest proof | Bank swaps the on-chain statement | Reject | Reject | PASS |
| 4.4 | negative | Offer under `x'`, genuine proof for `x'`, `Y_chain` for `x` | The 4.1 cheat with a valid-looking proof | Reject | Reject | PASS |
| 4.5 | negative | Proof for another statement replayed | Reusing an old proof | Reject | Reject | PASS |
| 4.6 | negative | Prover asked to prove `x ≥ 2^252` | Secret too large to be the same integer in both groups | Prover refuses | Refuses | PASS |
| 4.7 | negative | One bit commitment changed (secp256k1 side) | Tampered proof | Reject | Reject | PASS |
| 4.8 | negative | Digits 2 and −1 in bits 0 and 1, sums still match | Committing different values per group while sums agree | Reject | Reject | PASS |
| 4.9 | negative | One response changed | Tampered proof | Reject | Reject | PASS |
| 4.10 | negative | Challenge split changed, XOR unchanged | Forging the OR-proof split | Reject | Reject | PASS |
| 4.11 | negative | Proof truncated to 251 bits | Malformed proof | Reject | Reject | PASS |

**Measurement:** 252-bit proof, 55.4 KB (compressed points, 32-byte scalars). Single runs:
prove 227 / 228 / 231 ms, verify 226 / 227 / 230 ms. Not a benchmark; repeat properly before
quoting. Alice's full check is the DLEQ verify plus the Step 3 verifier (~12 ms).

**Not covered by this run:** a real on-chain reveal of `x` through an adaptor signature
(Part B). The reveal in 4.2 is simulated by handing over `x` as a secp256k1 scalar.

---

## Run 2026-10-07 (3) — Part B, Steps B1–B2 (plus regression of Part A)

- **Code:** `server/poc_adaptor_sig/`, commit `5952652` plus uncommitted `src/adaptor.rs`,
  `src/bin/b1_ecdsa_adaptor.rs`, `src/bin/b2_bonding_ledger.rs`, `src/lib.rs` (module line), and
  new dependencies `k256 0.13` (feature `ecdsa`), `sha3 0.10`.
- **Environment:** WSL2 (Linux 6.18), rustc 1.94.1, `--release`.
- **Randomness:** `ark_std::test_rng()` (fixed seed).
- **Command:** `cargo run -q --release --bin <name>`; all six binaries (Steps 1–4, B1, B2)
  exited 0.
- **Regression:** Part A Steps 1–4 unchanged, all 30 cases PASS.
- **Totals for Part B:** 34 cases (14 positive, 18 negative, 2 gap), 34 PASS, 0 FAIL.
- **Independent verifier:** completed signatures are checked with `k256` (RustCrypto), a separate
  ECDSA implementation from the arkworks code that produced them. It enforces low-s, as
  Bitcoin policy does.

### B1 — ECDSA adaptor signature on secp256k1 (`b1_ecdsa_adaptor`)

Alice pre-signs a payment to the Bank under `Y_chain` (from the Step 4 offer). The Bank
completes the signature with `x`; Alice extracts `x` and decrypts.

| # | Kind | Case | Simulates | Expected | Observed | Result |
|---|---|---|---|---|---|---|
| B1.1a | positive | `pVerify` of Alice's honest pre-signature | Bank checks Alice's pre-signature | Accept | Accept | PASS |
| B1.1b | positive | Completed signature, standard ECDSA verify (k256) | A chain verifying the Bank's payment | Accept | Accept | PASS |
| B1.1c | positive | Completed signature, `ecrecover`-style recovery | Ethereum's signer recovery | Alice's address | Alice's address | PASS |
| B1.1d | positive | Extract `x`, decrypt, Waters checks | Alice reads the chain and activates her key | `x` recovered; `sk3`; valid | As expected | PASS |
| B1.2a | negative | Completed signature with high `s`, not normalised | Signature a chain would refuse (Bitcoin low-s rule) | Reject | Reject | PASS |
| B1.2b | positive | Same signature low-s normalised | Bank normalises before broadcasting | Accept | Accept | PASS |
| B1.2c | positive | Extract from the normalised signature | Alice extracts after normalisation (`s → n − s`) | `x` recovered | `x` recovered | PASS |
| B1.3a | positive | Completed signature already low-s | No normalisation needed | Accept | Accept | PASS |
| B1.3b | positive | Extract from it | Alice extracts | `x` recovered | `x` recovered | PASS |
| B1.4 | negative | Pre-signature under a different `Y` | Alice pre-signs for a statement the Bank can't complete | Reject | Reject | PASS |
| B1.5 | negative | Pre-signature checked against a different transaction | Pre-signature on the wrong payment | Reject | Reject | PASS |
| B1.6 | negative | Pre-signature checked against a different key | Not Alice's key | Reject | Reject | PASS |
| B1.7 | negative | `s'` tampered | Corrupted pre-signature | Reject | Reject | PASS |
| B1.8 | gap | `R' ≠ k·Y` with `r`, `s'` recomputed; checks without the DLEQ proof | Alice sabotages: Bank would reveal `x` for an invalid signature | Passes non-DLEQ checks; completion invalid | As expected | PASS |
| B1.9 | negative | Same pre-signature, full `pVerify` | The B1.8 attack against the real check | Reject | Reject | PASS |
| B1.10 | negative | Completed with a wrong witness, standard verify | Bank without `x` | Reject | Reject | PASS |
| B1.11 | negative | Completed with a wrong witness, recovery | Same, on Ethereum | Not Alice's address | Not Alice's | PASS |
| B1.12 | negative | Extract using an unrelated pre-signature | Wrong pairing of signature and pre-signature | No `x` | None | PASS |
| B1.13 | negative | Extract from a signature not made by `Adapt` | Unrelated signature | No `x` | None | PASS |

**Measurement:** `pSign` 0.66 ms, `pVerify` 0.95 ms (single run, laptop).

### B2 — two-signature bonding transaction on a simulated ledger (`b2_bonding_ledger`)

Lock: claim needs Alice's (completed) signature **and** the Bank's ordinary signature on the
same transaction, at any time while unspent. Refund needs Alice's signature and
`height ≥ timelock`. The miner may order transactions adversarially.

| # | Kind | Case | Simulates | Expected | Observed | Result |
|---|---|---|---|---|---|---|
| B2.1a | positive | Bank's claim with both signatures | Honest payment | Confirmed | Confirmed | PASS |
| B2.1b | positive | Alice extracts `x` from the confirmed transaction | Alice activates her key | `sk3`; valid | As expected | PASS |
| B2.2 | gap | Naive Alice-only lock; Alice front-runs the Bank's claim | The race the paper warns about | Alice keeps money and decrypts | As expected | PASS |
| B2.3a | negative | Same front-run against the two-signature lock, mined first | Alice redirects funds after seeing `x` in the mempool | Reject | Reject (Bank sig invalid) | PASS |
| B2.3b | positive | Bank's claim, mined second | Bank still paid | Confirmed | Confirmed | PASS |
| B2.4 | negative | Claim with the un-completed pre-signature | Bank tries to get paid without `x` | Reject | Reject | PASS |
| B2.5 | negative | Claim completed with a wrong witness | Bank tries to get paid without `x` | Reject | Reject | PASS |
| B2.6 | negative | Alice's completed signature reused on a different transaction | Bank changes the transaction | Reject | Reject | PASS |
| B2.7 | negative | Refund before the timelock | Alice reclaims too early | Reject | Reject | PASS |
| B2.8 | positive | Refund after the timelock, Bank never claimed | Bank disappears | Confirmed; Alice refunded | As expected | PASS |
| B2.9 | negative | Bank's claim after Alice refunded | Late claim on a spent lock | Reject | Reject | PASS |
| B2.10a | positive | Late claim after expiry, mined before Alice's refund | Bitcoin-style: claim branch has no deadline | Confirmed | Confirmed | PASS |
| B2.10b | negative | Alice's racing refund, mined second | Same race | Reject | Reject | PASS |
| B2.10c | positive | Alice extracts `x` from the late claim | Outcome still fair | `sk3`; valid | As expected | PASS |
| B2.11 | negative | Second claim on the same lock | Double spend | Reject | Reject | PASS |

**Not covered by this run:** a real chain. The ledger, transaction format and script
conditions are simulated. Only signature verification uses a standard implementation.

---

## Run 2026-10-26 — Part B, B2 timelock race (plus regression of everything)

- **Code:** `server/poc_adaptor_sig/`, commit `5952652` plus uncommitted Part B files
  (`src/adaptor.rs`, `src/bin/b1_ecdsa_adaptor.rs`, `src/bin/b2_bonding_ledger.rs`). This run
  adds cases B2.12–B2.13 and the constant `CLAIM_MARGIN = 3` to `b2_bonding_ledger.rs`.
- **Environment:** WSL2 (Linux 6.18.54), rustc 1.94.1, `--release`.
- **Randomness:** `ark_std::test_rng()` (fixed seed).
- **Command:** `cargo run -q --release --bin <name>`; all six binaries exited 0.
- **Regression:** Part A (30 cases), B1 (19 cases) and B2.1–B2.11 (15 cases) unchanged, all
  PASS.
- **Totals for this run's new cases:** 5 cases (3 positive, 1 negative, 1 gap), 5 PASS, 0 FAIL.

**Correction to run 2026-10-07 (3), row B2.10c.** That row reads "Outcome still fair". This holds
only for the order tested, where the Bank's late claim is mined before Alice's refund. With the
opposite order the outcome is unfair to the Bank (B2.12 below). The B2.10 rows themselves are
unchanged and still pass.

### B2.12–B2.13 — the late-claim race and the safety-margin fix (`b2_bonding_ledger`)

| # | Kind | Case | Simulates | Expected | Observed | Result |
|---|---|---|---|---|---|---|
| B2.12 | gap | Bank claims after expiry; Alice reads `x` from the mempool and broadcasts her refund; miner picks the refund first | The Bank claims too late | Refund confirmed; claim rejected; Alice keeps her money and decrypts `sk3` | As expected | PASS |
| B2.13a | positive | Bank asked to claim 3 blocks before expiry (`height + CLAIM_MARGIN ≥ timelock`) | The Bank follows the safety-margin rule | Bank declines; `x` never revealed | Declines | PASS |
| B2.13b | positive | Alice's refund after expiry, Bank stayed silent | Refund without having learned `x` | Confirmed | Confirmed | PASS |
| B2.13c | positive | Bank's claim inside the safety window | Honest, timely claim | Confirmed | Confirmed | PASS |
| B2.13d | negative | Alice's refund once the timelock passes, after the timely claim | Refund after a confirmed claim | Reject | Reject (spent) | PASS |

**What this shows:** the chain alone does not make the exchange fair near expiry. Fairness
needs the protocol rule that the Bank completes the signature only while
`height + CLAIM_MARGIN < timelock`. The margin must cover the claim's confirmation time on the
real chain.
