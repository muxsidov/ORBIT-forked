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
