# Replacing zfairexchange.sol's HTLC with an Adaptor-Signature / Verifiable-Encryption Scheme

Design exploration (prof-suggested direction) for replacing the current HTLC hashlock
mechanism in `zfairexchange.sol` with a discrete-log-based adaptor-signature construction
applied directly to the Waters activation key. Not yet implemented — this is a design doc,
analogous in status to `so-all-of-this-breezy-lampson.md`.

**Objective is genuine multi-chain support**, not just an Ethereum-only simplification —
confirmed explicitly by the user. The construction must work against any chain with a native
ECDSA or Schnorr adaptor-signature scheme (Bitcoin, most EVM chains, etc.), not only chains
with a pairing precompile. See `CLAUDE_AandFD.md` for the paper background this is modeled on.

## Motivation

Current `zfairexchange.sol` requires the chain to evaluate a full BN254 pairing check
(`e(...) = e(...)`) on-chain to verify a submitted `(sk1,sk2,sk3)` — see "Waters activation key" in `CLAUDE_crypto.md`. This ties ORBIT to chains with a pairing precompile
(effectively just Ethereum/EVM via `alt_bn128`).

Professor's suggestion: replace the on-chain pairing check with an **adaptor-signature-style
verifiable encryption** of `sk3`. The pairing math moves entirely off-chain (checked by the
recipient before they lock funds); the on-chain contract only needs to enforce a generic
"pay out to whoever reveals the discrete log of `Y`" condition — the same primitive behind
Bitcoin/Monero-style atomic swaps ("scriptless scripts").

## Background reading

- Tas et al., *Atomic and Fair Data Exchange via Blockchain* (local copy:
  `Atomic and Fair Data.pdf`, summarized in `CLAUDE_AandFD.md` — read that instead of the PDF)
  — Fair Data Exchange (FDE) protocol; the Bank/Alice flow below is modeled directly on this
  paper's Ethereum protocol (§4.2: server posts commitment → sends encrypted payload + proof
  off-chain → client locks funds → server reveals decryption key on-chain → client decrypts)
  and, for the multi-chain generalization, its Bitcoin/adaptor-signature protocol (Appendix B).
- Aumayr et al., *Generalized Channels from Limited Blockchain Scripts and Adaptor
  Signatures* (local copy: `Generalized Channels.pdf`) — formal adaptor signature syntax
  (`pSign`/`pVrfy`/`Adapt`/`Ext`), ECDSA-based construction (Fig. 5), Schnorr-based
  construction (Appendix B, Fig. 8).

## Core idea: ElGamal-encrypt sk3 under an adaptor statement

Waters activation key recap (BN254 Type-3 pairing, see `CLAUDE_crypto.md`):
`sk1 = g^α·H(tag)^r ∈ G1`, `sk2 = g^r ∈ G1`, `sk3 = g2^r ∈ G2`.

Only `sk3` needs protection — it's the component the pairing check isolates against `g2`.
`sk1`, `sk2` can be sent in the clear.

### The two-hop witness fix (resolves the group-mismatch problem below)

An adaptor signature's statement `Y` must be a discrete-log statement *in the same group as the
target chain's own signature scheme* (secp256k1 for Bitcoin/most EVM ECDSA, whichever curve for
Schnorr) — see `CLAUDE_AandFD.md`'s adaptor-signature section. `sk3` lives in BN254 `G2`, fixed
by Waters IBE. These are different groups, so a single `Y = g^x` cannot serve both as "the
on-chain adaptor statement" and "the ElGamal public key masking `sk3`" the way an earlier draft
of this doc assumed.

Fix: **one secret scalar `x`, hashed into two independent public commitments:**

```
Y_chain  := x · G_chain              (adaptor statement, native to the target chain's own
                                       signature curve — e.g. secp256k1 for Bitcoin/EVM-ECDSA)
Y_bn254  := g2^(H(x) mod r)          (VECK "public key", in G2, r = BN254 scalar field order)
```

Both are published by the Bank up front. `Y_chain` is what the target chain's adaptor-signature
machinery (§B.2 of `CLAUDE_AandFD.md`) actually operates on — no BN254, no pairing precompile
needed on-chain at all. `Y_bn254` is used only off-chain, by Alice, to verify the VECK
ciphertext before she locks any funds. Once the Bank reveals `x` on-chain (via `Adapt`/`Extract`
on the adaptor signature), Alice recovers `H(x) mod r` and can decrypt — see Step 5 below.

**ElGamal ciphertext of sk3**, masked additively (group operation) under `Y_bn254` (no need for
exponential ElGamal since `sk3` is already a group element, not a scalar):
```
c1 := g2^b                (fresh random b)
c2 := Y_bn254^b · sk3
```
Both `Y_bn254`, `c1`, `c2`, `sk3` live in `G2` — this part is group-type-consistent and its
round trip (mask with a known `x`, later decrypt with it) is **confirmed working in code**, see
`thesis_log/elgamal-sk3-veck.md`, Step 1 (`server/poc_adaptor_sig/src/bin/step1_baseline_elgamal.rs`).

**Verification identity — corrected, still being validated (do not treat as settled).** An
earlier version of this doc claimed `e(s3,g2) = e(Y_bn254,c1)^{-1}·e(c2,g2)`, which does **not**
type-check: BN254 here is a Type-3 asymmetric pairing (`e: G1 × G2 → GT`, confirmed by every
pairing call in `server/rustcode/src/lib.rs`), and `Y_bn254`, `c1` both live in `G2` — there is
no defined `e(G2, G2)` operation, and no efficient map from `G2` to `G1` (that asymmetry is the
whole point of using a Type-3 curve). See `thesis_log/elgamal-sk3-veck.md`'s first 2026-08-12
entry for the full writeup of this bug and why it went unnoticed until implementation.

**Notation.** Write `k` for the BN254 exponent of the ElGamal key, so `Y_bn254 = g2^k` (today
`k = H(x) mod r`; see "Cross-group link" below for why `k = x` may be preferable). All BN254
values use the Waters params' own generators `param.g` (G1) and `param.g2` (G2) — these are
random elements, **not** `G1::generator()`/`G2::generator()`.

**Current hypothesis (not yet confirmed):** publish a second commitment to the *same exponent
`k`*, this time in `G1`: `Y_G1 := param.g^k`. (An earlier draft wrote `Y_G1 = g^x`; with
`Y_bn254 = g2^(H(x))` the exponents differ and the identity below fails unless `H(x) = x`.)

Alice first checks the two commitments agree:
```
e(Y_G1, g2) == e(g, Y_bn254)                                  (consistency)
```
Then, writing `Dec := c2 · c1^{-k}` for what the ciphertext decrypts to:
```
e(g, c2) · e(Y_G1, c1)^{-1} = e(g, c2) · e(g, c1)^{-k} = e(g, Dec)
```
so Waters check 1 (`e(sk2,g2) == e(g,sk3)`) can be checked from public values only as
```
e(sk2, g2) == e(g, c2) · e(Y_G1, c1)^{-1}                    (check 1, encrypted)
```
Because `e(g, ·)` is injective on G2, this proves `Dec = g2^r` exactly (where `sk2 = g^r`), for
*any* `c1` — no well-formedness proof for `c1` needed. Step 2 of Part A.

**Waters check 2** (`e(g_alpha,g2_beta)·e(h_tag,sk3) == e(sk1,g2)`) needs `e(h_tag, Dec)`, and
`h_tag` is not a power of `g`, so `Y_G1` doesn't help. `h_vec`/`h_0` exist only in G1
(`ParamWaters`, `server/rustcode/src/lib.rs`), so there's no G2 twin to move the pairing onto
`sk2` either. **Hypothesis:** the Bank additionally sends the per-tag hint `T := h_tag^k ∈ G1`
(Alice's tag is known at issuance). Alice checks
```
e(T, g2) == e(h_tag, Y_bn254)                                 (hint consistency)
e(g_alpha, g2_beta) · e(h_tag, c2) · e(T, c1)^{-1} == e(sk1, g2)   (check 2, encrypted)
```
since `e(h_tag, c2)·e(T, c1)^{-1} = e(h_tag, Dec)`. Plain pairings, one extra G1 point — **confirmed in code (Step 3)**;
Groth-Sahai is not needed. Step 3 of Part A. Track in
`thesis_log/elgamal-sk3-veck.md`.

**Cross-group link (unresolved — the actual fairness gap).** The checks above prove the
ciphertext decrypts correctly under `k`. Nothing yet proves that `Y_chain = x·G_chain` hides an
`x` that yields that `k`. A cheating Bank can publish `Y_chain` for `x` and `Y_bn254` for an
unrelated `k'`: it gets paid on-chain when it reveals `x`, and Alice's decryption yields garbage.
Options:
- **`k = H(x)`** (current doc): proving the link needs a ZK proof of a hash preimage across
  groups (a SNARK) — heavy.
- **`k = x`**, with `x < 2^252` (fits both the secp256k1 and BN254 scalar fields): the link is a
  standard *cross-group discrete-log equality* proof (bit-decomposition with Pedersen
  commitments in both groups; the technique used in Monero↔Bitcoin atomic swaps, with existing
  Rust implementations). **Chosen and confirmed in code (Step 4).**
Step 4 of Part A.

## Full protocol (Bank ↔ Alice)

Modeled on the Atomic & Fair Data paper's FDE flow, Bank = server, Alice = client, "data" =
`sk3`:

1. **Bank → Alice (off-chain):** `sk1`, `sk2` in the clear, ElGamal ciphertext
   `(c1,c2) = (g2^b, Y_bn254^b·sk3)`, the commitments `Y_chain = x·G_chain`, `Y_bn254 = g2^k`,
   `Y_G1 = g^k`, the check-2 hint `T = h_tag^k`, and a cross-group proof linking `Y_chain` to
   `Y_bn254`.
2. **Alice verifies** consistency, check 1 and check 2 (encrypted forms above) and the
   cross-group proof — confirms the hidden `sk3` is well-formed *and* that the `x` she pays for
   unlocks it, without decrypting. dmk is still dormant (matches ORBIT's Issuance phase).
3. **Alice locks payment on-chain**, using `Y_chain` as the adaptor statement in a bonding
   transaction shaped like `CLAUDE_AandFD.md`'s §B.2 Bitcoin construction — i.e. spending the
   locked funds before the timelock requires **both** an adaptor signature under `Y_chain` and
   the Bank's own ordinary signature (see the anti-frontrunning note in `CLAUDE_AandFD.md`;
   this is the two-signature fix the original single-signature `withdraw()` design lacked).
4. **Bank claims payment** by computing `σ ← Adapt(pk_σ, σ̂, x)` and broadcasting it alongside
   its own ordinary signature on the same spending transaction — the chain only ever sees an
   ordinary-looking adaptor-signed transaction, not `(sk1,sk2,sk3)` or any BN254 material.
5. **Alice extracts `x`** from the on-chain transaction (`Extract`, in adaptor-signature
   terms), derives `k` from it, then `c1^k = g2^{b·k} = Y_bn254^b`, then:
   ```
   sk3 = c2 / Y_bn254^b = c2 · c1^{-k}
   ```
   Alice now holds a valid `(sk1, sk2, sk3)` — dmk activated.

**Protocol requirements found in the 2026-10-26 threat review**
(`thesis_log/ecdsa-adaptor-secp256k1.md`):
- **Claim safety margin.** The Bank completes the adaptor signature only while
  `height + CLAIM_MARGIN < timelock`. A late claim leaks `x` in the mempool while Alice's
  refund is valid, so Alice could get both her money and the key (test B2.12).
- **Confidential channel.** Step 1's messages must be confidential. An eavesdropper holding the
  pre-signature and the ciphertext can decrypt `sk3` after the claim.
- **Authentication.** The Bank signs the offer, and Alice locks to an authenticated Bank chain
  key.
- **Identity binding (open).** `sk3` is bound only to `x`, not to Alice's attested hardware as
  the dmk is today. See Part C.

## Re-delegation for free (Alice → Bob)

Once Alice holds `sk3` in the clear (post-Step 5), she can play the Bank's role for Bob using
the identical primitive:

1. Pick fresh `b'` and a fresh secret `x'` — **known only to Alice** (the seller; whoever
   reveals the witness is the one who gets paid — if Bob knew it he could decrypt without
   paying). Publish the same commitments: `Y'_chain = x'·G_chain`, `Y'_bn254 = g2^{k'}`,
   `Y'_G1 = g^{k'}`, `T' = h_tag^{k'}`, plus the cross-group proof.
2. Send Bob `sk1`, `sk2`, and `(c1', c2') = (g2^{b'}, Y'_bn254^{b'}·sk3)`.
3. Bob verifies (Step 2 above), locks payment against `Y'_chain` (same two-signature
   bonding-transaction shape as Step 3 above); Alice claims it, revealing `x'`; Bob extracts
   `x'` and decrypts `sk3` the same way Alice did.

Note `h_tag` here is the tag the key was issued for — this is "Option A" (Bob reuses Alice's
key), so `T'` uses Alice's tag, not Bob's. Also unresolved: Alice still holds `sk3` after the
sale, so this alone doesn't make the coin one-shot.

This replaces the current GS-circuit-based offline re-delegation (89 AndroidKeyStore ECDH ops since the 88-bit tag change, see "GS — the re-delegation circuit" in `CLAUDE_crypto.md`) with the same atomic-fair-exchange primitive
used for activation. It's cryptographically equivalent to today's "Option A" (Bob reuses
Alice's exact `(sk1,sk2,sk3)`), except the handoff becomes atomic and fair by construction —
Bob can't be cheated out of a decryptable `sk3` without Alice getting paid, and vice versa —
rather than depending on the server to honestly mediate `/api/redelegate`.

## Consequence: chain generalization

Because the pairing check moves entirely off-chain (Alice/Bob verify it themselves before
locking funds) and the on-chain adaptor statement `Y_chain` lives in the target chain's own
native curve (not BN254), the on-chain contract's job shrinks to a generic "pay out to whoever
produces a valid adaptor-signed spend under `Y_chain`" condition — exactly
`CLAUDE_AandFD.md` §B.2's Bitcoin bonding transaction. This is **not** tied to a
pairing-supporting chain; it only needs the target chain's native signature scheme to support
an ECDSA or Schnorr adaptor-signature construction, which covers most major chains (Bitcoin,
most EVM chains via secp256k1-ECDSA, Taproot/Schnorr chains), not just EVM ones with an
`alt_bn128` precompile. **This is the actual objective — genuine multi-chain support — not an
Ethereum-only simplification.**

## Implementation plan

### Part A — crypto-only proof of concept (no chain, no app)

Standalone Rust binaries in `server/poc_adaptor_sig/src/bin/`, one per step, before touching
any blockchain or Android code. Every step has negative tests: a cheating Bank must be caught
*before* Alice pays, not after decryption.

1. **Baseline ElGamal round trip — done** (`step1_baseline_elgamal.rs`). Uses
   `G2::generator()` and `x` directly; later steps switch to `param.g`/`param.g2` and `k`.
2. **Check 1 without decrypting — done** (`step2_check1_encrypted.rs`). Publish `Y_G1 = g^k`, `Y_bn254 = g2^k`; verify consistency
   and check 1 (encrypted). Negative: tampered `c2`; `Y_G1`/`Y_bn254` with different exponents.
   Check 1 alone accepts any self-consistent `(g^{r'}, g2^{r'})` — validity needs Step 3.
3. **Check 2 without decrypting — done** (`step3_check2_encrypted.rs`; 11 pairings, ~12 ms). Add the hint `T = h_tag^k`; verify hint consistency and
   check 2 (encrypted). Negative: wrong `T`; hint for a different tag; key for a different tag;
   consistent `(sk2', sk3')` with an `sk1` that doesn't match.
4. **Cross-group link — done** (`step4_cross_group_link.rs`, `src/dleq.rs`; proof 55.4 KB, ~230 ms prove/verify). Pick `x < 2^252`, set `k = x`, `Y_chain = x·G_secp256k1` (`k256`), and
   prove `Y_chain`/`Y_bn254` share `x` (cross-group DLEQ). Negative: `Y_chain` for a different
   `x` must be rejected. Run this negative test *before* adding the proof too — it should pass
   verification, documenting the gap.
5. **Reveal and decrypt — covered by Step 4** (case 4.2: `x` handed over as a secp256k1 scalar decrypts `sk3`; the real reveal is Part B). Simulate the on-chain reveal of `x`, decrypt `sk3' = c2 · c1^{-k}`,
   assert `sk3' == sk3`. (Re-running the Waters checks on the decrypted key adds nothing once
   `sk3' == sk3` holds — the encrypted checks in Steps 2–3 are the real test.)

Part A is complete; the remaining feasibility risk is Part B. Zero blockchain/Android dependency. Per-coin secrets
(`x`, `b`) may use `test_rng()` in the PoC but must use `thread_rng()` once ported (CLAUDE.md).

### Part B — one concrete adaptor-signature instantiation, on a real chain

**Status 2026-10-07:** ECDSA adaptor (Fig. 5) and the two-signature lock are done on a
**simulated ledger** — `src/adaptor.rs`, `src/bin/b1_ecdsa_adaptor.rs`,
`src/bin/b2_bonding_ledger.rs` (34/34 cases, `thesis_log/test-results.md`). Completed signatures
pass k256's standard verifier and Ethereum-style recovery.
**Status 2026-10-26: done on a real chain** — `src/bin/b3_bitcoin_regtest.rs`, a P2WSH 2-of-2 +
CLTV lock on Bitcoin Core v31.1 regtest (14/14 cases). Front-running is rejected by consensus;
fairness needs the claim *confirmed* before the timelock (`CLAIM_MARGIN`, B3.11b). Needs
`bitcoind -regtest -datadir=$HOME/btc-regtest -daemon -fallbackfee=0.0001` running.
Findings: low-s normalisation is required (extract must try `±`); the pre-signature's DLEQ proof
is load-bearing; the claim branch can't have a deadline in Bitcoin script (still fair).

Once Part A confirms the VECK side works, implement one full adaptor-signature bonding
transaction for real:

- Recommended: **ECDSA-adaptor on secp256k1** (Aumayr et al., *Generalized Channels* Fig. 5 —
  well-specified, existing Rust crates for ECDSA adaptor signatures exist, and secp256k1 is
  native to both Bitcoin and most EVM chains, so this single instantiation demonstrates
  multi-chain-readiness without committing to Bitcoin Script specifically).
  Schnorr-adaptor (Appendix B, Fig. 8 of the same paper) is the cleaner construction and matches
  Bitcoin Taproot directly, but has less tooling support outside Bitcoin-specific libraries —
  fall back to it only if a Bitcoin-specific demo becomes the priority.
- Implement `pSign`/`pVerify`/`Adapt`/`Extract` for the chosen scheme.
- Build the two-signature bonding transaction shape from `CLAUDE_AandFD.md` §B.2 (adaptor sig
  + Bank's ordinary sig required together) — either on an actual testnet (Bitcoin testnet, or a
  secp256k1-ECDSA-capable EVM testnet) or a local simulated ledger if standing up chain infra
  is its own detour better deferred.
- Confirm the anti-frontrunning property holds: a party who sees the pre-signature cannot
  extract the witness or redirect funds before the Bank's real spend confirms.

### Part C — wire into ORBIT

**Status 2026-10-26: server side done, on Bitcoin regtest** (`test_fde_regtest`, 26/26).
- `server/rustcode/src/fde.rs`: PyO3 wrappers over `poc_adaptor_sig`, which is a path
  dependency; the shared transaction code is in `src/btc.rs`.
- Endpoints `GET /api/fde/bank`, `POST /api/fde/offer` and `POST /api/fde/claim` in
  `server.py`, alongside the HTLC flow.
- Decisions:
  - Bitcoin regtest first;
  - identity binding by an attestation gate, with the attested key hash in the signed terms;
  - authentication by Bank-signed terms and a pinned `bank_pk`;
  - timelock 144 blocks, claim margin 12 blocks.
- Not done:
  - Android;
  - a confidential channel;
  - cryptographic identity binding;
  - re-delegation over FDE;
  - offer persistence.

**Constraints found in Parts A/B (resolve before or during Part C; tracked in
`thesis_log/open-questions.md`):**
- The cross-group DLEQ proof is 55.4 KB, with ~230 ms prove/verify on a laptop and phone timing
  unmeasured. It doesn't fit the single-QR offline handoff used for re-delegation today, so it
  needs multi-QR/NFC/Bluetooth or a more compact proof.
- Alice's pre-signing key must be secp256k1. AndroidKeyStore has no secp256k1, so it would be a
  software key, outside the hardware protection used for the ORBIT attestation key.
- **Identity binding.** The FDE-delivered `sk3` is bound to `x` only. Whoever pays gets a working
  key for Alice's tag, which loses ORBIT's hardware binding. Options: an attestation check
  before the Bank issues an offer, or encrypting `sk3` additionally to Alice's attested key.
- Confidential, authenticated Bank–Alice channel (signed offer, known Bank chain key), and the
  claim safety margin; see "Protocol requirements" above.

- Add this as a **new path alongside** (not replacing) the existing `zfairexchange.sol` +
  pairing-check flow, so the current working Waters/RDelegate demo never breaks.
- Server: new endpoint(s) analogous to `/api/delegatedpresig`/`/api/pay`, but returning
  `(Y_chain, Y_bn254, c1, c2)` instead of the current unmasked flow, plus whatever pre-signature
  material the chosen adaptor scheme needs from the Bank.
- Compare against the `beta_secret` stripping fix already done for the current design (see `CLAUDE_crypto.md`) — this design likely also removes any need to send `beta_secret`-derived
  material to Alice, since she decrypts a Bank-prepared ciphertext rather than re-deriving
  `sk3` herself. Confirm once Part A/B are working.
- Re-delegation (Alice → Bob) reuses the identical primitive per the "Re-delegation for free"
  section above — no separate mechanism needed.

## Open questions / not yet resolved

- Concrete on-chain script/contract for the bonding transaction on the Part B target chain —
  Bitcoin Script vs. a minimal EVM contract that just checks an ECDSA-adaptor-completed
  signature recovers to the expected address (no pairing precompile needed either way).
- How `x` (and thus `Y_chain`/`Y_bn254`) is generated per-transaction — today's `hashlock` is
  derived deterministically from `denomination`; `x` needs an analogous per-transaction
  generation/derivation scheme, ideally still tied to `denomination` so `Y_chain` can serve the
  same role `hashlock` does today (binding a lock to a specific coin value).
- **Decided 2026-10-07: `k = x`** (`x < 2^252`), see "Cross-group link". Read `H(x)` elsewhere in this doc as `x`.
- The 55 KB DLEQ proof doesn't fit the single-QR offline handoff used for re-delegation; Part C needs another transport or a smaller proof.
- Part A is done (`server/poc_adaptor_sig`, Steps 1–4; Step 5 covered by Step 4). Part B done on a simulated ledger (B1, B2) and on Bitcoin Core regtest (B3, 2026-10-26); Part C server side done (2026-10-26), Android not started.
- Alice's pre-signing key must be secp256k1; AndroidKeyStore has no secp256k1, so it would be a software key on the phone (Part C).