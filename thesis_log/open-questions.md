# Open Questions

Live tracker of unresolved threads surfaced across `thesis_log/`'s dated entries. Unlike those
entries, **this file is edited in place** — when an item is resolved, a new dated entry in the
relevant topic file documents the resolution, and the bullet here is deleted (git history keeps
the record if it's ever needed again). Add a line here the same session an entry first raises an
open item — don't rely on re-reading old entries later to reconstruct what's still pending.

## waters-ibe-signature-scheme.md

- **[critical] `beta_secret` derivable from the public seed and bundled in the app.** `generate_params_waters()` draws `alpha_secret = beta_secret` from `ark_std::test_rng()` (fixed public seed), so anyone can compute `msk` and forge Waters keys for any tag. `res/raw/waters_params.json` also contains `beta_secret`. Fix: real randomness for the secret, kept on the server; seed only the public elements; strip it from the bundled file; regenerate params. Empirical confirmation pending. Raised 2026-10-26 ("Master secret `beta_secret` derivable...").
- **[critical] Fixed HTLC contract not redeployed.** The `memory` → `storage` fix is in `zfairexchange.sol` and passes `server/test_htlc_state.py` locally, but `HTLC_ADDRESS` still points to the old contract, where withdrawals repeat and drain the pool. Raised 2026-10-02; fixed in source 2026-10-05 ("Fixes for the three critical flaws...").
- **On-device verification of the 2026-10-05 fixes pending.** The app has not been built or run with `consumeCard()`, the per-coin sync keys, the 94-use budget or the new `librust.so`. Untested: that the double withdrawal no longer reproduces, and that 94 ECDH uses suffice in practice (activation + one re-delegation). Raised 2026-10-05.
- **Activation no longer needs the bank.** The `beta_secret` fix removed the IBE gate; `GWat` decrypts with ECDH alone, so "dormant" coins are usable at sync time. Restore an `ak` gate or state as a limitation. Raised 2026-10-02.
- **Hashlock shared per denomination.** `hashlock = denomination` for every contract; once real keys are verified, one key drains all contracts of that denomination and is public after first use. Paper uses a fresh random tag per coin. Raised 2026-10-02.
- **Software attestation root trusted, security level unchecked.** Rooted/emulated devices can fake `nusecount` enforcement. Raised 2026-10-02.
- **Sender can withdraw before the recipient.** `/api/pay` needs only `contract_id`; after re-delegating, the sender (or anyone) can redeem first. Raised 2026-10-02.
- **Denomination forgery (supervisor's concern) — fixed in code 2026-10-26, not yet deployed or enforced at payout.** Circuit: `generate_gs_core` now garbles only the slot matching the coin's real bit for the fixed `_DDD_` bytes (bits 24–63), so a denomination-1 coin cannot be evaluated at a denomination-100 tag (`test_gs_full`); costs 40 unneeded uses (`_GS_NUSECOUNT` could drop to 54). The Android `evaluate_gs` was changed but `librust.so` is not rebuilt; old coins must be re-minted. Server: `/api/redelegate` and `/api/pay` read the denomination from the on-chain contract, reject empty `contract_id`, and `/api/redelegate` aborts on a failed withdrawal (`test_denomination_trust`, mocks only). Still open: the circuit fix only bites at payout once the tag-encoding mismatch is fixed (`/api/pay` ignores the submitted key), and it assumes `beta_secret` is secret, which it currently is not (derivable from the seed, 2026-10-26). `/api/lock` still trusts the request denomination.
- **Two-sender race condition.** Two senders who scan the same displayed "My ID" QR before the
  recipient's counter advances independently derive Waters keys for an identical
  `(uid,denom,counter)` tag. Accept as a documented limitation, or mitigate? Raised 2026-09-28
  ("On-chain vs. offline-only scope for the embedded coin counter").
- **Brute-forceable `(uid,denom,counter)` tag space.** The ~7M-combination tag space lets anyone
  holding a submitted `(sk1,sk2,sk3)` (the server receives it on every `/api/pay` call) recover
  exactly which coin was redeemed via trial Waters verification — a linkability channel beyond
  what the offline-only scope decision accounted for. Mitigation options (high-entropy nonce vs.
  accept-and-document) not yet decided. Raised 2026-10-01 ("Limitation: small enumerable tag
  space makes (uid,denom,counter) brute-forceable from a submitted key").
- **Legacy GS circuits have no versioning/migration.** Any `gs_circuit` minted before the
  56→88-bit extension or the 2026-10-05 masking change is incompatible (the latter now fails
  with a parse error rather than silently); the only fix today is discard-and-re-mint, not a
  code-level handling path. Raised 2026-09-28 ("Per-recipient coin counter cryptographically
  embedded in the GS tag").
- **Counter field width overflow.** `CCC` is fixed at 3 ASCII digits (`%03d`); a per-denomination
  counter reaching 1000 breaks the tag's byte alignment. Not handled. Raised 2026-09-28.
- **Multi-denomination counters-map fallback not empirically verified.** The default-to-`0` path
  (Bob receiving a denomination he's never touched before) has only been reasoned about, not
  exercised in a real device-to-device scan. Raised 2026-09-28 ("Clarifying which denomination
  Bob's 'My ID' QR applies to").

## denomination-and-identity-qr-review.md

- **Recipients have no attestation binding ("Option A" gap).** Bob's "My ID" QR is a
  self-declared, unverified `uid` with no hardware-key attestation — one-timeness (Def. 4.3) is
  only enforced on the delegator's side of a re-delegation, not the recipient's, beyond the
  first hop. A deliberate scope limitation (demo shortcut vs. "Option B"), not a bug — but worth
  resolving or explicitly bounding before claiming full paper-equivalence. Raised 2026-08-17.

## elgamal-sk3-veck.md

- **Hiding assumption for the encrypted sk3 not yet stated.** Publishing `Y_G1 = g^k` makes
  DDH in G2 easy for the ciphertext, so the hiding of `sk3` rests on a computational, co-CDH-style
  assumption (compute `g2^{kb}` from `g^k, g2^k, g2^b`), not IND-CPA. Needs stating and arguing for
  the security chapter. Raised 2026-10-07 ("Step 3: Waters check 2 verified...").

## multichain-feasibility.md

- **Alice's secp256k1 key on Android.** AndroidKeyStore has no secp256k1, so the pre-signing key
  would be a software key, outside the hardware protection the rest of ORBIT relies on. Accept
  as a limitation, or another approach? Raised 2026-10-07.
- **FDE purchase on Android.** Part C runs with a scripted Alice (`test_fde_regtest`). The app
  needs the Alice-side functions in JNI (`fde_verify_offer`, `fde_presign`, `fde_extract_decrypt`,
  refund), a software secp256k1 key, a way to fund the lock, and a transport for the 114 KB offer.
  Offers are kept only in server memory. Raised 2026-10-26 ("Part C: ... wired into the server").
- **DLEQ proof size and speed for the offline handoff.** 55.4 KB and ~230 ms prove/verify on a
  laptop; doesn't fit the single-QR re-delegation handoff, and phone timing is unmeasured.
  Options: multi-QR/NFC/Bluetooth transport, or a more compact proof. Raised 2026-10-07
  ("Step 4: cross-group DLEQ...").

## ecdsa-adaptor-secp256k1.md

- **[design gap] Identity binding of the FDE-delivered key — gate implemented, binding open.**
  `/api/fde/offer` now issues offers only to an attested device and records the attested key's
  hash in the signed terms (Part C, 2026-10-26). The delivered `sk3` is still bound to `x` only:
  whoever pays and holds the ciphertext gets a working key. Cryptographic binding (also encrypting
  `sk3` to the attested key) is unanalysed. Raised 2026-10-26 ("Threat review...").
- **Confidential channel not specified.** Authentication is done in Part C (Bank-signed terms,
  pinned `bank_pk`, Alice rebuilds the lock address herself). Confidentiality is not: the offer
  travels over plain HTTP, and an eavesdropper with the ciphertext and the pre-signature gets
  `sk3` after the claim. Needs TLS or encryption to Alice's key. Raised 2026-10-26.
- **Claim safety margin on a real chain.** Fairness needs the Bank's claim *confirmed* before
  the timelock, not just broadcast: on regtest an unconfirmed claim 4 blocks early is replaced by
  Alice's refund under full-RBF (B3.11b). The Bank cannot raise the pre-signed fee (only CPFP).
  Proposed, not measured: ~144-block timelock, ~12-block margin, Alice pre-signs at a generous
  fee or several fee levels. Measure confirmation delays on a public testnet, or argue the value
  from fee data. Raised 2026-10-26; narrowed 2026-10-26 ("B3: ... regtest").

## two-bank-refund-design.md

- **Two-bank payback path not designed.** Supervisor's proposal: Alice pays two banks half each,
  an exchange coordinates, at least one bank is honest, everything on Bitcoin. Open: the refund
  scripts, how `x` is shared, the exchange's role, and the payout rule ("whoever provides the …
  is paid" is incomplete in the source). Raised 2026-10-27 ("Problem statement...").
- **No coin holder is ever paid.** Sepolia: every HTLC's receiver is the Bank's own address, so
  Withdraw pays the Bank back. Bitcoin FDE: no redemption step exists. Bob paying Alice on
  re-delegation is designed but not implemented. Part of the two-bank design scope. Raised
  2026-10-27 ("Gap: no coin holder is ever paid...").

## Tracked elsewhere (cross-reference only, not originated in thesis_log)

- **Tag encoding mismatch.** `h_of_id` (string bit-decomposition) vs.
  `water_unlock_solidity`/`hashlockMatches` (integer bit-decomposition) compute different group
  elements for the same nominal tag, so `/api/pay` silently substitutes its own
  denomination-only derived key rather than checking submitted keys. Tracked primarily in
  `CLAUDE_crypto.md`'s "Tag-encoding mismatch" section. Listed here only because
  several `thesis_log/` entries depend on understanding it.
