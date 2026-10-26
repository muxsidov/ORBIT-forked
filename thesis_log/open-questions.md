# Open Questions

Live tracker of unresolved threads surfaced across `thesis_log/`'s dated entries. Unlike those
entries, **this file is edited in place** — when an item is resolved, a new dated entry in the
relevant topic file documents the resolution, and the bullet here is deleted (git history keeps
the record if it's ever needed again). Add a line here the same session an entry first raises an
open item — don't rely on re-reading old entries later to reconstruct what's still pending.

## waters-ibe-signature-scheme.md

- **[critical] Fixed HTLC contract not redeployed.** The `memory` → `storage` fix is in `zfairexchange.sol` and passes `server/test_htlc_state.py` locally, but `HTLC_ADDRESS` still points to the old contract, where withdrawals repeat and drain the pool. Raised 2026-10-02; fixed in source 2026-10-05 ("Fixes for the three critical flaws...").
- **On-device verification of the 2026-10-05 fixes pending.** The app has not been built or run with `consumeCard()`, the per-coin sync keys, the 94-use budget or the new `librust.so`. Untested: that the double withdrawal no longer reproduces, and that 94 ECDH uses suffice in practice (activation + one re-delegation). Raised 2026-10-05.
- **Activation no longer needs the bank.** The `beta_secret` fix removed the IBE gate; `GWat` decrypts with ECDH alone, so "dormant" coins are usable at sync time. Restore an `ak` gate or state as a limitation. Raised 2026-10-02.
- **Hashlock shared per denomination.** `hashlock = denomination` for every contract; once real keys are verified, one key drains all contracts of that denomination and is public after first use. Paper uses a fresh random tag per coin. Raised 2026-10-02.
- **Software attestation root trusted, security level unchecked.** Rooted/emulated devices can fake `nusecount` enforcement. Raised 2026-10-02.
- **Sender can withdraw before the recipient.** `/api/pay` needs only `contract_id`; after re-delegating, the sender (or anyone) can redeem first. Raised 2026-10-02.
- **Denomination forgery (supervisor's concern) — not fixed by the coin counter.** `generate_gs` gives a free 1-of-2 choice on every tag bit, including the fixed denomination bits `DDD`, so the GS evaluator can derive a key for any denomination (latent only because of the tag-encoding mismatch). Server-side, `/api/redelegate` trusts the POST-body denomination and mints a fresh HTLC even when `contract_id` is empty or the old withdrawal fails; `/api/pay` ignores the submitted key. Fixes: bake fixed bits into `base_dk1` and garble only `UUU`/`CCC` (or one Waters key per denomination); stop trusting client denomination (read it from the contract, reject empty `contract_id` in `/api/redelegate`, abort on failed withdrawal); fix the encoding mismatch. The baked-in-bits fix is sound under CDH even without masking (correction entry, 2026-10-02). Status: proposed to supervisor, not implemented. Raised 2026-10-02 ("Re-check against the supervisor's concern...").
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

- **Part B on a real chain.** B1/B2 pass on a simulated ledger; not yet deployed as Bitcoin
  script (testnet/regtest) or an EVM contract with two `ecrecover` checks. Which one to demo?
  Raised 2026-10-07 (`ecdsa-adaptor-secp256k1.md`).
- **Alice's secp256k1 key on Android.** AndroidKeyStore has no secp256k1, so the pre-signing key
  would be a software key, outside the hardware protection the rest of ORBIT relies on. Accept
  as a limitation, or another approach? Raised 2026-10-07.
- **DLEQ proof size and speed for the offline handoff.** 55.4 KB and ~230 ms prove/verify on a
  laptop; doesn't fit the single-QR re-delegation handoff, and phone timing is unmeasured.
  Options: multi-QR/NFC/Bluetooth transport, or a more compact proof. Raised 2026-10-07
  ("Step 4: cross-group DLEQ...").

## ecdsa-adaptor-secp256k1.md

- **[design gap] Identity binding of the FDE-delivered key.** `sk3` is encrypted only under `x`,
  so whoever pays and holds `x` plus the ciphertext gets a working key for Alice's tag; ORBIT's
  hardware binding (dmk tied to the attested AndroidKeyStore key) is lost. Options: attestation
  check before the Bank issues an offer, or additionally encrypt `sk3` to Alice's attested key
  (may conflict with the pairing checks — needs analysis). Raised 2026-10-26 ("Threat review...").
- **Confidential channel and authentication not specified.** Bank–Alice messages must be
  confidential (eavesdropper with the pre-signature and ciphertext gets `sk3`); the offer must be
  signed by the Bank and the Bank's chain key in the lock authenticated. Raised 2026-10-26.
- **Claim safety margin on a real chain.** Fairness needs the Bank to claim while
  `height + CLAIM_MARGIN < timelock` (B2.12/B2.13); the real value depends on confirmation times
  and fee policy. Pick and justify it in the regtest/testnet step. Raised 2026-10-26.

## Tracked elsewhere (cross-reference only, not originated in thesis_log)

- **Tag encoding mismatch.** `h_of_id` (string bit-decomposition) vs.
  `water_unlock_solidity`/`hashlockMatches` (integer bit-decomposition) compute different group
  elements for the same nominal tag, so `/api/pay` silently substitutes its own
  denomination-only derived key rather than checking submitted keys. Tracked primarily in
  `CLAUDE_crypto.md`'s "Tag-encoding mismatch" section. Listed here only because
  several `thesis_log/` entries depend on understanding it.
