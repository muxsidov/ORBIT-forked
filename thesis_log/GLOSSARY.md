# Glossary

One-line definitions for terms used across `thesis_log/` entries without re-explaining them
each time. Canonical, fuller definitions live in `CLAUDE_crypto.md` / `CLAUDE_architecture.md` / `CLAUDE_contracts.md` / `ORBIT_PAPER.md` / `CLAUDE_Waters.md`
— this file only points there, it doesn't duplicate them, so the two can't drift apart.

## Paper-level algorithms (ORBIT_PAPER.md, Definition 4.1)

- **OKeyGen / DKeyGen** — bank's / delegatee's one-shot keypair generation.
- **Delegate(sk, pk, pkD)** — bank issues a dormant key `dmk` bound to a fresh `tag`, offline, free.
- **Unlock(sk, tag)** — bank computes the active key `ak` for `tag` (= a Waters signature on `tag`).
- **Activate(dmk, ak, pk, tag)** — delegatee combines `dmk` + `ak` → one-shot signing key `osk`.
- **RDelegate(osk, skD, tag2)** — delegatee re-evaluates their own `osk` at a new tag → `ak2` for the next recipient.
- **DSign(osk, skD, m)** — delegatee spends `osk` to produce a final signature `σ` and stop the chain.
- **One-timeness / history-freeness** — the paper's two core security properties (Def. 4.3/4.4);
  see "Security properties" in `ORBIT_PAPER.md`.

## Code-level key objects

- **dmk** — "dormant key": a garbled circuit (`GWat` + `GS`), inert until activated. Code: the
  server's `/api/delegatedpresig`/`/api/replenish` response (`epk`+`msg`+`gs_circuit`).
- **osk** — the activated one-shot signing key, `(sk1, sk2, sk3)` once evaluated. Stored on
  `DelegatedData.hiding_sign_vec2`.
- **ak2** — the Waters activation key for the *next* recipient, produced by `RDelegate`/GS
  evaluation. Same shape as `osk`: `(sk1, sk2, sk3)`.
- **sk1 / sk2 / sk3** (code names for the paper's `dk1 / dk2 / dk3`) — the 3-component Waters
  activation key. `sk1 ∈ G1` (signing key + hashed identity), `sk2 ∈ G1`, `sk3 ∈ G2` (random
  factor, split across G1/G2 for the Type-3 pairing — see "Waters activation key" in `CLAUDE_crypto.md`).
- **GWat** — the garbled Waters circuit covering Alice's own activation (5 positions × 256
  items, `garble_waters()`).
- **GS** — the second garbled structure covering offline re-delegation (`generate_gs_core()`,
  reached via `garble_waters_with_gs()` / `evaluate_gs()`; `generate_gs()` before 2026-10-05);
  see "GS — the re-delegation circuit" in `CLAUDE_crypto.md`.
- **nUKE** — "n-Use Key Exchange": the paper's non-interactive-OT replacement, backed by
  AndroidKeyStore's hardware `nusecount` limit. Code: `nusecount` attestation parameter.
- **beta_secret (β)** — the Waters IBE master secret; server-only, never transmitted (see
  "`beta_secret` stays on the server" in `CLAUDE_crypto.md`).
- **h_vec / u' / U** — the Waters params' per-bit generator vector (256 generators) and the
  base generator `u'`; `u'·∏u_i` is the bit-decomposable identity term (see `CLAUDE_Waters.md`).

## Tag / identity terms (per-recipient coin counter work, Sept-Oct 2026)

- **tag** — the Waters IBE identity string an activation key is bound to.
- **bobTag** — the concrete tag string Alice's device builds and evaluates the GS circuit
  against during re-delegation: `"UUU_DDD_CCC"` (uid + denomination + coin counter), 88 bits.
  Never transmitted — exists only transiently on the delegator's device.
- **coinIndex / CCC** — the 0-based per-account-per-denomination mint sequence number. Cosmetic
  for self-minted cards; cryptographically bound into `bobTag` for GS-received cards (see
  "Per-coin counter" in `CLAUDE_architecture.md`).
- **TAG_BITS / _GS_TAG_BITS** — the bit-width of the GS evaluation tag (88, was 56 before the
  per-recipient-counter extension).
- **tag encoding mismatch** — a pre-existing, unrelated bug where `h_of_id` (string/ASCII
  bit-decomposition) and `water_unlock_solidity`/`hashlockMatches` (integer bit-decomposition)
  compute different group elements for the same nominal tag — see "Tag-encoding mismatch" in `CLAUDE_crypto.md`. Orthogonal to the GS/RDelegate path and the coin-counter work.

## Crypto primitives referenced in Part A (HTLC replacement / VECK)

- **VECK** — Verifiable Encryption under a Committed Key (informal name used in
  `CLAUDE_replace_HTLC.md`): a scheme letting a recipient verify a ciphertext decrypts to a
  *correct* value before the decryption key is revealed.
- **Type-3 pairing** — `e: G1 × G2 → GT` with no efficient isomorphism between G1 and G2 (BN254,
  used throughout this codebase). Contrast Type-1 (symmetric, G1=G2), which the original Waters
  paper implicitly assumes.
- **XDH assumption** — the hardness assumption a Type-3 pairing's G1/G2 asymmetry can provide;
  relevant to the ElGamal-in-G2 VECK design (`elgamal-sk3-veck.md`).

## Contract / on-chain terms

- **HTLC** — Hash Time-Locked Contract; `zfairexchange.sol` in this codebase.
- **hashlock** — the value an HTLC's withdrawal must match; currently always `= denomination`
  (see "What the demo does instead" in `CLAUDE_contracts.md`), not a true per-tag identity, because of the
  encoding-mismatch bug above.
- **contract_id** — the `bytes32` HTLC identifier from `zfairexchange.sol`'s `HTLCETHNew` event.

See the `CLAUDE_*.md` topic files, `ORBIT_PAPER.md`, and `CLAUDE_Waters.md` for full definitions and code
locations — this file is a quick-reference index only, kept short on purpose.
