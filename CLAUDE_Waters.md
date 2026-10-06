# Waters IBE / Signature Scheme — Paper Reference

Summary of Brent Waters, "Efficient Identity-Based Encryption Without Random Oracles"
(Eurocrypt 2005; local copy `Waters.pdf`). Read this instead of re-reading the PDF for
questions about the underlying cryptographic scheme ORBIT's Waters activation key is built on.
For how these concepts map onto the actual code in this repo, see `CLAUDE_crypto.md` — this file stays paper-focused
plus tag-design notes so the two don't drift out of sync. Dated design-discussion history for
this topic lives in `thesis_log/waters-ibe-signature-scheme.md` (append-only, never edited).

## What the paper proves

- First IBE scheme fully secure in the standard model (no random oracle), security reduced to
  the decisional Bilinear Diffie-Hellman (BDH) assumption.
- A derived signature scheme (§7), security reduced to the weaker computational Diffie-Hellman
  (CDH) assumption, also without random oracles.

## Construction (§4, paper's own G/G1 notation — symmetric-ish pairing)

**Setup**: secret `α ∈ Zp`; generator `g`; `g1 = g^α`; `g2` random in `G`; `u′ ∈ G` random; `U =
(u_i)` an *n*-length vector of random generators, one per identity bit position. Public params:
`(g, g1, g2, u′, U)`. Master secret: `g2^α`.

**KeyGen(v)**: identity `v` is an *n*-bit string, `V = {i : v_i = 1}`. Pick random `r`. Private
key:
```
d_v = ( g2^α · (u′·∏_{i∈V} u_i)^r , g^r )
```

**Encrypt(M, v)**: pick random `t`.
```
C = ( e(g1,g2)^t · M, g^t, (u′·∏_{i∈V} u_i)^t )
```

**Decrypt**: `C1 · e(d2,C3) / e(d1,C2) = M`.

**Signature scheme (§7)**: same Setup/KeyGen shape — secret key `g2^α`, "signature" of message
`M` is literally `d_v` evaluated at `v = M`'s bits. Verification is one deterministic pairing
check: `e(σ1,g) / e(σ2, u′·∏_{i∈M} u_i) = e(g1,g2)`. This determinism (vs. the generic
IBE→signature transform's randomized verify) is what drops the security reduction from
decisional BDH down to plain CDH.

## The two properties ORBIT actually exploits

1. **Signature = IBE decryption key.** `KeyDerWat(sk, tag) = SignWat(sk, tag)` — literally the
   same object (`d_v` / `σ_M`). This lets a garbled circuit gate access to a next-stage secret
   behind "produce a valid signature for `tag`", by IBE-encrypting that secret to
   identity=`tag`. This is the mechanism behind ORBIT's `GS` circuit / `RDelegate` (see
   `CLAUDE_crypto.md`, "GS — the re-delegation circuit").
2. **Bit-decomposable identity term.** `u′·∏_{i∈V} u_i` is a product of *independent per-bit*
   generators — not `u′·g1^v` (Boneh-Boyen's integer form, cited in the paper §4.2 as the
   modification Waters made to Boneh-Boyen). This decomposability is what makes ORBIT's
   OT/garbling-based `garble_waters`/`generate_gs` possible at all: because the exponent is a
   product over independent bit positions, each bit can be independently secret-shared and
   gated behind a 1-of-2 AndroidKeyStore ECDH (nUKE). The integer form would not decompose this
   way.

   **This is exactly the axis of ORBIT's documented "tag encoding mismatch" bug**
   (`CLAUDE_crypto.md`, "Tag-encoding mismatch"): `h_of_id`/`garble_waters`
   (server Rust) correctly use the bitwise/product form; `water_unlock_solidity` /
   `hashlockMatches` (Solidity) use the integer form. Same nominal "tag", two different group
   elements.

## Type-3 pairing adaptation — why ORBIT's key is a 3-tuple, not 2

The paper frames a single group `G` with `e: G×G → G1` (effectively symmetric/Type-1). BN254 in
ORBIT is Type-3 (`e: G1×G2 → GT`, no efficient isomorphism between G1 and G2), so the paper's
single `g^r` term splits into a G1 copy (`sk2`) and a G2 copy (`sk3 = g2^r`), giving **two**
verification checks instead of the paper's one:
- `e(g, sk3) == e(sk2, g2)` — consistency (both use the same `r`)
- `e(g^α, g2^β) · e(H(tag), sk3) == e(sk1, g2)` — the actual Waters equation

Standard Type-3 adaptation; does not change the security argument, just the group bookkeeping.

## Design notes: splitting the identity into semantic fields

Full dated history: `thesis_log/waters-ibe-signature-scheme.md`.

### uid / denomination field split — validated, safe

If `V = V_uid ⊍ V_denom` (disjoint generator index ranges, no overlap) and the identity is the
fixed-width concatenation `uid ∥ denom`, then
```
u′·∏_{i∈uid} u_i^{m_i} · ∏_{j∈denom} u_j^{d_j}
```
is **the identical group element** as the flat `u′·∏_{i∈V} u_i` form — multiplication in `G` is
commutative/associative, so this is a regrouping, not a new construction. Security (Theorem 1)
and correctness (Decrypt) are unaffected, provided:
- no generator index is reused across fields, and
- the `(uid, denom) → bitstring` encoding is injective (fixed-width, zero-padded fields already
  satisfy this).

**What the split does *not* give you**: independent per-field re-derivability. A key valid for
`(uid=A, denom=1)` does not yield a key for `(uid=A, denom=2)` without a fresh full `Unlock` —
that would require a genuine hierarchical (HIBE) construction. Paper §6 sketches an ℓ-level HIBE
built the same way but notes the reduction becomes inefficient (`O((nq)^ℓ ϵ)`) beyond small `ℓ`
— not attractive past ~2 levels.

### Per-recipient coin counter in the tag — IMPLEMENTED (September 2026)

Idea: extend the GS circuit's `bobTag` from `uid ∥ denom` (56 bits, `"UUU_DDD"`) to
`uid ∥ denom ∥ counter` (88 bits, `"UUU_DDD_CCC"`), cryptographically binding a re-delegated
coin's Waters key to the specific serial-numbered coin (`coinIndex`), not just the recipient +
denomination.

**Cost**: more GS bit-slots ⇒ higher attested `nusecount` (currently 64, would need ~89+) ⇒
changes needed in server (`verify_attestation` allowlist), Rust (`garble_waters`/`generate_gs`),
and Android (`computeGsAk2`/`evaluate_gs`).

**Core obstacle (architectural, not cryptographic)**: Alice must know Bob's *live* counter value
fully offline, before her GS evaluation. The current "My ID" QR is cached/static
(`{"uid":N}`, read from `SharedPreferences`), which can't supply a value that changes over time.

**Decided (2026-09-28)**: "My ID" will regenerate its QR live every time it's shown, embedding
`{"uid":N,"counters":{denom:count,...}}` read fresh from `orbit_coin_counters_$account` at
render time — not implemented yet, this is the agreed direction.

**Considered and dismissed as non-blocking (2026-09-28)**: Bob can trivially edit/reset his own
local counter (unauthenticated client-side `SharedPreferences`, no in-UI edit control, clearable
via account delete/recreate — see `PersistencyManager.removeAccount()`). Judged not a real
security issue: Waters' unforgeability notion concerns whether an *unauthorized* party can forge
a signature for an identity, not whether a user's self-chosen identity label is internally
consistent. Bob duplicating his own tag by resetting his own counter cannot forge another user's
key or claim another user's funds — worst case, confusing/duplicate cosmetic tags in his own
wallet. This conclusion holds **only** as long as the counter stays confined to the offline
GS/RDelegate derivation and never reaches on-chain verification — if a future change routes the
counter into `hashlockMatches`, a duplicate on-chain hashlock becomes a real replay concern and
would need actual uniqueness enforcement (e.g. a server-issued nonce).

**Decided (2026-09-28): offline-only.** The embedded counter is checked only by the offline GS
circuit derivation (`computeGsAk2`/`evaluate_gs`) and is never validated by
`zfairexchange.sol`'s `hashlockMatches`. Reasoning: the on-chain option's main selling point —
real rejection of a mismatched key — doesn't actually materialize from the scoped change alone,
since `hashlockMatches` only checks a key against the one HTLC instance storing it, not a global
registry; catching cross-contract tag collisions would need a much larger nullifier-style
registry feature. Against that thin benefit, on-chain enforcement would require fixing the
tag-encoding-mismatch bug first, roughly doubles the bit-width (and gas cost) of
`hashlockMatches`'s decomposition loop, and reintroduces a server dependency on
client-asserted `(uid, counter)` state that conflicts with the counter being locally-resettable
client state. It would also mean investing Solidity effort in `zfairexchange.sol`'s hashlock
mechanism right as `CLAUDE_replace_HTLC.md` explores replacing it. Full tradeoff writeup:
`thesis_log/waters-ibe-signature-scheme.md`, entry "On-chain vs. offline-only scope for the
embedded coin counter."

This closes out the counter-embedding design question end-to-end (nusecount expansion, live
"My ID" QR, offline-only trust boundary) — implementation-ready whenever picked up. Still open,
not yet decided: the two-sender-race-condition risk (two people scanning the same shown QR
before Bob's counter advances, deriving keys for an identical tag) — accept as a documented
limitation, or mitigate.

**Implemented (2026-09-28).** `server.py`: `_GS_TAG_BITS` 56→88, new `_GS_NUSECOUNT=96` constant
replacing the hardcoded `64` throughout. No Rust changes on the server side — `generate_gs`
already took `tag_bits` as a parameter, and `h_vec` has 256 generators (verified live against
the running params), far more than the 88 now indexed, so no params regeneration was needed.
`MainActivity.kt`: `bobTag` now `"%03d_%03d_%03d"`, sourced from the scanned "My ID" QR's new
`counters` map; the re-delegation QR carries the chosen counter back so the recipient's
`addCardFromQR()` records it verbatim (`recordReceivedCounter()`) instead of self-assigning —
this is what keeps the tile's cosmetic `CCC` and the cryptographic tag in sync for GS-received
cards. `computeGsAk2()`/`evaluate_gs()` (Kotlin + Android Rust JNI) required **no changes** —
both already derived their bit-slot count from the tag string's length rather than a hardcoded
constant, so the 56→88 extension was purely a caller-side change. Full details and known
limitations (no collision enforcement, legacy-card incompatibility, no automated test):
`CLAUDE_crypto.md`, "The re-delegation tag". The
two-sender race condition above remains an accepted, undecided limitation — not addressed by
this implementation.

## Sections worth re-reading directly from `Waters.pdf`

- **§5** (security proof): the "artificial abort" technique — correcting for the adversary's
  success probability being correlated with the simulator's abort probability. Relevant if this
  project ever needs to reason formally about its own reduction.
- **§6** (HIBE extension): the per-level reduction-efficiency caveat, relevant to any future
  hierarchical-tag idea (e.g. independent per-denomination re-derivation).
- **§7.2**: the signature scheme's security theorem (existential unforgeability under adaptive
  chosen-message attack, reduces to CDH) — the formal justification for treating `(sk1,sk2,sk3)`
  as an unforgeable token in the first place.
