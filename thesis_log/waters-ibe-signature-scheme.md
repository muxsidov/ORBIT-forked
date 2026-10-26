# Waters IBE / Signature Scheme

Tracks review of Brent Waters' "Efficient Identity-Based Encryption Without Random Oracles"
(Eurocrypt 2005, local copy `Waters.pdf`) and design discussions about extending ORBIT's
Waters identity ("tag") to carry more structured/semantic information (denomination, per-user
coin counters).

## 2026-09-28 — Waters IBE/signature paper review, and tag-splitting design discussion

**Attempt:** Extracted and read the full text of `Waters.pdf` (Brent Waters, "Efficient
Identity-Based Encryption Without Random Oracles", Eurocrypt 2005, 13 pages) via PyMuPDF, then
worked through how its construction maps onto ORBIT's `h_of_id`/`garble_waters`/GS-circuit
implementation, and evaluated two proposed extensions to the Waters identity ("tag"): splitting
it into disjoint `uid`/`denomination` generator-index ranges, and further embedding a
per-recipient coin serial counter for RDelegate.

**Result:** Partial — the paper-to-code mapping and the uid/denomination field-split were fully
resolved (both sound); the counter-embedding extension was scoped but is not yet implemented,
with one open sub-decision (live QR delivery) resolved by the user mid-session and one (on-chain
scope) still pending.

**Details:** Reviewed Setup/KeyGen/Encrypt/Decrypt (§4), the decisional-BDH security reduction
and its "artificial abort" step (§5), the HIBE extension and its reduction-efficiency caveat
(§6), and the generic IBE→signature transform reduced to CDH (§7). Confirmed ORBIT's
`(sk1,sk2,sk3)` is a Type-3-pairing adaptation of the paper's 2-element `(σ1,σ2)`: the single
`g^r` term splits into a G1 copy (`sk2`) and a G2 copy (`sk3=g2^r`) since BN254 has no efficient
G1↔G2 isomorphism, adding a consistency check `e(g,sk3)==e(sk2,g2)` alongside the paper's
original Waters verification equation. Confirmed the paper's identity term `u′·∏_{i∈V}u_i`
(bit-decomposable, independent per-bit generators) is what `h_of_id`/`garble_waters` (server
Rust) implement, and is structurally required for the per-bit OT/garbling trick
(`garble_waters`, `generate_gs`) that makes offline `RDelegate` possible at all — the integer
form `u′·g1^v` used by `water_unlock_solidity`/`hashlockMatches` would not decompose this way,
which is the root of the already-documented tag-encoding-mismatch bug (`CLAUDE.md`, "Known
remaining gap").

Worked through, algebraically, whether splitting `u′·∏u_i` into disjoint `uid`/`denomination`
sub-ranges (`u′·∏_{i∈uid}u_i^{m_i}·∏_{j∈denom}u_j^{d_j}`) changes security or correctness: it
does not — the split term is the identical group element as the flat form (multiplication in G
is commutative/associative), so Theorem 1's reduction and Decrypt's correctness both carry over
unchanged, provided (a) generator index ranges never overlap between fields and (b) the
`(uid,denom)`→bitstring encoding is injective (satisfied by the existing fixed-width
zero-padded format). Noted the split does not grant independent per-field re-derivability (a
key for one denomination doesn't yield a key for another without a fresh `Unlock`) short of a
genuine HIBE construction, which §6 notes has an inefficient reduction beyond small numbers of
levels.

Extended the discussion to the per-coin counter (`coinIndex`, the `CCC` segment of the
`UUU_DDD_CCC` tile tag, previously confirmed purely cosmetic/client-side — see
`denomination-and-identity-qr-review.md`). Scoped what it would take to embed this into the
cryptographic tag used by `computeGsAk2()`/`evaluate_gs()`: identity length grows from 56 bits
(`UUU_DDD`) to 88 bits (`UUU_DDD_CCC`), requiring more GS bit-slots and a higher attested
`nusecount` (currently 64) across server, Rust, and Android. Identified that Alice needs Bob's
live per-denomination counter fully offline, before her GS evaluation — which the current
cached, static "My ID" QR (`{"uid":N}`) cannot supply — and that this could allow two senders
who scan the same displayed QR before Bob's counter advances to independently derive Waters
keys for an identical `(uid,denom,counter)` tag. Also raised whether Bob could manipulate his
own local counter (it lives in unauthenticated client-side `SharedPreferences`, clearable via
account delete/recreate, with no in-UI edit control, per prior research this session).

Decisions made by the user: (1) "My ID" should regenerate its QR live each time it's shown,
embedding `{"uid":N,"counters":{denom:count,...}}` read fresh from
`orbit_coin_counters_$account` at render time, rather than displaying a cached QR — resolving
the offline-delivery problem for the counter-embedding idea. (2) Bob manipulating his own
counter was judged not a real security issue, reasoning that Waters' unforgeability notion
concerns unauthorized parties forging a signature for an identity, not the honesty of a user's
self-chosen identity label — Bob duplicating his own tag by resetting his own counter cannot
forge another user's key or claim another user's funds, only produce confusing/duplicate
cosmetic tags within his own wallet, as long as the counter stays confined to the offline
GS/RDelegate derivation.

**Why:** The bit-decomposable identity term is what the entire ORBIT re-delegation mechanism is
built on — any tag redesign is safe exactly to the extent that it preserves that decomposability
and stays within a flat (non-hierarchical) identity space with disjoint, injectively-encoded
fields. The counter-embedding idea's real obstacle is not cryptographic (the algebra is sound)
but architectural: ORBIT's RDelegate is designed to be fully offline (no bank/server contact),
and a mutable, receiver-local counter embedded in the tag reintroduces a freshness/liveness
requirement that a static QR cannot satisfy.

**Implication:** The uid/denomination field-split is validated and safe to implement whenever
the tag-encoding-mismatch bug is fixed (both changes touch the same
`h_of_id`/`garble_waters`/`water_unlock_solidity`/`hashlockMatches` code paths, so doing them
together is likely cheaper than sequencing them). The counter-embedding extension is scoped but
still has one open question before implementation should start: whether the embedded counter
should ever be checked on-chain (via `hashlockMatches`) or stay confined to the offline GS
circuit derivation only — leaning toward offline-only, since that also sidesteps the existing
tag-encoding-mismatch bug (the on-chain path already ignores user-submitted `sk1/sk2/sk3` in
favor of its own denomination-only derivation). This question, plus the concrete
`nusecount`/GS-bit-slot expansion work, should be resolved/scoped in a follow-up session before
touching `garble_waters`, `generate_gs`, `computeGsAk2`, or the Android "My ID" flow.

## 2026-09-28 — On-chain vs. offline-only scope for the embedded coin counter

**Attempt:** Compared the two remaining options for the per-recipient coin-counter tag
extension (see entry above): keeping the embedded counter confined to the offline GS/RDelegate
derivation only, versus extending on-chain verification (`hashlockMatches` in
`zfairexchange.sol`) to check it as well.

**Result:** Success — decided in favor of offline-only, closing the last open sub-question from
the prior entry.

**Details:** Enumerated concrete tradeoffs for each option.

*Offline-only*: no Solidity/contract changes or Sepolia redeploy; sidesteps the
tag-encoding-mismatch bug entirely since `/api/pay` already substitutes its own
denomination-only derived key rather than checking the user-submitted `(sk1,sk2,sk3)`; no added
gas cost to `hashlockMatches`'s bit-decomposition loop; keeps the on-chain-checked identity
space the same size it is today. Against it: the cryptographic binding remains informal —
nothing (server or contract) ever actually verifies that a submitted key matches its claimed
`(uid,denom,counter)`, so a tag collision (e.g. from the Bob-resets-his-own-counter scenario,
entry above) stays invisible to the whole system rather than merely tolerated.

*On-chain*: would give real enforcement — a mismatched key gets rejected by the contract — and
would force a fix to the pre-existing tag-encoding-mismatch bug (`h_of_id`'s bitwise/string form
vs. `water_unlock_solidity`/`hashlockMatches`'s integer form) as a side effect. Against it:
requires fixing that bug first (cross-cutting across Rust, Solidity, and Android); roughly
doubles the identity bit-width checked in `hashlockMatches`'s loop (56→88+ bits), which scales
gas cost with bit-width rather than with how many bits are actually set; does not even achieve
real collision-prevention by itself, since `hashlockMatches` only checks a key against the one
HTLC contract instance that stores it, not a global registry — two independently-locked HTLCs
under the same nominal tag would still go undetected without a much larger nullifier-style
registry feature; and it reintroduces a server dependency on client-asserted `(uid, counter)`
state for `/api/pay` to compute the matching key, which conflicts with the counter being
locally-resettable, unauthenticated client state (see the Bob-manipulation consideration
above). Additionally, `CLAUDE_replace_HTLC.md` is already exploring replacing
`zfairexchange.sol`'s hashlock mechanism with an adaptor-signature/verifiable-encryption scheme,
so extending `hashlockMatches` now risks investing Solidity effort into a component that may be
replaced.

**Why:** The on-chain option's main advantage — real enforcement — does not actually
materialize from the scoped change alone; genuine collision-prevention needs a nullifier-style
registry, a substantially larger feature than extending the bit-decomposition, while its costs
(bug-fix prerequisite, gas, server-trust reintroduction, risk of building on a component slated
for replacement) are concrete and immediate. The offline-only option keeps the addition inside
the same client-bookkeeping layer the coin counter already lives in, consistent with the paper's
own scope — multi-denomination support is explicitly left to future work in the base
construction (`ORBIT_PAPER.md`), so ORBIT's denomination-as-tag mechanism is already an informal
extension beyond the paper; adding a third semantic field on-chain would compound that rather
than keep it isolated to the offline layer.

**Implication:** The per-recipient counter, if implemented, stays confined to the offline
GS/RDelegate derivation (`computeGsAk2`/`evaluate_gs`) and is never checked by
`zfairexchange.sol`. The counter-embedding feature is now fully scoped end-to-end (nusecount
expansion, live "My ID" QR, offline-only trust boundary) and ready for implementation planning
whenever picked up, without needing to touch the smart contract or wait on the
tag-encoding-mismatch bug fix.

## 2026-09-28 — Implemented the per-recipient coin counter in the GS tag

**Attempt:** Implemented the counter-embedding extension scoped in the two entries above:
widened the GS evaluation tag from `UUU_DDD` (56 bits) to `UUU_DDD_CCC` (88 bits) across the
server and Android app, following the offline-only decision.

**Result:** Success. Read the actual source (server `rustcode/src/lib.rs`, `server.py`,
`MainActivity.kt`, `PaymentBoxAdapter.kt`, the Android JNI `pbcrypto.rs`) before changing
anything, which overturned one assumption from the scoping entries above: `generate_gs()` and
`evaluate_gs()` were already fully parameterized by tag-bit-count (`tag_bits` argument /
tag-string byte length respectively) rather than hardcoding 56, so no Rust code changed at all
on either side — the entire implementation was caller-side constant/format-string changes plus
one new piece of client bookkeeping.

**Details:** `server.py`: `_GS_TAG_BITS` 56→88; added `_GS_NUSECOUNT=96` (94 needed: 5 GWat + 1
GS branch + 88 GS bits, +2 spare, following the existing convention that gave the old 62-op
total 2 spare at 64) and replaced every hardcoded `64` tied to this meaning — the two
`getpresig`-family nusecount asserts, the GS-generation trigger condition, `/api/replenish`'s
`expected_nusecount = 64 * total_count`, and `verify_attestation`'s keycount allowlist (added
96 to the explicit set, changed the batch-multiple check from `% 64` to `% 96`). Verified live
against the running `rustcode` extension (no rebuild needed) that `generate_gs` produces
correctly-shaped 88-slot output and that `h_vec` has 256 generators — comfortably enough for
index 87, so no params regeneration was needed either, resolving the "does h_vec have enough
capacity" open question from the pre-compaction implementation checklist.

`MainActivity.kt`: `gsRedelegateLauncher`'s `BobIdentity` data class gained a `counters: Map<String,
Double>?` field (Gson decodes JSON numbers as Double); `bobTag` is now
`"%03d_%03d_%03d".format(bobId.uid, card.denomination, bobCounter)` where `bobCounter =
bobId.counters?.get(denom.toString())?.toInt() ?: 0`; the outgoing re-delegation QR gained a
`"counter"` field carrying that same value. "My ID" now builds `{"uid":N,"counters":
${Gson().toJson(loadCoinCounters())}}` freshly on every tap in both the already-registered and
newly-registered branches, satisfying the "live, not cached" decision from the first entry
above purely by reading `loadCoinCounters()` (a SharedPreferences read) at click-time rather
than reusing any stored/remembered QR bitmap. `addCardFromQR()`'s `WatersKey` data class gained
an optional `counter: Int?`; when present, a new `recordReceivedCounter(denomination, counter)`
records that exact value as the card's `coinIndex` and advances the local
`orbit_coin_counters_$account[denomination]` to `max(current, counter+1)` — deliberately
*not* calling the existing `nextCoinIndex()`, since that would derive a value independent of
what the sender actually embedded in the cryptographic tag, breaking the invariant that the
tile's displayed `CCC` matches the identity the received Waters key verifies against. Legacy
scans without a `counter` field (manual QR paste, old-format re-delegate) fall through to the
original `nextCoinIndex()` self-assignment unchanged. `PaymentBoxAdapter.issueCard()` and
`MainActivity.performSync()`'s mint-time nusecount requests bumped `64`→`96`.

Updated `CLAUDE.md` (new "Per-recipient coin counter cryptographically embedded in the GS tag"
subsection, plus touch-ups to the GS Circuit structure/size numbers, the Demo Flow steps, and
the Actions/UI-Layout bullets) and `CLAUDE_Waters.md` (marked the design section
"IMPLEMENTED", appended an implementation summary) to reflect the new state, rather than
leaving them describing the superseded 56-bit/cosmetic-only design.

**Why:** The two prior entries had scoped this as if it might require touching
`garble_waters`/`generate_gs`'s cryptographic core and `computeGsAk2`/`evaluate_gs`'s ECDH-loop
logic — reading the real implementation showed both were already written generically against a
runtime-supplied bit count, a design choice apparently made when the original 56-bit GS circuit
was first implemented (independent of this session's work) that this extension simply
benefited from. The actual complexity was entirely in the *bookkeeping layer* the design
discussion had already fully resolved: getting Bob's live counter to Alice offline (My ID QR),
and getting the coin's recorded `coinIndex` back in sync with what the key was actually derived
against (the new `recordReceivedCounter()` vs. the pre-existing `nextCoinIndex()`).

**Implication:** The per-recipient coin counter is now a real cryptographic property of
GS-redelegated coins, not just a display convenience, closing the gap between the `UUU_DDD_CCC`
tile label and the Waters identity actually used. Confirmed this is orthogonal to the
pre-existing tag-encoding-mismatch bug (`CLAUDE.md`, "Known remaining gap"): neither
`garble_waters` nor `generate_gs` ever called `h_of_id`, so the 56→88 bit extension neither
fixes nor worsens that bug, which remains confined to `water_encrypt`/`water_unlock_solidity`/
`hashlockMatches`. Three items from the pre-implementation checklist were deliberately left
unaddressed and are now documented as known limitations in `CLAUDE.md` rather than resolved:
legacy GS circuits minted under the 56-bit scheme are silently incompatible (no versioning or
migration added — treated the same as this codebase's prior precedent of requiring re-mint
after a breaking change, e.g. the multi-account migration); the two-sender race condition
remains accepted-but-undecided, unchanged from the prior entry; and there is still no automated
test exercising the actual `generate_gs`/`evaluate_gs` pipeline (`test_redelegate_full()`
exercises the separate, unused Option-B `garble_redelegate` path instead) — a gap that predates
this change and was not introduced by it, but was not closed either.

## 2026-09-28 — First live re-delegation attempt surfaces legacy-circuit incompatibility

**Attempt:** After implementing the 88-bit GS tag extension (entry above), attempted a live
device-to-device re-delegation using the updated app and server.

**Result:** Failure on the first try, root-caused and resolved without further code changes.
The app crashed with `toIndex (3795) is greater than size (3729)` inside `computeGsAk2()`'s
`gsEpkBytes.sliceArray(...)` call.

**Details:** The arithmetic identified the exact cause: `3729 / 33 = 113` — the stored
`gs_circuit`'s epk array held exactly `1 + 56×2` keys, the old pre-extension slot count. The
crash occurred requesting `epkIdx = 114` (`toIndex 3795 = 115×33`), which resolves to
`1 + 2×56 + 1` — the first bit-slot past the old 56-bit boundary, i.e. the first bit of the new
`_CCC` suffix. This confirmed the card being re-delegated was minted under the old scheme, not
that the server or client code itself was broken. Checked whether the running Flask server
process (PID 5874) predated the `server.py` edit by comparing process start time (`20:18:19`)
against the file's mtime (`18:08:35`) — the server had already been restarted after the edit
and was serving the new 88-bit/nusecount=96 scheme correctly. The stale card was therefore
minted either before that restart, or before the Android app was rebuilt with the updated
Kotlin (`bobTag` construction, nusecount=96 request) — its `gs_circuit` field is fixed at mint
time and cannot retroactively pick up the new scheme. Resolution: rebuild/reinstall the Android
app, discard the stale card (long-press → delete), and mint a fresh one against the
already-updated server.

**Why:** `evaluate_gs()`/`computeGsAk2()` derive their expected bit count from the *tag string*
being evaluated, not from the circuit itself — by design, so the same code works at any tag
width (see the implementation entry above). This means a size mismatch between an old-format
circuit and a new-format tag isn't caught until the ECDH loop actually runs past the old
circuit's slot count, producing an out-of-bounds array crash rather than a clean, early error.
This is exactly the "Legacy cards" limitation already flagged as a known, unaddressed
limitation when the feature was implemented — this was the first time it was actually observed
end-to-end rather than reasoned about in the abstract.

**Implication:** Confirms no versioning/migration mechanism exists for `gs_circuit` — any
dormant or live card minted before both the server restart and the app rebuild is permanently
incompatible with re-delegation and must be discarded and re-minted, not just re-synced. Worth
noting for future breaking changes to the GS/GWat circuit shape: since `evaluate_gs` fails
loudly (array index crash) rather than silently, this class of legacy-format mismatch is at
least always detectable, just not automatically recoverable. No code change was made as a
result of this entry — the fix was operational (rebuild + re-mint), not a bug in the new
scheme itself.

## 2026-09-28 — Clarifying which denomination Bob's "My ID" QR applies to

**Attempt:** Answered a question about the counter-embedding feature (entry above): when Bob
shows his "My ID" QR before receiving a re-delegated coin, which denomination is he requesting?

**Result:** Clarified the existing design — Bob's QR was never denomination-specific, and this
extension didn't change that. Not yet empirically verified end-to-end.

**Details:** Bob's identity QR is built as `{"uid":N,"counters":${Gson().toJson(loadCoinCounters())}}`,
where `loadCoinCounters()` returns his *entire* per-denomination counter map (e.g.
`{"1":0,"2":3}` for every denomination he has touched before), not a value tied to one
denomination he has selected. Bob is not requesting anything in this QR — it is a static
snapshot of "here is my identity, and my next slot for every denomination I have seen so far."
The denomination of the actual transfer is chosen entirely on Alice's side: she selects which
card (which already carries its own fixed `card.denomination`) to tap "Re-delegate" on, scans
Bob's QR, and extracts only the one counters-map entry relevant to that card:
`bobId.counters?.get(card.denomination.toString())?.toInt() ?: 0`. If Bob's map has no entry
for that denomination — he has never minted or received one before — the lookup defaults to
`0`, his first coin of that kind. This preserves the pre-existing "denomination is the sender's
concern" design already noted in the `btnBarMyId` click-listener comment in `MainActivity.kt`;
the counter-embedding extension changed what gets embedded once the denomination is decided,
not who decides it.

**Why:** The design intentionally keeps identity (uid + counters snapshot) and transaction
parameters (denomination, amount) on separate sides of the protocol — Bob broadcasts a
denomination-agnostic identity once, and each sender independently decides what to send against
it, consistent with how `card.denomination` already drove the (pre-extension) `bobTag`
construction before this session's changes.

**Implication:** The multi-denomination counters map and the default-to-`0` fallback path (a
denomination Bob has never touched before) have not been exercised in a real device-to-device
scan as of this entry — only single-denomination re-delegation has been tested live so far (see
the legacy-circuit entry above, same session). Worth an explicit test pass: register Bob's
identity, re-delegate a denomination he has never seen before, and confirm both sides agree the
resulting card's `coinIndex` is `0` before treating this path as verified.

## 2026-10-01 — Limitation: small enumerable tag space makes (uid,denom,counter) brute-forceable from a submitted key

**Attempt:** In response to a user question about where exactly `(uid, denomination, counter)`
get hardcoded into the Waters signature, re-examined whether embedding them as plaintext digits
in the GS tag string creates a privacy/linkability risk beyond the on-chain scope already
decided (offline-only, see the two entries above).

**Result:** Identified a genuine, previously unconsidered privacy limitation. Not yet mitigated
— logged here to return to later.

**Details:** The tag string is constructed in `MainActivity.kt`'s `gsRedelegateLauncher`:
```kotlin
val bobCounter = bobId.counters?.get(card.denomination.toString())?.toInt() ?: 0
val bobTag = "%03d_%03d_%03d".format(bobId.uid, card.denomination, bobCounter)
```
and cryptographically bound into `dk1`/`sk1` inside `evaluate_gs()`
(`paymentbox_otp/app/rust/src/paymentbox/pbcrypto.rs:572-614`), via the per-bit accumulation
loop at lines 586-604. The resulting `(sk1,sk2,sk3)` therefore encodes `(uid,denom,counter)`
through the Waters verification equation `e(g^α,g2^β)·e(H(tag),sk3) == e(sk1,g2)`.

The identity space this tag draws from is small and fully enumerable: roughly 1000 uids × 7
denominations × 1000 counters ≈ 7×10^6 combinations. `/api/pay`'s request body is `{sk1, sk2,
sk3, contract_id, denomination}` — the server receives `sk1/sk2/sk3` as plain fields on every
withdrawal request, independent of whether it currently uses them for the on-chain call (it
currently does not, due to the pre-existing tag-encoding-mismatch bug documented in
`CLAUDE.md`). Anyone holding a copy of a submitted `(sk1,sk2,sk3)` — the server via the request
body or logs, or any other party who obtains it — can brute-force the full ~7M-candidate space
offline by computing `H(tag)` per guess and checking the verification equation: one scalar
multiplication and one pairing comparison per candidate, trivially fast with no cryptographic
hardness protecting against it. A successful guess reveals exactly which `(uid, denom, counter)`
triple the key was derived for — i.e. the recipient's identity and precisely which numbered coin
was redeemed.

Distinguished this from the already-decided offline-only scope (see the two entries above): that
decision was about whether the *contract* (`hashlockMatches`) enforces the embedded counter.
This finding is about *passive extractability* of the tag from a key the server already
receives, regardless of enforcement and regardless of whether the tag-encoding-mismatch bug is
ever fixed. It does not reveal Alice's (the sender's) identity directly, since her uid is never
embedded in `bobTag` — only Bob's (the recipient's) identity and coin serial number are exposed.
However, since the GS/offline re-delegation path withdraws from Alice's *original* `contract_id`
(no new HTLC is created — see "Demo flow: offline re-delegation" in `CLAUDE.md`), and that
`contract_id`'s creation is itself public on Sepolia (Alice calls `newContract` from her own
address), a party able to brute-force the tag could combine the two and link "Alice's locked
contract" to "Bob's Nth coin of denomination D" — a linkability channel that did not exist
before this feature, since the base scheme's redeemed key previously carried no recipient
identity information at all.

**Why:** Waters' unforgeability guarantee protects against forging a signature for a *chosen*
identity; it says nothing about hiding which identity a given valid signature was issued under
when the identity space is small enough to enumerate. Embedding small sequential integers
(`uid`, `counter` both bounded under 1000) as the cryptographic identity, rather than a
high-entropy value, trades away whatever implicit identity-hiding existed when the tag was
effectively only "denomination" (7 possible values, already small, but revealing only the coin's
denomination rather than its specific recipient and serial number).

**Implication:** This does not break one-timeness or unforgeability (the paper's core security
properties), but it does degrade the base scheme's informal unlinkability beyond what the
offline-only scope decision accounted for. Two mitigation directions were discussed, neither
implemented: (a) keep the small counter for UI display only, but bind the cryptographic tag to a
separate high-entropy (e.g. 128-bit random) per-coin nonce instead, carried alongside the
display counter in the QR; (b) accept and document this as a known limitation of the research
prototype, on the grounds that the base ORBIT construction does not formally claim identity
privacy for denomination/recipient metadata it doesn't natively support (multi-denomination is
already explicitly out of scope for the paper's base construction, per `ORBIT_PAPER.md`). Left
open, to be revisited; no code changed as a result of this entry.

## 2026-10-02 — Re-check against the supervisor's concern: the coin counter does not prevent denomination forgery

**Attempt:** Re-examined the `UUU_DDD_CCC` coin-counter extension (entries above) against the
problem the supervisor originally raised: a holder can manipulate the denomination field `DDD`
of the tag and so redeem more than the sender actually locked. Checked whether the counter
extension addresses this, and read the server's `/api/pay` and `/api/redelegate` handlers
(`server/server.py`) to confirm the server-side behaviour directly from code.

**Result:** Failure, in the sense that the counter extension does not address the concern at
all. The denomination remains forgeable at the circuit level, and two live server-side holes
were confirmed in code. No code was changed.

**Details:** *Circuit level.* `generate_gs()` (`server/rustcode/src/lib.rs`) builds its base key
as `base_dk1 = msk + u′·r` and then, for every bit `i ∈ [0, tag_bits)`, emits one ciphertext
for bit value 0 and one for bit value 1, with `delta_i = h_vec[i]·r`. Every one of the 88 tag
bits, including the 24 denomination bits (bytes 4–6 of `"UUU_DDD_CCC"`) and the two separator
bytes, is therefore a free 1-of-2 choice for whoever evaluates the GS circuit. A free choice is
correct for the recipient fields `UUU` and `CCC`, which are unknown at mint time. It is
incorrect for `DDD`, which is fixed and paid for at mint time. The counter extension added 32
further free bits and left `DDD` unchanged. In the current flow the GS evaluator is the sender
(Alice), since the recipient receives a finished key and an empty `gs_circuit`. In a
paper-correct chain every hop would hold a circuit. This forgery is not exploitable today only
because of the separate tag-encoding-mismatch bug: no GS-derived key ever reaches the chain.
Fixing that bug without also fixing this one would make the forgery live.

*Server level (live).* `/api/redelegate` reads `denomination` from the POST body. If
`contract_id` is empty it skips withdrawing the sender's HTLC. If the withdrawal raises, it
logs `[WARN] Could not withdraw Alice's HTLC` and continues. Either way it then calls
`newContract(..., cfg["hashlock"], timelock)` with `value = _DENOM_ETH[denomination]`. A
request `{contract_id: "", denomination: 100}` therefore mints a 100C HTLC backed by nothing.
`/api/pay` also reads `denomination` from the body and substitutes a server-derived key,
`water_unlock_solidity(water_parameter, denomination)`, ignoring the client's
`(sk1, sk2, sk3)`. The contract's hashlock check bounds this: a wrong denomination makes
`withdraw()` revert, so `/api/pay` alone cannot inflate a coin. It does, however, let anyone who
knows a `contract_id` (public on Sepolia) and its denomination withdraw it without holding any
key. In the current demo all HTLCs name the server's own address as recipient, so ETH does not
leave the server wallet. The flaw appears as unbacked coin value and becomes theft once payouts
go to the holder.

**Why:** The GS construction treats the tag as a single uniform bitstring and makes no
distinction between bits fixed by the issuer and bits chosen by the delegator. The
denomination was bolted onto the tag (the base construction supports one fixed value per key,
per `ORBIT_PAPER.md`, §2.4) without the issuer committing those bits. On the server, the
demo shortcut of deriving keys from `beta_secret` and trusting client-supplied parameters
bypasses the cryptographic binding entirely.

**Implication:** The counter extension answers "which coin is this", not "can the denomination
be forged". Three fixes are required, none implemented:
(1) Bind the fixed bits in the circuit. At mint time the issuer knows `DDD` and the separators,
so `generate_gs` should compute `base_dk1 = msk + (u′ + Σ_{fixed bits = 1} u_j)·r` and emit
1-of-2 slots only for the free fields `UUU` and `CCC`. `evaluate_gs`/`computeGsAk2` must skip
the fixed positions. This reduces the free bits to 48, so the budget becomes 5 + 1 + 48 = 54
uses and fits back under `nusecount = 64`. The paper's own suggested alternative, a separate
Waters key per denomination (`pk1`, `pk5`, ...), binds the denomination to the master secret
rather than to tag bits; it is cleaner but a larger change.
(2) Stop trusting client-supplied parameters on the server: read the denomination from the
contract itself, refuse an empty `contract_id`, abort `/api/redelegate` when withdrawing the old
HTLC fails, or remove `/api/redelegate` entirely, since the GS path does not need it.
(3) Fix the tag-encoding mismatch so `/api/pay` verifies the submitted key instead of deriving
its own. Without it, fix (1) cannot be verified on-chain.

## 2026-10-02 — Wider flaw audit: re-delegation one-timeness, HTLC state, activation gating, and a reproduced double withdrawal

**Attempt:** Following the denomination-forgery re-check (entry above), audited the remaining
code paths for further flaws: the GS circuit construction (`generate_gs()`,
`server/rustcode/src/lib.rs`), the HTLC contract (`server/zfairexchange.sol`), the activation
path, attestation verification, and the Android Withdraw flow (`MainActivity.kt`,
`btnBarPay` click listener). The user additionally reported a reproducible double withdrawal
from the app, which was traced to its cause.

**Result:** Failure. Eight further flaws were confirmed in code, two of them critical. The
user's double-withdrawal report is an end-to-end reproduction of the contract-state bug. No
code was changed.

**Details:**

1. *Re-delegation one-timeness is broken (critical).* `generate_gs()` encrypts the identity
   element `G::zero()` into every bit-0 slot (`lib.rs:556-566`) and the unmasked value
   `delta_i = h_vec[i]·r` into every bit-1 slot (`lib.rs:562-567`). A bit-0 slot therefore
   carries no information, and a bit-1 slot reveals `u_i^r` directly. A modified client can skip
   all bit-0 slots and decrypt the branch slot plus all 88 bit-1 slots: 89 ECDH uses, within the
   attested `nusecount = 96`. This yields `base_dk1` and every `u_i^r`, from which a valid
   `dk1 = base_dk1 + Σ_{i∈V} u_i^r` follows for every tag `V`: any recipient, any counter, any
   denomination, without limit. The paper prevents this with a multiplicative secret sharing of
   the per-bit shares (`t'_0 · Π t'_i = 1`) and an all-or-nothing layer (per-bit XOR shares `a_i`
   of a key `a`); neither is implemented. This also defeats the "bake the fixed bits into the
   base key" fix proposed in the entry above, since the free `UUU`/`CCC` bits remain fully
   extractable. All recipients except the first to withdraw on-chain are cheated.

2. *HTLC state is never persisted (critical, contract bug).* `withdraw()` and `refund()` load the
   contract with `LockContract memory c = contracts[_contractId]` (`zfairexchange.sol:349`,
   `:373`) and set `c.withdrawn`, `c.refunded` and `c.preimage` on that memory copy. Storage is
   never updated (only `newContract()` uses `storage`, line 301). Consequences: the receiver can
   call `withdraw()` on one contract repeatedly and drain the whole contract balance, including
   other senders' locked ETH; the sender can `refund()` after a withdrawal, and repeatedly; the
   revealed preimage is never stored, so `getContract()` cannot return the activation key the
   paper's purchase flow (step 4) relies on. Fix: `LockContract storage c`.

3. *Double withdrawal reproduced from the app (critical, compound).* Reported by the user: after
   a successful Withdraw, dismissing the success dialog by any means other than "OK" (back
   button, tap outside) leaves the card in the wallet, and it can be withdrawn again. Cause in
   code: the "Payment verified" `AlertDialog` is cancelable (default), and the card is removed
   only inside its `setPositiveButton("OK")` handler. The repeated `/api/pay` then succeeds
   on-chain only because of flaw 2: `withdrawn` is never persisted, so `hashlockMatches` and
   `withdrawable` both pass again and the contract pays `c.amount` from its pooled balance. With
   flaw 2 fixed the second call would revert with "already withdrawn"; with the UI fixed the
   card would be gone. Either fix alone stops this reproduction, but flaw 2 remains exploitable
   directly against `/api/pay` regardless of the UI. UI fix: remove the card as soon as the
   withdrawal succeeds (before showing the dialog), or make the dialog non-cancelable.

4. *Activation no longer requires the bank (high, design deviation).* The August 2026
   `beta_secret` fix removed the Waters-IBE layer from the activation circuit; `GWat` now
   decrypts with ECDH shares alone (no `water_decrypt`, no `ak`, in `evaluate_paymentbox`).
   `performSync()` therefore recovers usable `(sk1, sk2, sk3)` for "dormant" coins at sync time.
   The dormant/live distinction is bookkeeping only (whether ETH is locked on Sepolia); the
   paper's guarantee that a `dmk` is useless until `Unlock` releases `ak` after payment no longer
   holds. Combined with flaw 1, an unpaid dormant coin's GS circuit can be re-delegated offline.

5. *Hashlock shared across all contracts of a denomination (high, latent).* Every contract of
   denomination `D` has `hashlock = D`, and keys are not bound to a `contract_id`. Once
   `/api/pay` verifies user-submitted keys (tag-encoding fix), one valid key for `D` withdraws
   every contract of denomination `D`, and that key becomes public in `withdraw()` calldata at
   the first redemption. The paper avoids this with a fresh random tag per `Delegate`. It is
   masked today only because the server is the sole receiver of every contract.

6. *Hardware one-timeness not guaranteed (medium).* `rootcert.pem` trusts the Android Keystore
   *software* attestation root, and `verify_attestation()` does not check the attested security
   level (its own comment calls the check incomplete). A rooted or emulated device can satisfy
   `nusecount` without hardware enforcement, and every one-timeness argument rests on it.

7. *Sender can withdraw before the recipient (medium).* `/api/pay` requires only `contract_id`
   and `denomination`, so after re-delegating, the sender, or anyone who learns the
   `contract_id` (public on Sepolia), can withdraw first. Only the honest app deleting the card
   prevents this.

8. *Keys from one GS circuit are linkable (low).* All keys derived from the same circuit share
   `sk2 = g^r` and `sk3 = g2^r`.

**Why:** The implementation simplified the paper's construction in three load-bearing places
without replacing the properties they provided: the GS circuit dropped masking and the
all-or-nothing layer (flaw 1), activation dropped the IBE gate (flaw 4), and the tag was reduced
to the denomination (flaw 5). Separately, the contract has an implementation bug unrelated to
the cryptography (flaw 2), and the app's cleanup depends on a single dialog button (flaw 3).

**Implication:** The demo proves that the Waters/GS arithmetic and on-chain pairing verification
work, but not the paper's security properties. One-timeness (Def. 4.3) currently holds neither
cryptographically (flaw 1) nor on-chain (flaw 2). Suggested order of fixes: flaw 2 (one word,
and it stops real loss of ETH), flaw 3 (app cleanup), then flaw 1 (masks + all-or-nothing in
`generate_gs`/`evaluate_gs`), then the server-trust and denomination fixes from the entry above.
Flaws 4 and 5 need design decisions (restoring an `ak` gate; per-coin random tags) rather than
local patches, and should be stated as limitations if not addressed.

## 2026-10-02 — Correction: missing masking does not defeat the fixed-denomination fix

**Attempt:** While reviewing a draft email to the supervisor describing the proposed
denomination fix, re-examined a claim made in the "Wider flaw audit" entry above (flaw 1): that
the missing masking in `generate_gs()` "defeats" the fix of baking the fixed bits into the base
key.

**Result:** The earlier claim was overstated and is corrected here. The fixed-denomination fix
does prevent denomination forgery, even with the current unmasked slots. The masking flaw remains
real, but it affects a different property. Also confirmed that neither proposed fix has been
implemented: `generate_gs()` (`server/rustcode/src/lib.rs:533-568`) still uses
`base_dk1 = msk + u′·r` with slots for all 88 bits, and `/api/pay` (`server/server.py:529`) still
reads `denomination` from the request body.

**Details:** Under the fix, the denomination and separator bits are folded into the base,
`base_dk1 = msk + (u′ + Σ_{fixed bits = 1} u_j)·r`, and the circuit emits 1-of-2 slots only for
the `UUU` and `CCC` positions. The evaluator then holds `base_dk1`, `dk2 = g^r`, `dk3 = g2^r`,
and at most `u_i^r` for the free positions. Changing a denomination bit requires adding or
removing `u_j^r` for a fixed position `j`, for which no slot exists. Computing `u_j^r` from the
public `u_j` and `g^r` (or `g2^r`) is an instance of the computational Diffie-Hellman problem,
which is the assumption Waters' signature unforgeability already rests on (§7.2). The
denomination is therefore unforgeable under the fix, independently of masking.

What the missing masks and all-or-nothing layer still allow is extraction of every `u_i^r` for
the free positions, so the evaluator can derive keys for any combination of recipient and
counter bits. That breaks re-delegation one-timeness (one coin to many recipients), not
denomination integrity.

The server half of the fix also needs one addition beyond reading the denomination from the
on-chain contract: `/api/redelegate` with an empty `contract_id` has no contract to read and
still mints a fresh HTLC for a client-chosen denomination, so it must reject an empty
`contract_id` and abort when withdrawing the old HTLC fails (or be removed, since the GS path
does not use it).

**Why:** The earlier entry conflated two properties of the same circuit: which bits the evaluator
can choose (denomination integrity) and how many tags the evaluator can evaluate (one-timeness).
Baking bits into the base removes choice over those bits, while masking and all-or-nothing limit
the number of evaluations. They are independent fixes for independent problems.

**Implication:** The proposed denomination fix is sound and can be presented as such, but as a
proposal, since it is not yet implemented. The masking/all-or-nothing gap should be presented
separately as a one-timeness issue, not as a weakness of the denomination fix. Flaw 1 of the
"Wider flaw audit" entry should be read with this correction.

## 2026-10-05 — Fixes for the three critical flaws: HTLC state, card consumption, GS masking and all-or-nothing

**Attempt:** Implemented fixes for flaws 1–3 of the 2026-10-02 "Wider flaw audit" entry: the
`memory`/`storage` bug in `zfairexchange.sol`, card removal depending on a dialog button, and
the missing masking and all-or-nothing layers in the GS re-delegation circuit.

**Result:** Partial. All three are fixed in code. The contract and the GS circuit pass new
automated tests. The contract is not redeployed, and the app changes have not been built or run
on a device.

**Details:**

1. *Contract.* `withdraw()` and `refund()` now load `LockContract storage c`
   (`server/zfairexchange.sol`). New regression test `server/test_htlc_state.py` deploys the
   contract on an in-memory py-evm chain (`eth-tester`) with real Waters parameters and a valid
   key from `water_unlock_solidity`. Run against the previous source (git `HEAD`), the second
   `withdraw()` on the same contract succeeds and pays out of the other contract's locked
   balance, `withdrawn` and `preimage` are not stored, and `refund()` fails. Run against the
   fixed source, all nine checks pass: a second `withdraw()` reverts with "already withdrawn",
   `refund()` after a withdrawal reverts with "already withdrawn", a second `refund()` reverts
   with "already refunded", and the pool is not drained. `HTLC_ADDRESS` in `server.py` still
   points to the old deployment.

2. *App.* A new `consumeCard(card)` in `MainActivity.kt` removes the card by reference, resets
   the selection and calls `PersistencyManager.save()` immediately. It runs as soon as a spend
   succeeds, before any result dialog, at all three spend sites: Withdraw, GS re-delegate and
   legacy re-delegate. Previously, removal happened only in the dialog's positive-button
   handler, and was persisted only in `onPause()`. So dismissing the dialog, or killing the app
   while the re-delegation QR was on screen, kept the card.

3. *GS circuit.* `generate_gs` was replaced by `generate_gs_core`, reached through a new
   `garble_waters_with_gs` that garbles GWat and GS together (`server/rustcode/src/lib.rs`):
   - **Masking.** Random G1 shares `s_1..s_88` with `s_0 = −Σ s_i`. Slot `(i,0)` holds `s_i`,
     slot `(i,1)` holds `u_i·r + s_i`, and the base holds `msk + u′·r + s_0`. This is the
     paper's multiplicative sharing `t′_0·∏t′_i = 1`, in additive notation.
   - **All-or-nothing.** `a = H(link) ⊕ a_0 ⊕ a_1 ⊕ … ⊕ a_88`. The branch slot carries `a_0`.
     Slot `(i,β)` carries `a_i ‖ b_iβ` under its own ECDH key, and its share is encrypted under
     `H(a ‖ b_iβ)`. The base (a 16-byte zero check value, `dk1`, `dk2`, `dk3`) is encrypted
     under `a`.
   - **Link.** `link = SHA256("ORBIT-GS-LINK" ‖ sk2 ‖ sk3)` of the coin's own GWat key. It takes
     the place of the paper's `rtag` from `Activate`: GS cannot be opened without first
     evaluating GWat.

   The evaluator `evaluate_gs(gs, tag, keys, gwat_sk2, gwat_sk3)` now returns an error, rather
   than a garbage key, when the check value does not match. It is byte-identical in the Android
   crate (`app/rust/src/paymentbox/pbcrypto.rs`) and in the server's `pbcrypto.rs`. The JNI
   `evaluateGs` gained a `gwatKey` argument and throws `RuntimeException` instead of panicking;
   `computeGsAk2()` passes the card's `hiding_sign_vec2`. `librust.so` (arm64-v8a) was rebuilt
   from WSL with NDK r23b.

   Masking alone would not have made GS one-time. Three further defects had to be fixed:
   - (a) *Fixed seed.* `garble_waters` and `generate_gs` drew `r`, masks and AoN shares from
     `ark_std::test_rng()`, a fixed seed, so every coin had identical values. A holder of two
     coins could open slot `(i,0)` of one and slot `(i,1)` of the other to obtain `u_i·r`. Both
     now use `rand::thread_rng()`. Only the Waters parameters keep the fixed seed.
   - (b) *Spare uses.* With `nusecount = 96`, GS needed 89 uses. A client that skipped GWat had
     7 spare uses (2^7 recipients), and one that did not had 2 (4 recipients). With the link,
     GWat cannot be skipped, and `_GS_NUSECOUNT` is now exactly `5 + 1 + 88 = 94`
     (`server.py`; Android `callToken(94, …)`).
   - (c) *Pooled batch budget.* `/api/replenish` issued a whole batch to one key with a pooled
     `96 × n` budget. A user could leave one coin unused and spend its uses opening both slots
     of another coin's bits. The endpoint now takes one attestation per coin, each with exactly
     94 uses (`performSync()` creates one `OneTimeMemory(94)` per coin), and
     `verify_attestation` no longer accepts multiples of the budget.

   New test `test_gs_full()` (`server.py`) simulates the device with a single P-256 key and
   counts its ECDH uses. All four checks pass:
   - The honest activate-then-re-delegate flow uses exactly 94 uses, and the resulting key
     passes both Waters equations for `"002_001_000"` but not for `"002_001_001"`.
   - GS evaluated with another coin's GWat key is rejected.
   - With one bit slot left unopened, which is what opening both slots of another bit within
     the budget forces, evaluation fails for both values of the doubly opened bit.
   - Two coins minted for the same key and tag have different GS ciphertexts and a different
     GWat `sig2`.

   The existing `test_redelegate_full()` still passes. A Flask test-client run of
   `/api/replenish`, with attestation verification stubbed, returned 400 for too few
   attestations and for a pooled 188-use key. It returned three circuits for three keys, each
   openable only by its own key.

**Why:** The original GS circuit implemented the paper's 1-of-2 selection but none of the
mechanisms that make the selection binding: shares that are useless individually, a key that
requires every position, and a budget with no slack. One-timeness in the paper is a
combination of the circuit's all-or-nothing structure and the hardware's exact use count. Any
slack in either reopens multiple evaluation: a fixed seed shared across coins, spare uses, a
pooled budget, or a GS circuit evaluable without GWat.

**Implication:** Re-delegation one-timeness (Def. 4.3) now holds cryptographically, assuming
the hardware enforces `nusecount`. That assumption is still weakened by the trusted software
attestation root. The contract fix stops repeated withdrawals only once it is redeployed. Coins
minted before this change cannot be re-delegated and must be re-minted. Unchanged: the GS
evaluator still chooses every tag bit, including the denomination bits (the denomination
forgery fix is still only proposed); activation still does not need the bank; the hashlock is
still shared per denomination. Next steps: build and test the app on a device, including that
94 uses suffice in practice, then redeploy the contract.

## 2026-10-26 — Master secret `beta_secret` derivable from the public parameter seed

**Attempt:** While reviewing the proposed denomination-forgery fix (one GS slot per fixed
`DDD` bit instead of two), the generation of the Waters master secret was checked to see whether
it could undermine any circuit-level fix.
**Result:** Failure (security flaw found by code reading; not yet confirmed by an experiment).
`beta_secret` can be recomputed by anyone, and the app's bundled parameter file contains it.
**Details:** `generate_params_waters()` (`server/rustcode/src/lib.rs:150`) draws its values in
this order:
```rust
let mut rng = ark_std::test_rng();            // fixed seed, public in the arkworks source
let alpha_secret = ScalarField::rand(&mut rng);
let beta_secret = alpha_secret;
let g = G::rand(&mut rng);  let g_alpha = g * alpha_secret;
let g2 = G2::rand(&mut rng); let g2_beta = g2 * beta_secret;
```
`ark_std::test_rng()` always starts from the same hard-coded seed. Running the same three lines
outside the server therefore gives `beta_secret` and the master key `msk = g_alpha^beta`.
With `msk`, a valid Waters key for any tag is `sk1 = msk · h_tag^r`, `sk2 = g^r`,
`sk3 = g2^r` for any `r`. That means any denomination and any user, without a coin, a GS
circuit or attested hardware.

Separately, the parameter file the app bundles
(`paymentbox_otp/app/src/main/res/raw/waters_params.json`) contains a non-zero
`beta_secret` field next to `g`, `g_alpha`, `g2`, `g2_beta`, `h_vec` and `h_0`. That file was
inspected directly. So the secret is also present in every APK, independently of the seed.

An empirical check was planned but not run: recompute `beta_secret` with
`poc_adaptor_sig::generate_params(&mut ark_std::test_rng())`, compare it byte-for-byte with
the bundled file, and verify `e(msk, g2) = e(g_alpha, g2_beta)`. The PoC copy draws values in
the same order as the server function, so a match is expected.
**Why:** The 2026-10-05 fix moved per-coin secrets (`r`, masks, AoN shares) to
`rand::thread_rng()`. It deliberately kept the fixed seed for the Waters parameters, so the app
could bundle them instead of receiving them. That reasoning holds for the *public* parameters,
but the same seeded generator also produces the *secret* `alpha_secret`/`beta_secret`. The rule
"`beta_secret` never leaves the server" (CLAUDE.md) cannot hold when the secret is not random:
it never needs to leave, because anyone can recompute it.
**Implication:** This breaks unforgeability of every Waters key, and with it any
denomination-forgery fix at the GS-circuit level. It must be fixed first.
- **Proposed fix:** generate `beta_secret` once with real randomness (`thread_rng()` or an
  offline ceremony) and store it only on the server. The public elements `g`, `g2`, `h_0` and
  `h_vec` may still come from the fixed seed. Compute `g_alpha`/`g2_beta` with the secret and
  bundle them as public constants. Remove `beta_secret` from `waters_params.json`.
- **Note on `alpha = beta`:** `alpha_secret = beta_secret` reduces the scheme to a single
  secret. Whether that matters once the secret is random needs a check against the Waters key
  structure (`CLAUDE_Waters.md`).
- **Every key and coin issued so far** under the current parameters must be treated as
  forgeable, and the bundled parameters regenerated.
