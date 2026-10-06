# Denomination and Identity-QR Feature Review

Tracks the walkthrough/review of the denomination system and the scan/identity-QR
re-delegation flow added on top of the base ORBIT implementation, and the gaps this
review surfaced relative to the paper's construction.

## 2026-08-17 — Q&A walkthrough of denomination and scan/identity-QR features

**Attempt:** Reviewed, endpoint by endpoint and field by field, how the two features added on
top of the base implementation — the per-denomination minting system and the scan/identity-QR
re-delegation flow — map onto the paper's algorithms (`Delegate`, `Unlock`, `Activate`,
`RDelegate`, `DSign`), following up a sequence-diagram artifact produced for a supervisor
meeting.

**Result:** Documentation/analysis pass — no code changed. Confirmed several points behave as
intended, and surfaced one significant deviation from the paper's trust model.

**Details:**

1. `POST /api/lock {denomination}` vs `GET /api/delegatedpresig?attestation=...&denomination=N`
   (`server/server.py:435-490` region, `denomination_config()`, `_send_tx`): `/api/lock` only
   locks capital for a dormant circuit that was already garbled by an earlier `/api/replenish`
   call — it takes just `{denomination}`, resolves `cfg = denomination_config(denomination)`
   (`hashlock = denomination`, `eth = _DENOM_ETH[denomination]`), and calls `newContract()`.
   `/api/delegatedpresig` does both `Delegate` (garbling, via `garble_waters`) and `Unlock`
   (locking capital) in one call, for when no dormant stock exists yet. Neither call takes a
   "tag" argument distinct from `denomination` — the on-chain HTLC `hashlock` and the Waters IBE
   identity `tag` are both just the integer denomination.

2. `POST /api/replenish` batching one AndroidKeyStore key across N circuits
   (`server.py:435-482`, `_garble_one_circuit`): confirmed the server never touches the caller's
   private key. It verifies one attestation, extracts the caller's one public key `raw_pk`, and
   for each of the `total_count` circuits requested generates 64 fresh, disposable ephemeral EC
   keypairs, computing `ephemeral_priv.exchange(ECDH(), raw_pk)` for each — i.e. the server-side
   half of ECDH against the caller's single public key, never their private key. The published
   `nusecount = 64 * total_count` requirement on the attestation is not a count of ECDH
   operations the server performs (it can garble arbitrarily many circuits against one public
   key); it is a budget check that the caller's hardware key is provisioned to allow that many
   *future* real ECDH operations, which are only actually spent later when the caller's device
   evaluates/activates or GS-re-delegates each specific circuit.

3. The `msg` field in `/api/delegatedpresig`/`/api/replenish` responses is the JSON-serialized
   `PaymentBox` struct produced by `garble_waters()` (`server/rustcode/src/lib.rs:355-506`) —
   ciphertext only (`sig1_vec`, `sig1_firstpart`, `sig2`, `sig3`, `key_mat_enc`, all encrypted
   under an all-or-nothing key derived from ECDH shares). This is the paper's `dmk`/`GWat`
   component; it is meaningless without the corresponding real ECDH operations performed by the
   caller's hardware key against the accompanying `epk` list.

4. Confirmed a known, already-documented deviation (see `CLAUDE.md`, "Current Demo vs. Paper"):
   `/api/pay` submits the Waters activation-key components `sk1/sk2/sk3` (paper's `dk1/dk2/dk3`)
   directly to `zfairexchange.sol`'s `withdraw()`, which runs the two Waters pairing checks
   on-chain. This substitutes for the paper's actual redemption step,
   `DSign(osk, skD, m) -> sigma = (r,s)` submitted to a `zecdsa.sol`-style contract via
   `ecrecover`. The substitution exists because no code path converts a Waters key into an
   ECDSA signature, and because the ECDSA garbled circuit currently produces signatures on
   secp256r1 while `ecrecover` requires secp256k1 (curve mismatch, tracked under "zecdsa.sol
   blockers" in `CLAUDE.md`). Functionally, `withdraw()` in the current demo behaves like an
   HTLC preimage-reveal check ("prove possession of a valid Waters key for this hashlock"), not
   a signature-over-a-message verification.

5. Classified which sequence-diagram steps are attributable to each of the two added features:
   denomination touches `/api/replenish`'s per-`(denomination, count)` request shape, the
   `/api/lock` / `/api/delegatedpresig?denomination=N` calls, and `newContract()`'s
   per-denomination ETH amount. Scan/identity-QR touches Bob's "My ID" QR generation, Alice
   scanning it before re-delegating, and the re-delegation QR Alice produces for Bob. The
   ECDH/`evaluate_paymentbox` evaluation, `/api/pay`, `withdraw()`, and the on-chain pairing
   check are unmodified base-implementation flow.

6. Confirmed the tile label `UUU_DDD_CCC` (`MainActivity.kt`, `orbit_identity_$account` +
   `card.denomination` + `coinIndex`) is purely a local, cosmetic display string — it is never
   transmitted over the network or fed into any cryptographic operation. It is distinct from
   the two-segment string `bobTag = "%03d_%03d".format(bobId.uid, card.denomination)`, which
   *is* load-bearing: it is the tag `computeGsAk2()` actually evaluates the GS circuit at during
   offline re-delegation, but it is likewise never transmitted (GS re-delegation is fully
   offline) and only exists transiently on the delegator's device.

7. Confirmed `contract_id` (the `bytes32` HTLC identifier from `zfairexchange.sol`'s
   `HTLCETHNew` event) predates both added features — it is core to the pre-existing
   Sepolia/HTLC integration, not something introduced by denomination or scan/QR. What did
   change: `newContract()`'s locked ETH amount and `hashlock` are now parameterized per
   denomination instead of fixed, and the dormant-stock split introduced a timing distinction
   (`contract_id = ""` for a garbled-but-not-yet-capital-locked dormant circuit, populated only
   once `/api/lock` runs).

8. **Most significant finding.** Bob's "My ID" QR encodes only `{"uid": N}` — a plain integer
   the holder types into a dialog once, with no cryptographic binding whatsoever to an actual
   AndroidKeyStore key, no attestation, and no server involvement. This conflicts with the
   paper's actual chain (Def. 4.2): `Delegate(sk, pk, pkD_Bob)` returns `(dmk_tag_Bob, tag_Bob)`
   only after the bank verifies `pkD_Bob`'s hardware attestation, so in the paper, possessing a
   valid `tag_Bob` is itself evidence that the bank once confirmed the delegatee has a genuine,
   count-limited hardware key. `RDelegate(osk, skD, tag2)` is meant to consume *that*
   bank-issued tag. In this implementation's current re-delegation path (documented in
   `CLAUDE.md` as "Option A"), Bob never goes through `Delegate` at all — he has no `dmk2`, and
   the tag Alice evaluates against is built from his self-declared, unverified `uid`. The
   resulting `ak2` is handed to Bob directly, and Bob spends it against Alice's original
   `contract_id` without ever exercising a hardware key of his own.

**Why:** "Option A" was chosen as the demo shortcut because the paper-correct alternative
("Option B": the bank garbles a fresh circuit bound to Bob's own attested public key, which Bob
then evaluates himself) requires transmitting a ~42 KB garbled circuit to Bob — too large for a
QR code, and not yet solved via BLE/NFC/server relay. Option A avoids that transport problem by
having Alice do all 57 GS-evaluation ECDH operations herself and hand Bob a ready-to-use key,
at the cost of dropping the attestation binding entirely for the recipient side of every
re-delegation hop after the first.

**Implication:** One-timeness (Def. 4.3) is currently only enforced on the *delegator's* side
of a re-delegation (via the delegator's own `nusecount` budget) — the current implementation
gives no cryptographic assurance that any recipient reached via the scan/QR flow is actually
constrained by a real limited-use hardware key, since recipients never present an attested
`pkD` before being issued a tag. This is a known, deliberate scope limitation rather than a bug,
and is exactly the kind of gap worth stating explicitly (as "Option A vs. Option B",
`CLAUDE.md`) when presenting this work — the demo proves the Waters/GS cryptography and the
on-chain settlement path work end-to-end, but does not yet demonstrate the paper's full
delegatee-attestation chain beyond the first hop.