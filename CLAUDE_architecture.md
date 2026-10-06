# ORBIT — App & Protocol Flows

How the demo actually runs end to end: minting, dormant stock, the coin counter, Withdraw,
Re-delegate, and the data structures they use. Read this before changing any flow in
`server.py`, `MainActivity.kt`, or `PaymentBoxAdapter.kt`. Crypto internals are in
`CLAUDE_crypto.md`, contracts in `CLAUDE_contracts.md`, UI details in `CLAUDE_android.md`.

## Minting and activation

1. Mint FAB dropdown → user picks a denomination → `activateOrMint(denomination)`.
2. If dormant stock exists for that denomination: POST `/api/lock {denomination}` → server calls
   `newContract()` → the dormant card moves from `dormantCards` into the grid with the returned
   `contract_id`. Done.
3. Otherwise `PaymentBoxAdapter.issueCard(denomination)` → `mainAct.callToken(94, denomination)`
   → `OneTimeMemory(94)` creates an AndroidKeyStore EC key with `nusecount = 94`
   (5 GWat + 89 GS, exact) → GET `/api/delegatedpresig?attestation=...&denomination=N`.
4. Server: `verify_attestation()` → `denomination_config(N)` → `garble_waters_with_gs()` (GWat:
   5 positions × 256 items = 1280 ephemeral EC keypairs; GS circuit linked to it) → `newContract()` locks
   `_DENOM_ETH[N]` → returns `{epk, params, msg, contract_id, denomination, gs_circuit}`.
   `params` has `beta_secret` stripped.
5. App: 5 parallel AndroidKeyStore ECDH ops → `paymentbox()` JNI → `evaluate_paymentbox()`
   recovers `(sk1, sk2, sk3)` → stored on a new `DelegatedData` card (with `gs_circuit`,
   `coinIndex = nextCoinIndex(denomination)`).

Activation needs only the device's own ECDH — no activation key from the bank (see the
"activation no longer needs the bank" flaw in `thesis_log/open-questions.md`).

## Dormant stock — minting separated from capital-locking

Mirrors the paper's `Delegate` (offline, free) vs. `Unlock` + payment (online) split.

- **Dormant dmk:** garbled Waters + GS circuit from `/api/replenish`, `contract_id == ""`, no
  capital locked. Kept in `dormantCards` (`MainActivity.kt`), persisted via
  `PersistencyManager.saveDormant()/loadDormant()` under `SAVE_DORMANT_$account`. Never shown as
  a grid tile. Keys are already evaluated at sync time.
- **Live dmk:** capital locked (`contract_id` set), card in `profileAdapter.dataSet`, spendable.
- **Sync:** overflow menu → "Sync" → `showSyncDialog()` computes
  `deficit = target − dormantCount` per denomination (targets from `loadTargets()`,
  `orbit_targets_$account`) → `performSync(deficit)` creates one `OneTimeMemory(94)` key per
  coin and POSTs to `/api/replenish` with one attestation per coin, then appends the circuits to
  `dormantCards` (each card's `keyalias` is its own key). A shared key with a pooled budget
  would break GS one-timeness (`CLAUDE_crypto.md`).
- **Checks FAB:** `showChecksDialog()` edits the per-denomination Sync *targets*
  (`[−] target [+]`, persisted immediately via `saveTargets()`); "Sync now" calls
  `showSyncDialog()`. It never mints or deletes a dmk itself.
- **Mint dropdown** shows live dormant counts ("1C / 0.01 ETH — 3x").
- New wallets default to target 0 for every denomination.
- Out of scope: deleting individual dormant dmks; turning a live card back into a dormant one
  (would need an on-chain `refund()` after the timelock — no endpoint exists).

## Per-coin counter (`coinIndex`, the `CCC` in `UUU_DDD_CCC`)

- `DelegatedData.coinIndex: Int` (default 0): a 0-based, monotonically increasing,
  per-account-per-denomination sequence number. Never reused or decremented.
- Stored as JSON `{denomination: count}` in SharedPreferences `orbit_coin_counters_$account`
  (`loadCoinCounters()` / `saveCoinCounters()`).
- Assigned via `nextCoinIndex(denomination)` in `issueCard()` and `performSync()`, and in
  `addCardFromQR()` for scans without a `"counter"` field.
- For cards received via GS re-delegation, `addCardFromQR()` instead calls
  `recordReceivedCounter(denomination, counter)`: it records the exact counter the sender
  embedded in the Waters tag, and advances the local counter past it. So `CCC` is cosmetic for
  self-minted cards, and cryptographically bound for re-delegated ones.
- Survives dormant → live promotion unchanged.
- The only reset is account deletion (`PersistencyManager.removeAccount()` clears
  `orbit_coin_counters_$name` for all denominations). No per-denomination edit control exists.

## Withdraw (Pay)

1. User selects a card → **Withdraw** → POST `/api/pay {sk1, sk2, sk3, contract_id, denomination}`.
2. Server derives its **own** key via `water_unlock_solidity(denomination)` and calls
   `withdraw(contract_id, key)` on `zfairexchange.sol`. The client's `(sk1, sk2, sk3)` are
   ignored (tag-encoding mismatch, see `CLAUDE_crypto.md`).
3. Success → `consumeCard()` removes the card and saves immediately, *then* the dialog with the
   Sepolia TX hash is shown. Every spend (Withdraw, GS and legacy re-delegate) uses
   `consumeCard()`, so removal never depends on how a dialog is dismissed or on `onPause()`.
4. Failure → error dialog, card stays.

**Dead cards:** cards minted without the blockchain env vars, or whose `newContract`/`/api/lock`
timed out, have `contract_id = ""` ("no HTLC" on the tile) and can never be withdrawn.
Long-press → "Delete token?". A timed-out `newContract` that mines later leaves ETH in an
orphaned HTLC, recoverable via `refund()` after the 1-hour timelock.

## Re-delegate

### GS path (current — cards with a `gs_circuit`), fully offline

1. **Bob shows "My ID".** First tap asks for a user id (stored as `uid` in
   `orbit_identity_$account`). Every tap regenerates the QR live as
   `{"uid":N,"counters":{denom:count,...}}` from `orbit_coin_counters_$account`. The QR is
   denomination-agnostic: Bob broadcasts all his counters; the sender picks the denomination.
2. **Alice re-delegates.** She selects a card → **Re-delegate** → `gsRedelegateLauncher` opens
   the camera → scans Bob's QR →
   `bobCounter = counters[card.denomination] ?: 0` →
   `bobTag = "%03d_%03d_%03d".format(uid, card.denomination, bobCounter)` (e.g. `"002_001_000"`).
3. `computeGsAk2(card, bobTag)`: 1 + 88 = 89 sequential AndroidKeyStore ECDH ops against the GS
   epks → `evaluateGs(gs, bobTag, keys, card.hiding_sign_vec2)` JNI (the card's own GWat key
   unlocks the GS all-or-nothing key) → `ak2 = (sk1, sk2, sk3)`. No server contact.
4. The card is consumed (`consumeCard()`), then Alice's app shows the re-delegation QR
   `{sk1, sk2, sk3, contract_id: <Alice's original>, denomination, counter: bobCounter}`
   (title "Alice → uid NNN").
5. **Bob scans** → `addCardFromQR()` → new card (`hiding_sign = hardcodedParams`,
   `gs_circuit = ""`, `coinIndex` from `counter`).
6. **Bob withdraws** against Alice's *original* `contract_id` — no new HTLC is created.

The server is contacted only at Alice's mint and Bob's withdrawal.
**One-phone demo:** screenshot Alice's QR, show it on a laptop, scan it on "Bob".

### Legacy path (cards without a `gs_circuit`)

POST `/api/redelegate {contract_id, denomination}` → server withdraws Alice's HTLC with its own
key, then creates a fresh HTLC for Bob → QR with the stored `(sk1, sk2, sk3)` and Bob's new
`contract_id`. Known hole: it trusts the request's denomination and still mints the new HTLC
when `contract_id` is empty or the old withdrawal fails.

### Option A vs. Option B

- **Option A (implemented):** the sender derives a ready-made key for the recipient, so the
  recipient never presents an attested hardware key of their own.
- **Option B (future):** the bank garbles a fresh circuit bound to the recipient's own attested
  key, which the recipient evaluates. Paper-correct, but the circuit (~42 KB of epks alone)
  doesn't fit in a ~3 KB QR — needs BLE/NFC or a server relay.

### Why params aren't in the QR

`ParamWaters` is ~30 KB. It's bundled instead as `res/raw/waters_params.json` (loaded as
`hardcodedParams`), which is safe because `generate_params_waters()` uses `ark_std::test_rng()`
(fixed seed), so params are identical on every server start.

## Key data structures

- **`TestData`** (server response): `{epk: base64url, params: JSON string, msg: JSON string,
  contract_id: hex, denomination: Int, gs_circuit: Any?}`. Gson maps `gs_circuit` to `Any?`; it's
  stored on the card as a serialized JSON string.
- **`DelegatedData`** (a card): `hiding_sign = params` (no `beta_secret`),
  `hiding_sign_vec2 = JSON(sk1, sk2, sk3)`, `contract_id` (bytes32 hex, `""` while dormant),
  `denomination` (1/2/5/10/20/50/100), `gs_circuit` (JSON: `base_key_mat`, `base_enc`,
  `key_mat0`, `key_mat1`, `slots_c0`, `slots_c1`, `epk`; `""` for legacy and received cards), `coinIndex`, `keyalias`, `userName = "Signing Token #N"`,
  `r = part1 = BigInteger.ZERO`.
- **`PersistencyManager`**: SharedPreferences store. `data` (live cards, `SAVE_$account`) is
  shared with the adapter; `dormant` (`SAVE_DORMANT_$account`) is not.
- **`VariantConfig`**: SIGN (ECDSA) vs REDELEGATE (Waters), with `count` and `wordSize`. The demo
  uses `RDelegateByteInstance()` (count=5, wordSize=8, MAX_ITEM=256).
- Server Rust `ECDSA` struct `{tag, rtag, r, s0, s_vec, key_mat_enc}`: ECDSA variant, unused in
  the UI.

**Gson gotcha:** Gson ignores Kotlin default values. A missing JSON field lands as `null` in a
non-null `String = ""` field and crashes later (e.g. `NullPointerException: parameter
contract_id` in `DelegatedData.copy`) — always guard parsed strings with `?: ""`. Missing `Int`
fields silently become `0`, which is why pre-counter cards show `CCC = 000`.
