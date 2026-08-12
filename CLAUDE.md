# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@ORBIT_PAPER.md

## Project Overview

ORBIT is an academic research prototype for a **one-shot payment system** using garbled circuits and Waters IBE. The system has three phases matching the paper:

- **Issuance (offline prep)**: Bank issues a dormant key (dmk) — a garbled Waters IBE circuit — to Alice. The circuit is useless without evaluation.
- **Activation (requires server)**: Alice evaluates the circuit using her AndroidKeyStore private key via ECDH → recovers `(sk1, sk2, sk3)`, her Waters activation key. The dmk is now live and stored as a card.
- **Use (fully offline)**: Alice uses the dmk exactly once — either **Withdraw** (submits Waters key to Sepolia, claims ETH) or **Re-delegate** (offline: re-evaluates GS circuit at Bob's tag bits using AndroidKeyStore ECDH, produces ak2 QR). Either action removes the card, enforcing one-timeness.

Two variants exist in the codebase:
- **Waters/RDelegate** — the main demo path; supports both Pay and Re-delegate from a single dmk
- **ECDSA/DSign** — a separate faster variant (direct `(r, s)` signing); does NOT support re-delegation; currently not exposed in the UI

## Components

### Server (`server/`)
Flask + Rust/PyO3 extension (`rustcode/`) running on WSL.

**Run server:**
```bash
cd server
source .venv/bin/activate
python3 server.py
```

**Build Rust extension (required before first run):**
```bash
cd server
source $HOME/.cargo/env
source .venv/bin/activate
bash build.sh   # runs: cd rustcode && maturin develop --release
```

Key endpoints:
- `GET /api/delegatedpresig?attestation=...&denomination=N` — verifies Android attestation (nusecount=64 required), garbles Waters circuit with `tag=N`, generates GS circuit (57 ECDH slots for offline re-delegation), calls `newContract()` on Sepolia (locks capital immediately), returns `{epk, params, msg, contract_id, denomination, gs_circuit}`. `denomination` defaults to 1. Used by the single-mint path (`issueCard()`) when no dormant stock exists for that denomination.
- `GET /api/delegatedpresigecdsa?attestation=...` — same but ECDSA variant (no blockchain call, no denomination)
- `POST /api/replenish` — body `{attestation: {att:[...]}, request: [{denomination, count}, ...]}` — batch-garbles Waters+GS circuits for every `(denomination, count)` pair, **does NOT call `newContract()`** — every returned circuit has `contract_id: ""` (dormant/unlocked). `nusecount` in the attestation must equal `64 × total_count` (one AndroidKeyStore key spans the whole batch). Returns `{params, circuits: [{denomination, contract_id:"", epk, msg, gs_circuit}, ...]}`. Backs the "Checks" / Sync flow (see Dormant Stock section below).
- `POST /api/lock` — body `{denomination}` — calls `newContract()` on Sepolia to lock capital for one already-garbled dormant dmk, right before it's spent. Returns `{contract_id}`. This is what turns a dormant dmk into a live/active one.
- `POST /api/pay` — body `{sk1, sk2, sk3, contract_id, denomination}` — calls `withdraw()` on `zfairexchange.sol` using the correct `hashlock=denomination`, returns `{tx_hash, contract_id}`
- `POST /api/redelegate` — body `{contract_id, denomination}` — withdraws Alice's HTLC (skipped gracefully if `contract_id` is empty), then `newContract()` creates a fresh HTLC for Bob at the same denomination's ETH amount, returns `{contract_id}` for Bob. sk1/sk2/sk3 NOT required — server derives Waters key from its own beta_secret for on-chain use.
- `GET /api/waters_solidity_params?id=<int>` — returns Waters params + signing key for given id in Solidity-compatible format; used by `ztest_htlc.ipynb`
- `GET /api/benchmarkdelegateecdsa?attestation=...` — runs 100 server-side benchmark iterations (heavy — avoid during normal use)
- `GET /api/verifyattest?attestation=...` — standalone attestation verification

**Blockchain env vars** (required for `/api/delegatedpresig` and `/api/pay`):
```bash
export ETH_PRIVATE_KEY="<your Sepolia wallet private key>"
export ALCHEMY_URL="https://eth-sepolia.g.alchemy.com/v2/<your key>"
```
If not set, blockchain calls are skipped with a warning and `contract_id` is returned as `""`. Env vars are per-shell — they must be exported in the same terminal that runs `python3 server.py`.

**Denomination system** (`server.py`):
```python
_DENOM_ETH = {1: 0.01, 2: 0.02, 5: 0.05, 10: 0.10, 20: 0.20, 100: 1.00}

def denomination_config(denom: int) -> dict:
    return {"tag": denom, "hashlock": denom, "eth": _DENOM_ETH[denom]}
```
`tag` = Waters IBE identity (key for tag=2 cannot unlock hashlock=1 contract — cryptographically enforced via `H(tag)` in the pairing). `garble_waters()` accepts `tag: u8` as its 5th argument (Rust, server extension); `water_unlock_solidity(params, id)` already accepted any id. Extend supported denominations by adding to `_DENOM_ETH` only — no contract, Rust, or Android changes needed.

**Sepolia transaction handling** (`_send_tx` in `server.py`):
- Nonce uses the `'pending'` block tag — prevents "replacement transaction underpriced" when sending sequential txs (e.g. `setup()` then `newContract()`).
- Gas price is **2x current** — bidding exactly the going rate leaves txs stuck in the mempool during Sepolia gas spikes.
- Receipt timeout is **300s** (web3 default 120s was too short during congestion).
- Server console logs: `[NEW]`, `[REDELEGATE]`, `[PAY]` lines print the `contract_id` for each on-chain action; `[WARN]` lines show skipped/failed calls.

**`contract_id` hex stripping:** `server.py` uses `contract_id_hex.removeprefix('0x')` (Python 3.9+) before calling `bytes.fromhex()`. Do NOT use `str.lstrip('0x')` — it strips all leading `'0'` and `'x'` characters (not just the two-char prefix), so a contract_id like `0f9a...` loses its leading zero, producing a 63-char odd-length hex string that causes `ValueError: non-hexadecimal number found` in `bytes.fromhex()`.

**Stuck nonce queue:** If txs time out with "is not in the chain after N seconds", check for a nonce jam: compare `get_transaction_count(addr, 'latest')` vs `'pending'` — if pending > latest, old low-gas txs are blocking the queue (Ethereum mines nonces strictly in order; mempool evictions can also leave nonce *gaps* that block everything after them). Fix with `server/unstick.py`: it replaces each stuck/gapped nonce with a 0-ETH self-transfer at 5x gas (21k gas each). Run it with the env vars set; enter the highest stuck nonce when prompted.

**Gas economics** (lock amounts per denomination defined in `_DENOM_ETH` in `server.py`; default 1-token = 0.01 ETH, 2-token = 0.02 ETH, up to 100-token = 1.00 ETH):
- New: −ETH locked + ~0.002 ETH gas (first issuance per server session also runs `setup()`, adding ~0.001 ETH)
- Re-delegate: +ETH recovered − ETH re-locked + ~0.003 ETH gas (withdraw ~389k gas + newContract)
- Pay: +ETH recovered, ~0.005–0.006 ETH gas (`withdraw()` runs BN254 pairing on-chain, ~389k gas)
- Full New → Re-delegate → Pay cycle: wallet loses only gas, ~0.007 ETH total. Lock amount must exceed gas-per-tx for Pay to show a visible positive wallet return; at 0.01 ETH lock, Pay nets ~+0.004 ETH.

**WSL networking:** Server binds to `0.0.0.0:5000`. Windows port forwarding routes phone traffic from `192.168.1.101:5000` → WSL IP:5000. Set up with:
```powershell
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=5000 connectaddress=<WSL-IP> connectport=5000
```
WSL IP changes on restart — check with `hostname -I`. Windows LAN IP is `192.168.1.101` (not .100).

**Android attestation:** `rootcert.pem` contains trusted root certificates for verifying Android Key Attestation chains. Includes both hardware TEE/StrongBox roots AND the Android Keystore Software Attestation Root (needed for devices without StrongBox like Galaxy A52).

### Android App (`paymentbox_otp/` on Windows at `C:\Masters\orbit-7C66\paymentbox_otp\`)

Built with Android Studio on Windows. The Rust JNI library (`librust.so`) is **pre-built and committed** to `app/src/main/jniLibs/` — the Gradle cargo plugin does not reliably recompile it. To rebuild the Rust JNI, you must manually compile for `aarch64-linux-android` and replace the `.so` files.

**App configuration:** `MainActivity.kt` — `urlDest` (internal visibility) is set to the Windows machine's LAN IP:
```kotlin
internal val urlDest = "http://192.168.1.101:5000/"
```

**Benchmark calls in `onCreate`** — all `benchmark_delegate(...)` calls in `MainActivity.onCreate()` should remain commented out during normal use. They fire 100 server requests on app startup and cause `Connection reset` when pressing `+`.

**Variant config:** The "New" button in `PaymentBoxAdapter.kt` uses `VariantConfig.RDelegateByteInstance()` → `count=5, wordSize=8, MAX_ITEM=256`. This issues a Waters garbled circuit (5 positions × 256 items = 1280 slots). `garble_redelegate()` JNI exists in both server Rust and Android JNI Rust for offline re-delegation.

**Git note:** The WSL repo (`/home/mirzokhid/Masters/orbit-7C66`) tracks only the server-side files. `paymentbox_otp/` lives on Windows at `C:\Masters\orbit-7C66\paymentbox_otp\` and must be committed to GitHub from Windows.

### Android Rust JNI (`paymentbox_otp/app/rust/`)

Cross-compiled for Android (`aarch64-linux-android`, `armeabi-v7a`). Key files:
- `src/lib.rs` — JNI entry points: `paymentboxecdsa()`, `paymentbox()`, `garble_redelegate()`, `rust_init()`, `test()`
- `src/paymentbox/pbcrypto.rs` — `evaluate_ecdsa()`, `evaluate_paymentbox()`, `garble_redelegate()`

`evaluate_ecdsa()` returns `(Vec<u8>, Vec<u8>)` → JNI serializes as `{"r":"<hex>","s":"<hex>"}`.  
`evaluate_paymentbox()` returns `(Vec<u8>, Vec<u8>, Vec<u8>)` → JNI serializes as `{"sk1":"<hex>","sk2":"<hex>","sk3":"<hex>"}`.  
`garble_redelegate()` takes Alice's osk bytes + Bob's ECDH keys → returns `PaymentBox` JSON string.

**Recompiling `librust.so` from WSL:**
```bash
# NDK extracted at /tmp/android-ndk-r23b (Linux NDK r23b)
# Symlinks required: clang and clang++ must point to clang-12 in the NDK bin dir
export PATH="/tmp/android-ndk-r23b/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
cd /mnt/c/Masters/orbit-7C66/paymentbox_otp/app/rust
cargo build --target aarch64-linux-android --release
cp target/aarch64-linux-android/release/librust.so /mnt/c/Masters/orbit-7C66/paymentbox_otp/app/src/main/jniLibs/arm64-v8a/librust.so
```
Linker config is in `.cargo/config.toml` (Linux NDK paths). If NDK symlinks break after re-extraction: `cd /tmp/android-ndk-r23b/toolchains/llvm/prebuilt/linux-x86_64/bin && rm clang clang++ && ln -s clang-12 clang && ln -s clang-12 clang++`.

## Architecture: Activation Flow ("New" button → Waters dmk)

1. `PaymentBoxAdapter` (`bindNewCard`) shows denomination picker dialog → user picks 1 or 2 → calls `issueCard(denomination)` → calls `mainAct.callToken(5, denomination)` (`RDelegateByteInstance`)
2. `callToken` creates `OneTimeMemory(5)` → generates EC key in AndroidKeyStore → gets attestation → GETs `/api/delegatedpresig?attestation=...&denomination=N`
3. Server: `verify_attestation()` validates certificate chain → `denomination_config(N)` resolves tag/hashlock/ETH → `garble_waters(..., tag=N)` generates 5×256=1280 ephemeral EC key pairs → `newContract()` locks `_DENOM_ETH[N]` ETH → returns `{epk, params, msg, contract_id, denomination}`
4. App: 5 parallel ECDH ops using AndroidKeyStore private key → derives 5 shared secrets → calls `paymentbox()` JNI
5. Rust: `evaluate_paymentbox()` decrypts garbled circuit → recovers `(sk1, sk2, sk3)` (Waters activation key) → returns as `{"sk1":"<hex>","sk2":"<hex>","sk3":"<hex>"}`
6. Kotlin stores on `DelegatedData`: `hiding_sign = params` (no `beta_secret` — stripped by server before transmission), `hiding_sign_vec2 = JSON(sk1, sk2, sk3)`, `r = part1 = BigInteger.ZERO`
7. "Signing Token #N" card added to RecyclerView

## Paper's Two-Contract Architecture (Section 2.4)

The full ORBIT payment system uses **two separate contracts** for two opposite directions of money flow. Understanding this is critical for the implementation.

### `zfairexchange.sol` — Alice purchases a coin from the bank (Steps 2-3)

Alice locks ETH in the contract. The bank can only claim it by revealing the Waters activation key on-chain. Alice watches the blockchain, extracts the key, and evaluates her dmk.

```
Alice: newContract(bank_address, alice_tag, timelock)  ← Alice locks her ETH
Bank:  withdraw(contractId, {sk1,sk2,sk3})             ← Bank reveals activation key, claims Alice's ETH
Alice: sees key on-chain → Activate(dmk, key) → osk   ← Alice now holds the one-shot signing key
```

The card in the UI represents Alice's `osk` — the activated signing right she purchased.

### `zecdsa.sol` — Final holder redeems the coin (Step 10)

The bank **pre-locks ETH once** in `zecdsa.sol` at the start. Any holder of a valid `osk` (Alice, or Bob after re-delegation) can produce an ECDSA signature via `DSign` and claim the ETH.

```
Bank:  pre-locks ETH in zecdsa.sol  ← done once at startup
Final: DSign(osk, skD, msg) → (r,s) → submit to zecdsa.sol → claims ETH
```

**Why re-delegation has no per-user HTLC problem:** Bob doesn't need his own HTLC contract. He inherits the ability to produce ECDSA signatures via `DSign`, and the **same** pre-locked `zecdsa.sol` pays out to whoever presents the first valid ECDSA signature. No new `newContract` is needed per re-delegation.

### Current Demo vs. Paper

The current demo uses `zfairexchange.sol` for **everything**, self-funded by the server wallet (not the paper's intended use): "New" locks 0.01 ETH (server acting as bank), "Pay" withdraws it (server acting as Alice). This proves the BN254 pairing verification works on-chain but does not implement the full payment flow. The correct final step is `zecdsa.sol` + `DSign` — see Possible Next Steps.

**zecdsa.sol blockers discovered (June 2026 investigation):**
1. No code path converts Waters `(sk1,sk2,sk3)` → ECDSA `(r,s)`. The Waters and ECDSA garbled circuits are completely separate; the paper's combined circuit (GWat + GECDSA branches in one osk) is NOT implemented.
2. The ECDSA circuit produces `(r,s)` on **secp256r1** (P-256), but `zecdsa.sol` uses `ecrecover` which is **secp256k1** — incompatible curves. Fixing properly means switching the Rust circuit to secp256k1 scalars (both server and Android Rust, plus `librust.so` rebuild).
3. Server-side `evaluate_ecdsa` returns nothing (verifies internally only); only the Android JNI returns `{"r","s"}`.
4. `zecdsa.sol` payout is hardcoded at 0.00001 ETH per claim; it was tested (`ztest.ipynb`) with standard Ethereum `eth_sign`, not ORBIT circuit output.

## Dormant Stock — decoupling minting from capital-locking

**(Implemented, October 2026.)** Mirrors the paper's `Delegate` (offline, free) vs. `Unlock`+payment (online, capital-committing) split: minting a Waters garbled circuit and locking Sepolia capital for it are now two separate steps, so Alice can hold a stock of dormant dmks without every one of them committing ETH.

- **Dormant dmk**: a garbled Waters+GS circuit exists (from `/api/replenish`), but `contract_id == ""` — no capital locked. Stored in a separate list, `dormantCards` (`MainActivity.kt`), persisted via `PersistencyManager.dormant` / `saveDormant()` / `loadDormant()` under SharedPreferences key `SAVE_DORMANT_$account`. **Dormant dmks never appear as grid tiles** — the grid (`profileAdapter.dataSet`) only ever holds live/active cards.
- **Live/active dmk**: capital is locked (`contract_id` is a real HTLC id) and the card sits in `dataSet`, visible in the main grid, spendable via Withdraw/Re-delegate — same as before this change.
- **Promotion**: `activateOrMint(denomination)` (`MainActivity.kt`) is what the Mint FAB now calls. If a dormant dmk of that denomination exists, it POSTs `{denomination}` to `/api/lock` (locks capital), then moves that card from `dormantCards` into `profileAdapter.dataSet` with the returned `contract_id`. If no dormant stock exists, it falls back to `issueCard(denomination)` — the original single-mint path via `/api/delegatedpresig`, which garbles *and* locks in one call.
- **Sync**: overflow menu → "Sync" → `showSyncDialog()` computes `deficit = target − currentDormantCount` per denomination (targets from `loadTargets()`/`orbit_targets_$account`) and calls `performSync(deficit)`, which POSTs the deficit to `/api/replenish` and appends the returned circuits to `dormantCards` (never touches the grid).
- **Checks**: a second FAB next to Mint (purple, `fabChecks`) opens `showChecksDialog()` — lets the user edit the per-denomination Sync *targets* after account creation (previously only settable once, in the Create-wallet dialog). Each row is `[coin icon] N C  [−] <target> [+]`; tapping `+`/`−` immediately mutates and persists the target via `saveTargets()` — it does **not** mint or delete any dmk directly. A "Sync now" button in the same dialog calls the existing `showSyncDialog()` to fill the newly-edited deficit without leaving the dialog. Deleting individual already-minted dormant dmks, and "deactivating" a live card back to dormant (which would require an on-chain `refund()` after the HTLC timelock — no server endpoint for this exists yet), are both explicitly out of scope / future work.
- **Mint dropdown counts**: the `ListPopupWindow` opened by the Mint FAB shows a live per-denomination dormant count next to each row (`dropdown_denom_item.xml`'s `dormant_count_label`, e.g. "1C / 0.01 ETH — 3x") computed from `dormantCards.groupBy{it.denomination}.mapValues{it.value.size}`.
- **New wallet default**: `showCreateAccountDialog()`'s per-denomination target picker now defaults to **0** (was 3) — new accounts start with no preordered dormant stock.

### Per-Coin Counter — telling coins of the same denomination apart

**(Implemented, October 2026.)** Every dmk gets a `coinIndex: Int` field on `DelegatedData`, assigned once at mint time by `nextCoinIndex(denomination)` (`MainActivity.kt`) — a 0-based, monotonically-increasing, per-account-per-denomination sequence number persisted in `orbit_coin_counters_$account` (mirrors the existing `orbit_targets_$account` pattern). It's assigned at exactly the 3 places a new `DelegatedData` is constructed: `PaymentBoxAdapter.issueCard()`, `MainActivity.performSync()` (once per circuit in the batch), and `MainActivity.addCardFromQR()` (Bob's incoming card gets *his* account's next index, independent of the sender's). It survives promotion from dormant → live unchanged (`activateOrMint()` only does `dormantCard.copy(contract_id = ...)`), and is never reused or decremented when a coin is later spent or deleted — the counter only ever increments. The tile displays it as the third segment of the tag, `UUU_DDD_CCC` (see UI Layout below). This is purely a client-side/cosmetic feature — confirmed structurally independent from the cryptographic `bobTag` used in `computeGsAk2()`/`evaluateGs()` for GS re-delegation, so it required no server or Rust changes.

## Use Phase Flow

### New (Activation + HTLC creation)
1. User taps the **Mint FAB** (bottom-right) → `ListPopupWindow` appears with denomination rows ("1 C / 0.01 ETH — Nx", …) showing live dormant-stock counts → user picks one
2. `activateOrMint(denomination)`: if dormant stock exists for that denomination, POSTs `/api/lock` to commit capital and promotes the existing circuit into the grid; otherwise falls back to `issueCard(denomination)` (garble + lock in one `/api/delegatedpresig` call, as originally)
3. Either way, the app ends up with `(sk1, sk2, sk3)` recovered (already evaluated at mint time for dormant cards) and a real `contract_id` locking `_DENOM_ETH[denomination]` ETH on Sepolia
4. `contract_id` and `denomination` are stored on the card
5. Card appears in the grid — coin art shows 1/2 gold coin icons, denomination label, tag (`UUU_DDD_CCC`, see Per-Coin Counter below), `contract_id` prefix in top-right

**Dead cards:** cards created without the blockchain env vars set, or whose `newContract`/`/api/lock` timed out, have `contract_id = ""` (tile shows "no HTLC"). They can never Pay. Long-press the tile → "Delete token?" to remove them. If a timed-out `newContract` mines later, the ETH is locked in an orphaned HTLC — recoverable via `refund()` after the 1-hour timelock.

### Pay (Waters key → Sepolia withdraw)
1. User selects a card, taps "Pay"
2. App shows "Submitting to Sepolia..." dialog
3. App POSTs `{sk1, sk2, sk3, contract_id, denomination}` to `/api/pay`
4. Server calls `withdraw(contract_id, {sk1,sk2,sk3})` using `hashlock=denomination` — BN254 pairing verified on-chain
5. On success: dialog shows Sepolia TX hash → user presses OK → card removed
6. On failure: error dialog shown → card stays (dmk not consumed)

### Re-delegate (Option A: server creates new HTLC for recipient)
1. User selects a card, taps "Re-delegate"
2. App POSTs `{sk1,sk2,sk3,contract_id,denomination}` to `/api/redelegate` → server **withdraws Alice's HTLC**, then calls `newContract(tag=denomination, timelock)` → locks `_DENOM_ETH[denomination]` ETH in a fresh HTLC → returns `contract_id` for Bob. Net wallet change: gas only (~0.003 ETH).
3. App builds QR JSON: `{"sk1":"...","sk2":"...","sk3":"...","contract_id":"...","denomination":N}` (Bob's dedicated HTLC included)
4. QR dialog shown → user dismisses → Alice's card removed (dmk consumed)
5. Bob scans QR on his device → `addCardFromQR()` parses all fields including `contract_id` → card added
6. Bob taps "Pay" → `withdraw(contract_id_bob, {sk1,sk2,sk3})` → Bob claims ETH

**Option A vs Option B:**
- **Option A (current)**: Bob uses Alice's Waters key (tag=1) on a fresh HTLC. Simple, no new Rust code.
- **Option B (future)**: `garble_redelegate()` produces a new circuit for Bob with tag=2 → Bob gets his own cryptographically distinct key (sk1',sk2',sk3'). Requires server to send the new garbled circuit to Bob (too large for QR — needs BLE/NFC or server relay) and Bob to evaluate it with his AndroidKeyStore. See Possible Next Steps.

**Why the garbled circuit can't go in the QR:** `garble_redelegate()` output is 5×256×33 = ~42 KB epk alone; QR max is ~3 KB.

### QR Transfer (device-to-device via displayed QR)
1. User selects a card, taps "Re-delegate" in the bottom bar → QR dialog shown
2. On Bob's device: tap "Scan" in the bottom bar → ZXing scanner opens
3. Bob scans the QR → `MainActivity.addCardFromQR()` parses `{sk1, sk2, sk3}` and creates a new `DelegatedData` card
4. Bob's card uses `hardcodedParams` (loaded from `res/raw/waters_params.json`) as `hiding_sign`; `denomination` is parsed from the QR (defaults to 1 if absent)

**Why `params` is not in the QR:** `ParamWaters` JSON is ~30 KB (8,192 bytes of h_vec curve points that resist compression); QR max is ~3 KB. Instead, `waters_params.json` is bundled as a raw resource — safe because `generate_params_waters()` uses `ark_std::test_rng()` (fixed seed), so params are **identical on every server restart** and never need to be transmitted.

## Key Data Structures

- `TestData` — server response: `{epk: base64url, params: JSON string, msg: JSON string, contract_id: hex string, denomination: Int, gs_circuit: Any?}` — `gs_circuit` is a raw JSON object (Gson maps it to `Any?`; stored as serialized JSON string on the card).
- `DelegatedData` — stored dmk card. For Waters tokens: `hiding_sign = params` (no `beta_secret` — stripped by server), `hiding_sign_vec2 = JSON(sk1, sk2, sk3)`, `contract_id = bytes32 hex of the HTLC on Sepolia` (`""` for a dormant, not-yet-locked dmk), `denomination = Int (1/2/5/10/20/50/100)`, `gs_circuit = JSON string (base_enc + slots_c0 + slots_c1 + epk)` for GS-capable cards, `coinIndex = Int` (0-based, per-account-per-denomination mint sequence number — see Per-Coin Counter below), `r = part1 = BigInteger.ZERO`. `userName = "Signing Token #N"`. Scanned cards from QRs without `contract_id` have `contract_id = ""`; without `denomination` default to 1; without `gs_circuit` have `gs_circuit = ""` (legacy cards); without `coinIndex` default to 0 (also legacy — pre-existing cards saved before this field was added always read back as `coinIndex=0`, since Gson uses the type default for a missing field rather than erroring).

**Gson null gotcha:** Gson ignores Kotlin default values — a missing JSON field lands as `null` in a non-null `String = ""` field, crashing later with `NullPointerException: parameter contract_id` (e.g. in `DelegatedData.copy`). Always guard parsed fields with `?: ""` (`addCardFromQR()` and `bindNewCard` both do this). For non-null primitive fields like `Int`, Gson instead silently substitutes the JVM default (`0`) rather than crashing — this is why old cards minted before `coinIndex` existed display `000` instead of erroring.
- `PersistencyManager` — SharedPreferences-backed store; `data` ArrayList (live/active cards, key `SAVE_$account`) is shared with the adapter; `dormant` ArrayList (dormant dmks, key `SAVE_DORMANT_$account`) is not — see Dormant Stock section above
- `VariantConfig` — selects between SIGN (ECDSA) and REDELEGATE (Waters) variants with `count` and `wordSize`. Main demo uses `RDelegateByteInstance()` (count=5, wordSize=8)
- Server `ECDSA` struct (Rust): `{tag, rtag, r, s0, s_vec, key_mat_enc}` — the garbled ECDSA components (ECDSA variant, not used in current UI)

## Waters Activation Key Structure

In the paper (Section 5, `Unlock` algorithm), the activation key `ak = dktag = KeyDerWat(skWat, tag)` is a **Waters IBE decryption key** with 3 components (BN254 Type-3 pairing):

| Paper name | Code name | Type | Value |
|------------|-----------|------|-------|
| `dk1`      | `sk1`     | G1   | `g^α · H(tag)^r` — signing key + hashed identity |
| `dk2`      | `sk2`     | G1   | `g^r` — random factor in G1 |
| `dk3`      | `sk3`     | G2   | `g2^r` — random factor in G2 |

These appear as `Preimage{sk1, sk2, sk3}` in `zfairexchange.sol`, as `sig_1/sig_2/sig_3` in `server/rustcode/src/pbcrypto.rs:evaluate_paymentbox()`, and as the `Preimage` struct in `evaluate_paymentbox` on the Android JNI side. The two pairing checks in both the Solidity contract and the Rust code verify the same Waters equations from the paper:
- `e(g, sk3) == e(sk2, g2)` — confirms dk2 and dk3 use the same r
- `e(g^α, g2^β) · e(H(tag), sk3) == e(sk1, g2)` — main Waters verification

## Smart Contract Testing

Two separate Jupyter notebooks in `server/`:

- **`ztest.ipynb`** — tests `zecdsa.sol` (ECDSA signature verification + ETH payout) on Sepolia testnet
- **`ztest_htlc.ipynb`** — tests `zfairexchange.sol` (HTLC fair exchange with BN254 pairing verification) on Sepolia testnet
  - Fill in `private_key` (cell 1) and Alchemy URL (cell 2) before running
  - Requires the Flask server to be running (fetches Waters params from `/api/waters_solidity_params`)
  - Run cells in order: deploy → setup() → newContract() + withdraw()
  - `withdraw()` uses ~389k gas (BN254 pairing on-chain)

Both contracts deployed to Sepolia (chain ID `11155111`).

## RDelegate Crypto Notes

### beta_secret — bank master secret, must NOT leave the server

`beta_secret` (β) is the Waters IBE master secret. Only the bank/server holds it. Anyone with it can mint unlimited activation keys for any denomination and user.

**FIXED (August 2026):** `beta_secret` is no longer sent to Alice. The fix involved two parts:

1. **Removed the Waters IBE extra layer** from the garbled circuit. The original code added `aon_key ^= SHA3(rand_m_t)` where `rand_m_t` was Waters-IBE-encrypted (requiring `beta_secret` to decrypt). This layer was unnecessary — `aon_key = XOR(ECDH_shares)` alone is sufficient because AndroidKeyStore `nusecount` enforces one-timeness at the hardware level. The `rtag` field was deleted from `PaymentBox`; `garble_waters` and the server-side `garble_redelegate` no longer produce it; `evaluate_paymentbox` no longer calls `water_decrypt`.

2. **Stripped `beta_secret` from the server response.** In `server.py`, `/api/delegatedpresig` does `params_public.pop('beta_secret', None)` before returning `params` to Alice. The server still holds `beta_secret` internally for use by `garble_waters` and `generate_gs`.

**Android `ParamWaters` struct:** `beta_secret` field kept with `#[serde(default)]` so it deserializes as zero (ScalarField default) when absent. `evaluate_paymentbox` never reads this field — it uses `msk = g^(α·β)` pre-embedded in `sig_1_hprime_masked`. The field exists only so `water_decrypt` and `garble_redelegate` (dead-code ECDSA/Option-B paths, not exposed in UI) compile without restructuring.

**Server-side test:** `python3 -c "from server import test_redelegate_full; test_redelegate_full()"` — verifies recipient's Waters key passes both pairing checks.

### Paper's RDelegate — no beta_secret needed

From the paper, `RDelegate(osk, sk_D, tag2)` works as follows:

- `osk` contains the **original garbled circuit** (GWat, GS components), not just `(sk1,sk2,sk3)`
- `sk_D` is Alice's **AndroidKeyStore private key** (the same key used during Activate)
- Alice re-evaluates her **own garbled circuit** at **Bob's tag bits** using ECDH with `sk_D`

The algorithm (from paper):
1. Parse `GS` → get `(pkS,1, cS,1)` and `(pk_{i,0}, c_{i,0}, pk_{i,1}, c_{i,1})` for each bit position
2. `K_{S,1} ← nUKE.Shared(sk_D, pkS,1)` — ECDH with AndroidKeyStore key → decrypt branch secret `a_{S,1}`
3. For each bit `i` of Bob's tag: `K_{i,btag_i} ← nUKE.Shared(sk_D, pk_{i,btag_i})` → decrypt `(a_i, b_{i,btag_i})`
4. Compute `a_tag := H2(r_tag)`, combine shares → `a`, then derive `dk1, dk2, dk3`
5. Return `ak2 = (dk1, dk2, dk3)` — Bob's Waters activation key (~128 bytes, fits in QR)

**Key insight:** The bank's garbled circuit supports evaluation at ANY tag input. Alice re-evaluates it along Bob's tag path, using different ECDH slots than her own activation used. No `beta_secret` needed — the circuit's structure handles the key derivation.

**One-shot enforcement:** Alice's AndroidKeyStore key has `nusecount` budget. Activate uses slots for Alice's tag bits; RDelegate uses the remaining slots for Bob's tag bits. After both, the key is exhausted — Alice cannot re-delegate twice.

**Fixed:** The GS circuit (`gs_circuit` field on `DelegatedData`) is now stored on the card and used for offline re-delegation via `evaluate_gs()`. `beta_secret` is no longer transmitted in `params` — see "beta_secret" section above for the full fix details.

### GS Circuit — structure and generation

GS is a second garbled structure generated by the bank alongside GWat. It is stored on Alice's card and consumed during RDelegate.

**GS structure:**
```
GS = {
  branch: { epk_s: [u8; 33], c_s: [u8; 32] },           // 1 branch slot
  slots:  [{ epk_0: [u8;33], c_0: [u8;32],               // per bit of tag
              epk_1: [u8;33], c_1: [u8;32] }; TAG_BITS]  // TAG_BITS = 56 for "UUU_DDD"
}
```

**Size:** 1 branch + 56 bit-slots × 2 keys each = 113 EC pubkeys (33B each) + 113 ciphertexts (32B each) ≈ **7.3 KB**. Included in the server response and stored on the card.

**Generation (server-side, inside `garble_waters`):**

The bank generates GS alongside GWat by:

1. Generate a fresh Waters key for Alice's tag: `(dk1, dk2, dk3)` with randomness `r`
2. Split `dk1` into `p'_0 · p'_1 · … · p'_{ℓ_m}` (multiplicative shares in G1); split `dk2, dk3` into additive shares `c_{γ,1}, c_{γ,2}` masked with `H2(a)` where `a` is a random secret
3. **Branch slot:** generate ephemeral EC keypair `(esk_S, epk_S)`, compute ECDH with Alice's AndroidKeyStore pubkey → `K_S`, encrypt `a_S := H2(K_S) ⊕ a_S_share`
4. **Per bit i:** generate two ephemeral EC keypairs `(esk_{i,0}, epk_{i,0})` and `(esk_{i,1}, epk_{i,1})`; compute ECDH with Alice's pubkey → `K_{i,0}, K_{i,1}`; encrypt: `c_{i,0} = H2(K_{i,0}) ⊕ (a_i || b_{i,0})`, `c_{i,1} = H2(K_{i,1}) ⊕ (a_i || b_{i,1})`
   - `a_i` are XOR shares of the master secret `a` (one per bit position)
   - `b_{i,b}` selects the correct `p'_i` share for bit value b
5. Return `GS = {branch: (epk_S, c_S), slots: [(epk_{i,0}, c_{i,0}, epk_{i,1}, c_{i,1})]}`

**RDelegate evaluation (Alice's phone, offline):**

1. Alice does ECDH(`sk_D`, `epk_S`) → `K_S` → decrypts `a_S`
2. For each bit `btag_i` of Bob's tag: ECDH(`sk_D`, `epk_{i,btag_i}`) → `K_{i,btag_i}` → decrypts `(a_i, b_{i,btag_i})`
3. `a = XOR(a_i) ⊕ a_tag` where `a_tag = H2(r_tag)` (r_tag comes from GWat)
4. `dk2 = H2(a||1) ⊕ c_{γ,1}`, `dk3 = H2(a||2) ⊕ c_{γ,2}`, `dk1 = p'_0 · ∏ p'_i[b_{i,btag_i}]`
5. Return `ak2 = (dk1, dk2, dk3)` — valid Waters key for Alice's tag (same tag, fresh randomness `r`)

**nUKE budget:** TAG_BITS = 56 bits → 56 ECDH ops for RDelegate + 1 branch = 57 ops. Activate uses `garble_message_size = 5` ops. Total = 62. App requests `nusecount=64`; server allowlist in `verify_attestation` includes 64. GWat still uses 5 positions × 256 items regardless of nusecount.

**Status: IMPLEMENTED AND TESTED END-TO-END.** Alice mints → offline re-delegates to Bob via QR (57 AndroidKeyStore ECDH ops, no server contact) → Bob withdraws on-chain. Server contacted exactly twice: once at Mint (Alice) and once at Withdraw (Bob). All code changes below are done:
- `server/rustcode/src/lib.rs`: `generate_gs()` PyO3 function generates and returns GS JSON
- `server/server.py`: `getpresig_fn` calls `generate_gs()` for nusecount=64 requests; response includes `gs_circuit`; nusecount=64 added to allowlist
- `paymentbox_otp/.../DelegatedData.kt`: `gs_circuit: String = ""` field added; `TestData` has `gs_circuit: Any?`
- `paymentbox_otp/.../PaymentBoxAdapter.kt`: stores `watersData.gs_circuit` (Gson-serialized) on card; requests nusecount=64
- `paymentbox_otp/app/rust/src/lib.rs`: `Java_..._evaluateGs` JNI wrapper added
- `paymentbox_otp/app/rust/src/paymentbox/pbcrypto.rs`: `evaluate_gs()` implemented; `hex` crate added to Cargo.toml

### Demo flow: offline re-delegation (IMPLEMENTED)

**Step 1 — Bob gets identity QR (one-time, offline)**
- Bob opens app → first-launch dialog asks for account name (e.g. "Bob") → account created, toolbar shows "ORBIT — Bob"
- Bob taps **My ID** → first use prompts for user_id → stores `uid` as Int in `orbit_identity_Bob` prefs → shows identity QR: `{"uid":2}`
- Subsequent presses of **My ID** show the stored QR immediately (title: "Bob — uid 002")

**Step 2 — Alice mints (online)**
- Alice taps Mint FAB → picks denomination → app requests nusecount=64 attestation
- Server garbles GWat (5 positions) + GS circuit (57 ECDH slots for re-delegation) → calls `newContract()` → returns `{epk, params, msg, contract_id, denomination, gs_circuit}`
- App does 5 ECDH ops (GWat evaluation) → `paymentbox()` JNI → recovers `(sk1, sk2, sk3)`
- Card stored with `gs_circuit` field intact — ready for offline re-delegation

**Step 3 — Alice re-delegates to Bob (fully offline, no server needed)**
- Alice selects card → taps **Re-delegate** → `gsRedelegateLauncher` opens camera (GS path; legacy path for cards without `gs_circuit` falls back to direct QR)
- Alice scans Bob's identity QR `{"uid":2}` → app constructs GS evaluation tag as `"%03d_%03d".format(bobId.uid, card.denomination)` (e.g. `"002_001"` for a 1C coin to uid 2)
- `computeGsAk2(card, bobTag)` runs: 57 sequential AndroidKeyStore ECDH ops against GS epk → `evaluateGs()` JNI → `ak2 = (dk1, dk2, dk3)` — **fully offline, no server contact**
- App shows **re-delegation QR** (title: "Alice → uid 002", body: "1 C transfer key"): `{sk1: ak2.sk1, sk2: ak2.sk2, sk3: ak2.sk3, contract_id: alice_original_contract_id, denomination}` ✓
- Alice's card removed (one-shot enforced)
- **No new HTLC needed:** ak2 is a fresh valid Waters key for the same `tag=denomination`, so Bob can call `/api/pay` directly against Alice's original `contract_id`. The `withdraw()` function only verifies the Waters equations — it doesn't care who generated the key.

**Step 4 — Bob receives card (offline)**
- Bob taps **Scan** → scans Alice's re-delegation QR → `addCardFromQR()` creates card with `{sk1, sk2, sk3, contract_id_bob, denomination}`
- Bob's card appears in grid; `gs_circuit = ""` (Bob uses the key directly, no further GS needed)

**Step 5 — Bob withdraws (online)**
- Bob selects card → taps **Withdraw** → POSTs `{sk1,sk2,sk3,contract_id,denomination}` to `/api/pay` → Sepolia withdraw → TX hash dialog → card removed

**One-phone demo:** Use screenshot QR workflow — Alice shows re-delegation QR, screenshot it, open on laptop screen, Bob presses Scan and scans the laptop screen.

**Fixed — beta_secret:** `beta_secret` is no longer sent to Alice. See "beta_secret — bank master secret" section above for full details.

**Known remaining gap — tag encoding mismatch:** There are THREE different tag-to-group-element computations in the codebase that must agree for an end-to-end Waters key to pass the on-chain pairing check:
1. `h_of_id()` (server Rust, line ~252): iterates the tag as a **string**, decomposing each ASCII byte bit-by-bit into `h_vec` indices.
2. `water_unlock_solidity()` (server Rust, line ~286): treats the tag as an **integer**, decomposing its bits into `h_vec[0..40]` indices.
3. `hashlockMatches` in `zfairexchange.sol` (line 224): integer bit-decomposition of `hashlock` — matches `water_unlock_solidity`.

`garble_waters` uses `h_of_id` (path 1) to generate the circuit and the on-chain pairing uses `hashlockMatches` (path 3). For the tag `"000_001"` (UUU_DDD string), `h_of_id` and `water_unlock_solidity` compute entirely different group elements. This means:
- Alice's evaluated `(sk1,sk2,sk3)` from the garbled circuit is keyed to `H_ascii("000_001")` — it will NEVER pass the on-chain BN254 pairing check (which expects `H_int(1)`).
- Bob's `ak2` from `evaluate_gs()` is also keyed to `H_ascii(bob_tag)` — it will NEVER pass either.
- `/api/pay` therefore uses `water_unlock_solidity(denomination)` to produce the server's own Waters key (paths 2 = 3), ignoring the user-submitted `sk1/sk2/sk3`.

**Fix (not yet implemented):** Change `denomination_config` to pass `tag = denomination` as an integer to `h_of_id` by changing `h_of_id` to accept a raw integer OR changing the garbled circuit to use integer bit-decomposition instead of string byte decomposition. Also change `generate_gs` to use integer-based tag bits. Then `computeGsAk2` on Android must pass `denomination` as a single-byte tag (not the `"%03d_%03d"` string). After this fix, Alice/Bob's evaluated keys can be submitted directly to `/api/pay` without the server re-generating its own key. The `UUU_DDD` display on tiles is purely cosmetic and does not need to change.

## Current Status

Waters-only dmk architecture is implemented end-to-end.

### UI Layout

**ActionBar**: shows "ORBIT — AccountName". Overflow menu (⋮) → "Switch account" (shows list of accounts + "＋ New account") / "New account". First launch shows a create-account dialog before any cards load.

Cards are displayed as a **2-column grid** of 160dp square tiles (`GridLayoutManager(2)`). Each tile shows **coin art** (1 gold coin icon for 1C, 2 stacked gold coin icons for 2C) on a fixed dark blue-grey background (`#37474F`, `MaterialCardView`), with:
- denomination label ("1 C" / "2 C") in bold below the coin(s)
- identity tag in monospace muted text below that, formatted `UUU_DDD_CCC` (current account's user_id padded 3 + `_` + denomination padded 3 + `_` + `coinIndex` padded 3, from `orbit_identity_AccountName` prefs; shows `000_DDD_CCC` if no identity registered). `CCC` is a 0-based, monotonically-increasing, per-account-per-denomination sequence number assigned once at mint time (`nextCoinIndex()`, persisted in `orbit_coin_counters_$account`) — it never changes when a coin is later spent/deleted, and is purely cosmetic (structurally independent from the cryptographic `bobTag` used in GS re-delegation, see `computeGsAk2()` below).
- first 8 chars of `contract_id` in the top-right corner ("no HTLC" if empty)

All card tiles are uniform colour — no cycling. Tapping a tile selects it (white stroke border via `MaterialCardView.strokeColor`); tapping again deselects. **Long-press a tile → "Delete token?"** removes the card without paying (for dead/no-HTLC cards). Note: use `adapterPosition`, not `bindingAdapterPosition` — the project's RecyclerView is too old for the latter.

Coin art is `res/drawable/ic_coin.xml` — a gold vector drawable (dark-gold rim `#B8860B`, bright-gold face `#FFD700`, "C" arc). For 2C, a second `ImageView` (`coin2`) overlaps coin1 by 5dp via negative `marginStart`; it is `GONE` for denomination < 2 and `VISIBLE` otherwise.

Two **`ExtendedFloatingActionButton`**s sit side-by-side at the bottom-right corner above the action bar, inside a wrapping `LinearLayout` (`activity_main.xml`) so they auto-space regardless of label width:
- **Checks** (purple `@color/purple_500`, `ic_badge_24` icon) — opens `showChecksDialog()`, letting the user edit per-denomination Sync targets after account creation (see Dormant Stock section above). Placed to the left of Mint.
- **Mint** (blue `@color/blue_500`, 64dp tall, `+` icon) — tapping it shows a `ListPopupWindow` anchored to the FAB — half the screen wide, with a rounded corner background (`res/drawable/dropdown_bg.xml`, 14dp radius) — listing available denominations. Each row shows coin image(s) + bold denomination label + muted ETH price + live dormant-stock count ("Nx"). Selecting a row calls `activateOrMint(denomination)`, not a direct mint. The placeholder item that previously occupied the last grid slot has been removed; `dataset.removeAll { it.hiding_sign_vec2.isEmpty() }` strips it on load so old saved data migrates cleanly.

A **fixed bottom action bar** (`#263238`) contains four `MaterialButton`s with icons:
- **Withdraw** (dark green `#2E7D32` when active, grey when inactive, `ic_payments_24` icon) — POSTs Waters key to `/api/pay`; greyed out when nothing selected
- **Re-delegate** (purple `purple_500` when active, grey when inactive, `ic_share_24` icon) — if card has `gs_circuit`: opens camera to scan Bob's identity QR → offline GS evaluation → shows re-delegation QR; otherwise legacy direct QR flow. Card consumed on dismiss. Greyed out when nothing selected.
- **Scan** (teal `teal_700`, `ic_qr_code_scanner_24` icon) — always active; opens ZXing scanner → `addCardFromQR()` parses `{sk1,sk2,sk3,contract_id,denomination}`
- **My ID** (indigo `#5C6BC0`, `ic_badge_24` icon) — always active; first tap prompts for user_id and saves it as `uid` (Int) to `orbit_identity_AccountName` prefs; subsequent taps show identity QR `{"uid":N}` (title: "AccountName — uid NNN")

Buttons use `app:backgroundTintList` (not `setBackgroundColor`) on `MaterialButton` with `app:icon` / `app:iconTint`. `updateBottomBarState()` swaps `backgroundTintList` between active colour and grey — buttons always visible, never hidden.

### Actions
- **Checks FAB** → `showChecksDialog()` → per-denomination `[−] target [+]` rows, editing `orbit_targets_$account` in place; "Sync now" button triggers the same fill-the-deficit flow as the overflow menu's Sync
- **Mint FAB** → `ListPopupWindow` dropdown (denomination + ETH price + dormant "Nx" count) → user picks denomination → `activateOrMint()`: promotes an existing dormant dmk via `/api/lock` if stock exists, else mints+locks fresh via `/api/delegatedpresig` (garbles Waters circuit nusecount=64 + GS circuit + calls `newContract()` on Sepolia) → `(sk1, sk2, sk3)` + `contract_id` + `denomination` + `gs_circuit` + `coinIndex` stored as "Signing Token #N" card
- **Withdraw** → POSTs `{sk1,sk2,sk3,contract_id,denomination}` to `/api/pay` → server calls `withdraw()` on Sepolia → success dialog with TX hash → card removed on OK
- **Re-delegate** (GS path, cards with `gs_circuit`): opens `gsRedelegateLauncher` camera → scan recipient's identity QR `{"uid":N}` → constructs `bobTag = "%03d_%03d".format(uid, denomination)` → `computeGsAk2()` does 57 AndroidKeyStore ECDH ops (offline, no server) → `evaluateGs()` JNI → ak2 → QR dialog (title: "Alice → uid NNN") with `{sk1,sk2,sk3,contract_id: alice_original,denomination}`; card removed on dismiss. Bob withdraws from Alice's original HTLC using ak2 — no new HTLC needed.
- **Re-delegate** (legacy path, cards without `gs_circuit`): POSTs `{contract_id,denomination}` to `/api/redelegate` directly → QR dialog with stored `{sk1,sk2,sk3,contract_id_bob,denomination}`
- **Scan** → ZXing scanner → `addCardFromQR()` → new card with `hardcodedParams`, scanned `contract_id` (or `""` if absent), `denomination` (or 1 if absent), `gs_circuit = ""`
- **My ID** → shows identity QR `{"uid":N}` for current account (namespaced to `orbit_identity_AccountName` prefs); first use prompts for user_id and stores as Int under key `"uid"`
- **Long-press tile** → delete card without withdrawing (cleanup for dead/no-HTLC cards)
- One-timeness enforced: Withdraw, Re-delegate, and Scan-then-Withdraw each consume the card exactly once

### Logcat debugging
Filter by tags `PaymentBoxAdapter` / `MainActivity`. Every `contract_id` hop is logged: circuit received, card stored, Pay pressed, Redelegate (Alice's + Bob's IDs), card added from QR. Match these against the server console `[NEW]`/`[REDELEGATE]`/`[PAY]` lines to see where an ID gets lost.

ECDSA variant (`/api/delegatedpresigecdsa`, `paymentboxecdsa()` JNI, `zecdsa.sol`) is fully implemented in the server and JNI but not exposed in the current UI.

### QR / Scan Dependencies
- `app/build.gradle.kts`: `com.journeyapps:zxing-android-embedded:4.3.0`
- `AndroidManifest.xml`: `CAMERA` permission
- `res/raw/waters_params.json`: bundled params (30 KB, deterministic)
- `MainActivity.kt`: `hardcodedParams`, `qrScanLauncher` (receives payment QR), `gsRedelegateLauncher` (receives Bob's identity QR during Re-delegate), `addCardFromQR()`, `generateQrBitmap()`, `updateBottomBarState()`, `computeGsAk2()` (57 ECDH ops + evaluateGs JNI), `callRedelegateHtlcOnly()` (POSTs contract_id/denomination only); `initWithAccount()` (loads data + sets RecyclerView), `switchToAccount()`, `showSwitchAccountDialog()`, `showCreateAccountDialog()`; `onCreateOptionsMenu`/`onOptionsItemSelected` inflate `R.menu.main_menu`; `activateOrMint()`/`callLock()` (promote dormant→live via `/api/lock`); `showChecksDialog()` (edit Sync targets); `showSyncDialog()`/`performSync()` (batch-mint dormant stock via `/api/replenish`); `loadTargets()`/`saveTargets()` (`orbit_targets_$account`); `nextCoinIndex()`/`loadCoinCounters()`/`saveCoinCounters()` (`orbit_coin_counters_$account`, per-denomination mint sequence for the tile tag)
- `external fun evaluateGs(gsCircuit, bobTag, sharedKeys)` — JNI into `librust.so`; `evaluate_gs()` in `pbcrypto.rs`
- `res/menu/main_menu.xml`: overflow menu with "Switch account" and "New account" items
- `res/drawable/ic_badge_24.xml`: badge icon for My ID button
- `res/drawable/selection_ring.xml`: unused shape drawable (leftover from prior approach; stroke is now set via `MaterialCardView.strokeColor`)

### adb / networking
- USB tunnel (recommended): `adb reverse tcp:5000 tcp:5000` — routes phone's `127.0.0.1:5000` → WSL. Re-run after every USB reconnect or phone reboot. adb is at `C:\Users\<name>\AppData\Local\Android\Sdk\platform-tools\adb.exe`.
- WiFi fallback: Windows port-proxy `netsh ...` → WSL IP. WSL IP changes on restart (`hostname -I`).

NDK note: Linux NDK r23b is downloaded to `/tmp/android-ndk-r23b` during the WSL session (not persistent — re-download on reboot with the command in the recompile section above). The Windows NDK in `AppData/Local/Android/Sdk/ndk/23.1.7779620/` has only Windows binaries and cannot cross-compile from WSL.

## Possible Next Steps

- **Multi-account / persona system**: **IMPLEMENTED**. First-launch "Create wallet" dialog, toolbar title "ORBIT — AccountName", overflow menu ⋮ → Switch/New account. Cards stored in `SAVE_AccountName` SharedPreferences; identity tags in `orbit_identity_AccountName`. Coin tiles show `UUU_DDD` tag (account user_id + denomination). Accounts list stored in `ORBIT_META` prefs. Note: existing cards saved under the old `"SAVE"` key are not migrated — users must re-mint after first account creation.
- **Fix tag encoding mismatch**: `h_of_id` (ASCII string bits) ≠ `water_unlock_solidity` / contract (integer bits). Fix by switching `garble_waters`, `generate_gs`, and Android's `computeGsAk2` to use integer denomination as the tag. After this, user-submitted `(sk1,sk2,sk3)` can be sent directly to `/api/pay` instead of the server re-generating its own key. See "tag encoding mismatch" gap note above.
- **Strip `beta_secret` from params**: **DONE (August 2026)**. Waters IBE extra layer removed from the garbled circuit; server strips `beta_secret` from `params` before transmitting. See "beta_secret — bank master secret" section for full details.
- **`decompress_waters_key` Rust function**: already implemented in `server/rustcode/src/lib.rs` (takes compressed hex sk1/sk2/sk3 → returns affine decimal JSON matching `water_unlock_solidity` format). Not currently used in production `/api/pay` because of the tag encoding mismatch — would produce the correct format but wrong group elements. Will become useful after the tag encoding fix.
- **Full paper Pay flow**: Replace the current `zfairexchange.sol` Withdraw with `DSign` → `zecdsa.sol`. Blocked by the curve mismatch (circuit is secp256r1, `ecrecover` is secp256k1) — see "zecdsa.sol blockers" above. A plan exists (plan file `so-all-of-this-breezy-lampson.md`): Option C (server proxy-signs with its secp256k1 key after verifying the card's `(r,s)`) as demo shortcut; Option A (rewrite Rust circuit to secp256k1) for the real fix.
- **Correct purchase flow** (`zfairexchange.sol` as designed): Alice locks ETH → bank reveals Waters key on-chain (atomic swap). Currently the server self-funds both sides; a real deployment needs Alice's Ethereum wallet on the phone.
- **ECDSA variant in UI**: Re-expose the "New (ECDSA)" path as a separate card type; would use `callToken_ecdsa()` + `paymentboxecdsa()` + `zecdsa.sol`.
