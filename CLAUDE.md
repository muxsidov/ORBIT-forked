# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ORBIT is an academic research prototype for a **one-shot payment system** using garbled circuits and Waters IBE. The system has three phases matching the paper:

- **Issuance (offline prep)**: Bank issues a dormant key (dmk) — a garbled Waters IBE circuit — to Alice. The circuit is useless without evaluation.
- **Activation (requires server)**: Alice evaluates the circuit using her AndroidKeyStore private key via ECDH → recovers `(sk1, sk2, sk3)`, her Waters activation key. The dmk is now live and stored as a card.
- **Use (fully offline)**: Alice uses the dmk exactly once — either **Pay** (demo: log + remove card) or **Re-delegate** (offline: garble a new circuit for a recipient using stored `params` + `(sk1, sk2, sk3)`). Either action removes the card, enforcing one-timeness.

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
- `GET /api/delegatedpresig?attestation=...` — verifies Android attestation, garbles Waters circuit, calls `newContract()` on Sepolia (locks 0.01 ETH), returns `{epk, params, msg, contract_id}`
- `GET /api/delegatedpresigecdsa?attestation=...` — same but ECDSA variant (no blockchain call)
- `POST /api/pay` — body `{sk1, sk2, sk3, contract_id}` — calls `withdraw()` on `zfairexchange.sol`, returns `{tx_hash, contract_id}`
- `POST /api/redelegate` — body `{sk1, sk2, sk3, contract_id}` — withdraws Alice's HTLC (recovers her 0.01 ETH), then `newContract()` creates a fresh 0.01 ETH HTLC for Bob, returns Bob's `contract_id`. If Alice's `contract_id` is empty, the withdraw is skipped gracefully.
- `GET /api/waters_solidity_params?id=<int>` — returns Waters params + signing key for given id in Solidity-compatible format; used by `ztest_htlc.ipynb`
- `GET /api/benchmarkdelegateecdsa?attestation=...` — runs 100 server-side benchmark iterations (heavy — avoid during normal use)
- `GET /api/verifyattest?attestation=...` — standalone attestation verification

**Blockchain env vars** (required for `/api/delegatedpresig` and `/api/pay`):
```bash
export ETH_PRIVATE_KEY="<your Sepolia wallet private key>"
export ALCHEMY_URL="https://eth-sepolia.g.alchemy.com/v2/<your key>"
```
If not set, blockchain calls are skipped with a warning and `contract_id` is returned as `""`. Env vars are per-shell — they must be exported in the same terminal that runs `python3 server.py`.

**Sepolia transaction handling** (`_send_tx` in `server.py`):
- Nonce uses the `'pending'` block tag — prevents "replacement transaction underpriced" when sending sequential txs (e.g. `setup()` then `newContract()`).
- Gas price is **2x current** — bidding exactly the going rate leaves txs stuck in the mempool during Sepolia gas spikes.
- Receipt timeout is **300s** (web3 default 120s was too short during congestion).
- Server console logs: `[NEW]`, `[REDELEGATE]`, `[PAY]` lines print the `contract_id` for each on-chain action; `[WARN]` lines show skipped/failed calls.

**Stuck nonce queue:** If txs time out with "is not in the chain after N seconds", check for a nonce jam: compare `get_transaction_count(addr, 'latest')` vs `'pending'` — if pending > latest, old low-gas txs are blocking the queue (Ethereum mines nonces strictly in order; mempool evictions can also leave nonce *gaps* that block everything after them). Fix with `server/unstick.py`: it replaces each stuck/gapped nonce with a 0-ETH self-transfer at 5x gas (21k gas each). Run it with the env vars set; enter the highest stuck nonce when prompted.

**Gas economics** (0.01 ETH lock amount, set in both `newContract` calls in `server.py`):
- New: −0.01 locked + ~0.0013 gas
- Re-delegate: +0.01 recovered − 0.01 re-locked + ~0.0025 gas (withdraw ~389k gas + newContract)
- Pay: +0.01 recovered, ~0.0018 gas
- Full New → Re-delegate → Pay cycle: wallet loses only gas, ~0.0056 ETH. The lock amount must exceed gas (~0.001/tx) for the demo to look sensible; 0.00001 ETH (the original value) was dwarfed by gas.

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

1. `PaymentBoxAdapter` (`bindNewCard`) calls `mainAct.callToken(5)` (`RDelegateByteInstance`)
2. `callToken` creates `OneTimeMemory(5)` → generates EC key in AndroidKeyStore → gets attestation → GETs `/api/delegatedpresig`
3. Server: `verify_attestation()` validates certificate chain → `garble_waters()` generates 5×256=1280 ephemeral EC key pairs → returns `{epk, params, msg}`
4. App: 5 parallel ECDH ops using AndroidKeyStore private key → derives 5 shared secrets → calls `paymentbox()` JNI
5. Rust: `evaluate_paymentbox()` decrypts garbled circuit → recovers `(sk1, sk2, sk3)` (Waters activation key) → returns as `{"sk1":"<hex>","sk2":"<hex>","sk3":"<hex>"}`
6. Kotlin stores on `DelegatedData`: `hiding_sign = params` (contains `beta_secret`), `hiding_sign_vec2 = JSON(sk1, sk2, sk3)`, `r = part1 = BigInteger.ZERO`
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

## Use Phase Flow

### New (Activation + HTLC creation)
1. User taps the "New" tile
2. Server garbles Waters circuit → app evaluates → `(sk1, sk2, sk3)` recovered
3. Server also calls `newContract(server_wallet, tag=1, timelock)` → locks 0.01 ETH on Sepolia
4. `contract_id` (bytes32) returned in the response and stored on the card
5. Card appears in the grid — it represents the locked ETH

**Dead cards:** cards created without the blockchain env vars set, or whose `newContract` timed out, have `contract_id = ""` (tile shows "no HTLC"). They can never Pay. Long-press the tile → "Delete token?" to remove them. If a timed-out `newContract` mines later, the ETH is locked in an orphaned HTLC — recoverable via `refund()` after the 1-hour timelock.

### Pay (Waters key → Sepolia withdraw)
1. User selects a card, taps "Pay"
2. App shows "Submitting to Sepolia..." dialog
3. App POSTs `{sk1, sk2, sk3, contract_id}` to `/api/pay`
4. Server calls `withdraw(contract_id, {sk1,sk2,sk3})` — BN254 pairing verified on-chain
5. On success: dialog shows Sepolia TX hash → user presses OK → card removed
6. On failure: error dialog shown → card stays (dmk not consumed)

### Re-delegate (Option A: server creates new HTLC for recipient)
1. User selects a card, taps "Re-delegate"
2. App POSTs `{sk1,sk2,sk3,contract_id}` to `/api/redelegate` → server **withdraws Alice's HTLC** (recovers her 0.01 ETH), then calls `newContract(tag=1, timelock)` → locks 0.01 ETH in a fresh HTLC → returns `contract_id` for Bob. Net wallet change: gas only (~0.0025 ETH).
3. App builds QR JSON: `{"sk1":"...","sk2":"...","sk3":"...","contract_id":"..."}` (Bob's dedicated HTLC included)
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
4. Bob's card uses `hardcodedParams` (loaded from `res/raw/waters_params.json`) as `hiding_sign` — scanned cards have no `contract_id` (no HTLC was created for Bob)

**Why `params` is not in the QR:** `ParamWaters` JSON is ~30 KB (8,192 bytes of h_vec curve points that resist compression); QR max is ~3 KB. Instead, `waters_params.json` is bundled as a raw resource — safe because `generate_params_waters()` uses `ark_std::test_rng()` (fixed seed), so params are **identical on every server restart** and never need to be transmitted.

## Key Data Structures

- `TestData` — server response: `{epk: base64url, params: JSON string, msg: JSON string, contract_id: hex string}`
- `DelegatedData` — stored dmk card. For Waters tokens: `hiding_sign = params` (with `beta_secret`), `hiding_sign_vec2 = JSON(sk1, sk2, sk3)`, `contract_id = bytes32 hex of the HTLC on Sepolia`, `r = part1 = BigInteger.ZERO`. `userName = "Signing Token #N"`. Scanned cards from QRs without `contract_id` have `contract_id = ""`.

**Gson null gotcha:** Gson ignores Kotlin default values — a missing JSON field lands as `null` in a non-null `String = ""` field, crashing later with `NullPointerException: parameter contract_id` (e.g. in `DelegatedData.copy`). Always guard parsed fields with `?: ""` (`addCardFromQR()` and `bindNewCard` both do this).
- `PersistencyManager` — SharedPreferences-backed store; `data` ArrayList is shared with the adapter
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

Alice can re-delegate her activation key to a recipient without the server. The full round-trip is tested in `server/server.py::test_redelegate_full()`.

**Key enabler:** `ParamWaters` serialized in `params` includes `beta_secret` (the Waters master secret scalar), so Alice can derive valid Waters keys for any identity without calling the server. This is why `params` must be stored on the card at activation time.

**Key crypto:** `water_encrypt` / `water_decrypt` in both Rust codebases are generalized to any `u8` tag via `h_of_id(param, id)`. Alice's circuit uses tag=1; recipient's circuit uses tag=2.

**Server-side test:** `python3 -c "from server import test_redelegate_full; test_redelegate_full()"` — verifies recipient's Waters key passes both pairing checks.

**osk packing:** `garble_redelegate()` expects `osk = sk1(32B) || sk2(32B) || sk3(64B)` = 128 bytes total (G1=32B compressed, G2=64B compressed on BN254).

## Current Status

Waters-only dmk architecture is implemented end-to-end.

### UI Layout

Cards are displayed as a **2-column grid** of 160dp square tiles (`GridLayoutManager(2)`). Each tile shows **"1 C"** (one coin) in large centered white text on a colored background (`MaterialCardView`), plus the first 8 chars of its `contract_id` in the top-right corner ("no HTLC" if empty — swap this label for a denomination later in `bindDmkCard`). The last tile is always the **"New"** tile (server activation, fixed blue). Tile colors are keyed to the card's creation index (`balance % colorArr.size`), not grid position, so colors stay stable as cards are added/removed. Tapping a tile selects it (white stroke border via `MaterialCardView.strokeColor`); tapping again deselects. **Long-press a tile → "Delete token?"** removes the card without paying (for dead/no-HTLC cards). Note: use `adapterPosition`, not `bindingAdapterPosition` — the project's RecyclerView is too old for the latter.

A **fixed bottom action bar** contains three buttons:
- **Pay** (black) — removes the selected card; logs `PAYMENT ACCEPTED (demo)`; greyed out when nothing selected
- **Re-delegate** (purple) — shows a QR bitmap of the selected card's `{sk1, sk2, sk3}`; card consumed on dialog dismiss; greyed out when nothing selected
- **Scan** (teal) — always active; opens ZXing scanner to add a card by scanning a QR

### Actions
- **"New" tile** → server garbles Waters circuit + calls `newContract()` (0.01 ETH) on Sepolia → Rust evaluates → `(sk1, sk2, sk3)` + `contract_id` stored as "Signing Token #N" card
- **Pay** → POSTs `{sk1,sk2,sk3,contract_id}` to `/api/pay` → server calls `withdraw()` on Sepolia → success dialog with TX hash → card removed on OK
- **Re-delegate** → POSTs `{sk1,sk2,sk3,contract_id}` to `/api/redelegate` (withdraws Alice's HTLC + creates Bob's) → QR dialog with `{sk1, sk2, sk3, contract_id}`; card removed on dismiss (dmk consumed). Full `garble_redelegate()` crypto is parked — see Re-delegate section above.
- **Scan** → ZXing scanner → `addCardFromQR()` → new card with `hardcodedParams` and the scanned `contract_id` (or `""` if the QR lacks one)
- **Long-press** → delete card without paying (cleanup for dead cards)
- One-timeness enforced: Pay, Re-delegate, and Scan-then-Pay each consume the card exactly once

### Logcat debugging
Filter by tags `PaymentBoxAdapter` / `MainActivity`. Every `contract_id` hop is logged: circuit received, card stored, Pay pressed, Redelegate (Alice's + Bob's IDs), card added from QR. Match these against the server console `[NEW]`/`[REDELEGATE]`/`[PAY]` lines to see where an ID gets lost.

ECDSA variant (`/api/delegatedpresigecdsa`, `paymentboxecdsa()` JNI, `zecdsa.sol`) is fully implemented in the server and JNI but not exposed in the current UI.

### QR / Scan Dependencies
- `app/build.gradle.kts`: `com.journeyapps:zxing-android-embedded:4.3.0`
- `AndroidManifest.xml`: `CAMERA` permission
- `res/raw/waters_params.json`: bundled params (30 KB, deterministic)
- `MainActivity.kt`: `hardcodedParams`, `qrScanLauncher` (ZXing `ScanContract`), `addCardFromQR()`, `generateQrBitmap()`, `updateBottomBarState()`
- `res/drawable/selection_ring.xml`: unused shape drawable (leftover from prior approach; stroke is now set via `MaterialCardView.strokeColor`)

NDK note: Linux NDK r23b is downloaded to `/tmp/android-ndk-r23b` during the WSL session (not persistent — re-download on reboot with the command in the recompile section above). The Windows NDK in `AppData/Local/Android/Sdk/ndk/23.1.7779620/` has only Windows binaries and cannot cross-compile from WSL.

## Possible Next Steps

- **Full paper Pay flow**: Replace the current `zfairexchange.sol` Pay with `DSign` → `zecdsa.sol`. Blocked by the curve mismatch (circuit is secp256r1, `ecrecover` is secp256k1) — see "zecdsa.sol blockers" above. A plan exists (plan file `so-all-of-this-breezy-lampson.md`): Option C (server proxy-signs with its secp256k1 key after verifying the card's `(r,s)`) as demo shortcut; Option A (rewrite Rust circuit to secp256k1) for the real fix.
- **Option B re-delegation** (full paper crypto): Replace Option A with `garble_redelegate()` producing a new circuit for Bob (tag=2 → distinct Waters key). Requires: (1) BLE/NFC to receive Bob's device public key on Alice's phone, (2) Alice calls `garble_redelegate(osk, bob_pub, tag=2)` locally, (3) transmits new garbled circuit + new HTLC `contract_id` to Bob via server relay or BLE (QR too small at ~42 KB). Also requires recompiling `librust.so` with any JNI changes.
- **Correct purchase flow** (`zfairexchange.sol` as designed): Alice locks ETH → bank reveals Waters key on-chain (atomic swap). Currently the server self-funds both sides; a real deployment needs Alice's Ethereum wallet on the phone.
- **ECDSA variant in UI**: Re-expose the "New (ECDSA)" path as a separate card type; would use `callToken_ecdsa()` + `paymentboxecdsa()` + `zecdsa.sol`.
- **Multiple denominations**: Use the Waters tag as denomination (tag=1/2/5/10/20 ↔ ETH amounts). The crypto already supports any `u8` tag (`h_of_id`, `water_encrypt`), but `garble_waters` hardcodes `tag = 1` at `server/rustcode/src/lib.rs:421` — add a `tag: u8` parameter there (2-line Rust change + `maturin develop --release` rebuild), pass `?tag=N` from the app, use `hashlock = tag` and a `DENOM_ETH` map in `server.py` (`water_unlock_solidity(params, tag)` already takes the id). UI needs a denomination picker and tile label.
