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
- `GET /api/delegatedpresigecdsa?attestation=...` — verifies Android attestation, returns garbled circuit `{epk, params, msg}`
- `GET /api/delegatedpresig?attestation=...` — same but Waters/REDELEGATE variant
- `GET /api/benchmarkdelegateecdsa?attestation=...` — runs 100 server-side benchmark iterations (heavy — avoid calling during normal use)
- `GET /api/verifyattest?attestation=...` — standalone attestation verification
- `GET /api/waters_solidity_params?id=<int>` — returns Waters params + signing key for given id in Solidity-compatible format (uncompressed integer coordinates); used by `ztest_htlc.ipynb`

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

## Use Phase Flow

### Pay (demo placeholder)
1. User taps "Pay" on a Signing Token card
2. Logcat: `PAYMENT ACCEPTED (demo)` — card removed from UI (dmk consumed, one-timeness enforced)
3. In a real deployment: submit `(sk1, sk2, sk3)` to `zfairexchange.sol` on Sepolia for on-chain Waters verification

### Re-delegate (fully offline — no server call)
1. User taps "Re-delegate" on a Signing Token card
2. `bindDmkCard` reads `hiding_sign` (params) and `hiding_sign_vec2` (sk1/sk2/sk3) from `dataSet[position]`
3. Packs `oskBytes = sk1(32B) || sk2(32B) || sk3(64B)` = 128 bytes
4. Generates recipient's software EC key pair (no attestation, no server)
5. Generates 1280 ephemeral secp256r1 key pairs; ECDH(eph_sk, recipientPub) → flat 40 KB shared-key array
6. Calls `garble_redelegate()` JNI → recipient's `PaymentBox` JSON
7. Recipient: picks random pattern, 5 ECDH ops against Alice's eph keys → `paymentbox()` JNI → `(sk1', sk2', sk3')` logged as `REDELEGATE SUCCESS!`
8. Alice's card removed (dmk consumed, one-timeness enforced)

## Key Data Structures

- `TestData` — server response: `{epk: base64url, params: JSON string, msg: JSON string}`
- `DelegatedData` — stored dmk card. For Waters tokens: `hiding_sign = params` (with `beta_secret`), `hiding_sign_vec2 = JSON(sk1, sk2, sk3)`, `r = part1 = BigInteger.ZERO`. `userName = "Signing Token #N"`.
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

Waters-only dmk architecture is implemented end-to-end:
- **"New"** → server issues Waters garbled circuit → Rust evaluates → `(sk1, sk2, sk3)` stored in "Signing Token" card
- **"Pay"** → demo placeholder: logs `PAYMENT ACCEPTED (demo)` → card disappears (dmk consumed)
- **"Re-delegate"** → fully offline: reads stored Waters key from card → `garble_redelegate()` → recipient evaluates → logs `REDELEGATE SUCCESS!` → card disappears (dmk consumed)
- One-timeness enforced: either action removes Alice's card; she cannot use the dmk twice

ECDSA variant (`/api/delegatedpresigecdsa`, `paymentboxecdsa()` JNI, `zecdsa.sol`) is fully implemented in the server and JNI but not exposed in the current UI.

NDK note: Linux NDK r23b is downloaded to `/tmp/android-ndk-r23b` during the WSL session (not persistent — re-download on reboot with the command in the recompile section above). The Windows NDK in `AppData/Local/Android/Sdk/ndk/23.1.7779620/` has only Windows binaries and cannot cross-compile from WSL.

## Possible Next Steps

- **Real Pay**: Submit `(sk1, sk2, sk3)` to `zfairexchange.sol` on Sepolia for on-chain Waters verification instead of the current log-only placeholder (`ztest_htlc.ipynb` has test scripts)
- **Recipient card**: After re-delegation, add the recipient's `(sk1', sk2', sk3')` as a new card for on-chain submission
- **Device-to-device transfer**: Wire up NFC/BLE to receive the recipient's actual public key and transmit the `PaymentBox` JSON instead of using an in-memory software key
- **ECDSA variant in UI**: Re-expose the "New (ECDSA)" path as a separate add-card for the faster direct-signing variant (no re-delegation); would use `callToken_ecdsa()` + `paymentboxecdsa()` + `zecdsa.sol`
- **Fair exchange** (`zfairexchange.sol`): Bank locks signing key in HTLC; phone receives it after payment
