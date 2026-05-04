# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ORBIT is an academic research prototype for a **one-shot payment system** using garbled circuits and ECDSA. The system has two phases:
- **Offline phase**: Bank server verifies Android hardware attestation, generates a garbled ECDSA signature circuit, phone evaluates it using its AndroidKeyStore private key via ECDH to recover `(r, s)`
- **Online phase**: Phone presents `(r, s)` for payment; verifier checks against bank's public key — no server needed at payment time

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

**Variant config:** The active variant is set in `PaymentBoxAdapter.kt` via `VariantConfig.SignByteInstance()` → `count=32, wordSize=8, MAX_ITEM=256` (byte variant, ECDSA path). The REDELEGATE (Waters signature) path requires `waters.rs` which is missing from the server Rust codebase.

### Android Rust JNI (`paymentbox_otp/app/rust/`)

Cross-compiled for Android (`aarch64-linux-android`, `armeabi-v7a`). Key files:
- `src/lib.rs` — JNI entry points: `paymentboxecdsa()`, `paymentbox()`, `rust_init()`, `test()`
- `src/paymentbox/pbcrypto.rs` — `evaluate_ecdsa()` (garbled circuit evaluation) and `evaluate_paymentbox()` (Waters variant)

`evaluate_ecdsa()` returns `(Vec<u8>, Vec<u8>)` — compressed serialized `r` and `s` scalars via `CanonicalSerialize`. The JNI wrapper serializes them as `{"r":"<hex>","s":"<hex>"}`.

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

## Architecture: Offline Phase Flow

1. `PaymentBoxAdapter` (Add/`+` button) calls `mainAct.callToken_ecdsa(32)`
2. `callToken_ecdsa` creates `OneTimeMemory(32)` → generates EC key in AndroidKeyStore → calls `getAttestation()` → POSTs to `/api/delegatedpresigecdsa`
3. Server: `verify_attestation()` validates certificate chain → `garble_ecdsa()` generates 32×256=8192 ephemeral EC key pairs → returns `{epk, params, msg}`
4. App: 32 parallel ECDH ops using AndroidKeyStore private key → derives 32 shared secrets → calls `paymentboxecdsa()` JNI
5. Rust: `evaluate_ecdsa()` decrypts garbled circuit using ECDH secrets → recovers `(r, s)` → verifies → logs "Siganture OK" → returns `(r_bytes, s_bytes)`
6. JNI wrapper serializes to `{"r":"<hex>","s":"<hex>"}` → Kotlin parses → stores in `DelegatedData.r` / `DelegatedData.part1`
7. Card added to RecyclerView

## Online Phase Flow

1. User taps payment card in RecyclerView
2. `PaymentBoxAdapter` (consume path) POSTs `{"r":"<hex>","s":"<hex>"}` to `<urlDest>api/verifypayment`
3. Server checks `used_signatures` set → accepts first use, rejects replay
4. Card removed from UI on success

## Key Data Structures

- `TestData` — server response: `{epk: base64url, params: JSON string, msg: JSON string}`
- `DelegatedData` — stored payment token; `r: BigInteger` and `part1: BigInteger` are available to store ECDSA `r` and `s` values; `hiding_sign: String` can store params
- `PersistencyManager` — SharedPreferences-backed store; `data` ArrayList is shared with the adapter
- `VariantConfig` — selects between SIGN (ECDSA) and REDELEGATE (Waters) variants with `count` and `wordSize`
- Server `ECDSA` struct (Rust): `{tag, rtag, r, s0, s_vec, key_mat_enc}` — the garbled ECDSA components

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

## Current Status

The full offline + online payment flow is working end-to-end:
- Offline: `+` → server issues garbled ECDSA circuit → Rust evaluates → `(r, s)` returned as JSON → stored in card → card appears in UI
- Online: tap card → POSTs `(r, s)` to `/api/verifypayment` → server accepts (first time) or rejects (replay) → card disappears

Server prints `PAYMENT ACCEPTED: r=...` on success; `PAYMENT REJECTED: signature already used` on replay.

## Possible Next Steps

- **Smart contract settlement**: Submit `(r, s)` to `zecdsa.sol` on Sepolia instead of Flask server (`ztest.ipynb` has test scripts)
- **Fair exchange** (`zfairexchange.sol`): Bank locks signing key in HTLC; phone receives it after payment (`ztest_htlc.ipynb`)
