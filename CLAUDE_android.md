# ORBIT — Android App

The Android app (`paymentbox_otp/`, on Windows at `C:\Masters\orbit-7C66\paymentbox_otp\`,
reachable from WSL at `/mnt/c/Masters/orbit-7C66/paymentbox_otp/`): configuration, the Rust JNI
library, the UI, and debugging. Flows themselves are in `CLAUDE_architecture.md`.

## Configuration

- **Server URL:** `urlDest` in `MainActivity.kt` (internal). Use `http://127.0.0.1:5000/` with
  `adb reverse`, or the Windows LAN IP (`http://192.168.1.101:5000/`) over Wi-Fi.
- **Benchmark calls:** keep every `benchmark_delegate(...)` call in `MainActivity.onCreate()`
  commented out. They fire 100 server requests at startup and cause `Connection reset`.
- **Variant:** minting uses `VariantConfig.RDelegateByteInstance()` (count=5, wordSize=8,
  MAX_ITEM=256), i.e. a GWat circuit of 5 × 256 = 1280 slots.
- **Mint-time attestation budget:** `callToken(94, …)` in `issueCard()` and the per-coin
  `OneTimeMemory(94)` keys in `performSync()` must equal `_GS_NUSECOUNT` in `server.py` exactly
  (no spare uses, one key per coin — see "Budget" in `CLAUDE_crypto.md`).

## Rust JNI library (`app/rust/`)

`librust.so` is **pre-built and committed** in `app/src/main/jniLibs/`; the Gradle cargo plugin
doesn't reliably rebuild it. Any change under `app/rust/` needs a manual rebuild (below).

- `src/lib.rs` — JNI entry points: `paymentbox()`, `paymentboxecdsa()`, `garble_redelegate()`,
  `evaluateGs` (throws `RuntimeException` if the circuit can't be opened), `rust_init()`, `test()`.
- `src/paymentbox/pbcrypto.rs` — `evaluate_paymentbox()` → `{"sk1","sk2","sk3"}` (hex);
  `evaluate_gs()` (byte-identical copy in `server/rustcode/src/pbcrypto.rs`, used by
  `test_gs_full()` — keep them in sync); `evaluate_ecdsa()` → `{"r","s"}`; `garble_redelegate()` (Option-B, unused in
  the UI).

**Rebuild from WSL** (Linux NDK r23b extracted to `/tmp/android-ndk-r23b`; `/tmp` doesn't survive
a reboot, so re-download it then):
```bash
export PATH="/tmp/android-ndk-r23b/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
cd /mnt/c/Masters/orbit-7C66/paymentbox_otp/app/rust
cargo build --target aarch64-linux-android --release
cp target/aarch64-linux-android/release/librust.so \
   /mnt/c/Masters/orbit-7C66/paymentbox_otp/app/src/main/jniLibs/arm64-v8a/librust.so
```
Linker config is in `.cargo/config.toml`. `clang`/`clang++` in the NDK bin dir must be symlinks
to `clang-12`; if they break: `cd /tmp/android-ndk-r23b/toolchains/llvm/prebuilt/linux-x86_64/bin
&& rm clang clang++ && ln -s clang-12 clang && ln -s clang-12 clang++`. The Windows NDK
(`AppData/Local/Android/Sdk/ndk/23.1.7779620/`) has only Windows binaries and can't be used from
WSL.

## UI

- **Action bar:** "ORBIT — AccountName". Overflow menu (⋮): Switch account / New account / Sync.
  First launch shows a create-account dialog. Cards are stored per account in `SAVE_$account`;
  the account list in `ORBIT_META`.
- **Grid:** 2 columns of 160 dp tiles (`GridLayoutManager(2)`), uniform `#37474F`
  `MaterialCardView`. Each tile: coin art (`res/drawable/ic_coin.xml`; a second overlapping coin
  for denomination ≥ 2), denomination label, tag `UUU_DDD_CCC` in monospace (`000_DDD_CCC` if no
  identity), and the first 8 chars of `contract_id` ("no HTLC" if empty).
- **Selection:** tap toggles a white stroke (`MaterialCardView.strokeColor`). Long-press →
  "Delete token?". Use `adapterPosition`, not `bindingAdapterPosition` (RecyclerView is too old).
- **FABs** (bottom right, in a wrapping `LinearLayout`): **Checks** (purple) →
  `showChecksDialog()`; **Mint** (blue) → `ListPopupWindow` of denominations with ETH price and
  dormant count → `activateOrMint()`.
- **Bottom bar** (`#263238`, four `MaterialButton`s): **Withdraw** (green when a card is
  selected) · **Re-delegate** (purple when a card is selected; GS path if the card has a
  `gs_circuit`, otherwise legacy) · **Scan** (teal, ZXing → `addCardFromQR()`) · **My ID**
  (indigo, live identity QR). Colours are set via `backgroundTintList`; `updateBottomBarState()`
  greys out inactive buttons rather than hiding them.

## QR dependencies

- `app/build.gradle.kts`: `com.journeyapps:zxing-android-embedded:4.3.0`; `CAMERA` permission in
  `AndroidManifest.xml`.
- `res/raw/waters_params.json`: bundled Waters params (~30 KB, deterministic), loaded as
  `hardcodedParams`.
- `MainActivity.kt`: `qrScanLauncher` (incoming payment QR), `gsRedelegateLauncher` (recipient's
  identity QR), `generateQrBitmap()`.

## Debugging

- **Logcat:** filter by `PaymentBoxAdapter` / `MainActivity`. Every `contract_id` hop is logged
  (circuit received, card stored, Pay pressed, re-delegate, card added from QR); match them
  against the server's `[NEW]` / `[REDELEGATE]` / `[PAY]` lines.
- **adb (recommended):** `adb reverse tcp:5000 tcp:5000` routes the phone's `127.0.0.1:5000` to
  WSL; re-run after every USB reconnect or phone reboot. adb lives at
  `C:\Users\<name>\AppData\Local\Android\Sdk\platform-tools\adb.exe`.
