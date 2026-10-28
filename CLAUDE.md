# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

ORBIT is an academic research prototype (Master's thesis) of a **one-shot payment system**
built on garbled circuits and Waters IBE, following the ORBIT paper:

- **Issuance:** the bank (Flask server) issues a dormant key (dmk) — a garbled Waters circuit
  bound to the phone's attested AndroidKeyStore key.
- **Activation:** the phone evaluates the circuit with AndroidKeyStore ECDH and recovers its
  Waters key `(sk1, sk2, sk3)`; capital is locked in an HTLC on Sepolia.
- **Use (once):** **Withdraw** (redeem on Sepolia) or **Re-delegate** (offline: re-evaluate the
  GS circuit at the recipient's tag, hand them a key by QR). Either consumes the card.

The main path is Waters/RDelegate. An ECDSA/DSign variant exists in the server and JNI but isn't
exposed in the UI and can't re-delegate.

## Where to read what

Read the relevant file **before** working in that area:

| Topic | File |
|---|---|
| Mint, dormant stock, coin counter, Withdraw, Re-delegate flows; data structures | `CLAUDE_architecture.md` |
| Waters key, GWat/GS circuits, tags, `beta_secret`, crypto flaws | `CLAUDE_crypto.md` |
| Contracts, demo vs. paper, Sepolia tx handling, gas, contract tests | `CLAUDE_contracts.md` |
| Android config, `librust.so` rebuild, UI, logcat, adb | `CLAUDE_android.md` |
| The ORBIT paper (algorithms, security definitions) | `ORBIT_PAPER.md` |
| Waters IBE/signature paper and tag-splitting math | `CLAUDE_Waters.md` |
| HTLC → adaptor-signature redesign (in progress) | `CLAUDE_replace_HTLC.md` |
| Atomic & Fair Data Exchange paper (VECK, adaptor signatures) | `CLAUDE_AandFD.md` |
| Dated experiment history for the thesis; open questions | `thesis_log/` (`README.md`, `open-questions.md`) |

## Layout

- `server/` — Flask server (`server.py`) + Rust/PyO3 extension (`rustcode/`), contracts
  (`zfairexchange.sol`, `zecdsa.sol`), notebooks, `unstick.py`. Runs on WSL.
- `paymentbox_otp/` — Android app (Kotlin + Rust JNI). Lives on Windows at
  `C:\Masters\orbit-7C66\paymentbox_otp\` (`/mnt/c/Masters/orbit-7C66/paymentbox_otp/` from WSL).
- **Git:** this WSL repo tracks only the server side. `paymentbox_otp/` is committed separately
  from Windows.

## Running

```bash
# Build the Rust extension (first run, and after any change in server/rustcode/)
cd server && source $HOME/.cargo/env && source .venv/bin/activate && bash build.sh

# Run the server (binds 0.0.0.0:5000)
cd server && source .venv/bin/activate
export ETH_PRIVATE_KEY="<Sepolia wallet key>"
export ALCHEMY_URL="https://eth-sepolia.g.alchemy.com/v2/<key>"
python3 server.py
```
Without the env vars, blockchain calls are skipped with a warning and `contract_id` is `""`.
They must be exported in the same shell that runs the server. `server.py` constants changes need
a server restart; `rustcode/` changes need `build.sh`; changes under
`paymentbox_otp/app/rust/` need a manual `librust.so` rebuild (`CLAUDE_android.md`).

**Tests:** `bash server/run_tests.sh [poc|chain|server] [--build]` prints one summary line per
test; full logs go to `server/test_logs/`.
- `chain` starts `bitcoind -regtest` if needed.
- `--build` reruns `build.sh` first.
- Recorded results are in `thesis_log/test-results.md`; re-run a group only when its code
  changed.

**Phone ↔ server:** `adb reverse tcp:5000 tcp:5000` (recommended; re-run after each reconnect),
or Wi-Fi via Windows port-proxy to the WSL IP:
`netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=5000 connectaddress=<WSL-IP> connectport=5000`
(WSL IP changes on restart — `hostname -I`; Windows LAN IP is `192.168.1.101`).

## Endpoints (`server.py`)

- `GET /api/delegatedpresig?attestation=…&denomination=N` — mint one coin: garble GWat + GS,
  `newContract()`, return `{epk, params, msg, contract_id, denomination, gs_circuit}`. Needs
  `nusecount = 94`.
- `POST /api/replenish {attestations: [...], request}` — batch-garble dormant coins, no
  `newContract()`. One attestation (own key, `nusecount = 94`) per coin.
- `POST /api/lock {denomination}` — lock capital for a dormant coin → `{contract_id}`.
- `POST /api/pay {sk1, sk2, sk3, contract_id, denomination}` — `withdraw()` with a
  server-derived key → `{tx_hash, contract_id}`.
- `POST /api/redelegate {contract_id, denomination}` — legacy path: withdraw the old HTLC, create
  a new one.
- `GET /api/fde/bank`, `POST /api/fde/offer {attestation, denomination, alice_pk, user_id}`,
  `POST /api/fde/claim {offer_id, txid, vout, presig}` — FDE purchase on Bitcoin regtest (Part C
  of `CLAUDE_replace_HTLC.md`), alongside the HTLC flow. Needs
  `bitcoind -regtest -datadir=$HOME/btc-regtest -daemon -fallbackfee=0.0001` (override with
  `BTC_DATADIR`); Bank key from `BTC_BANK_KEY` or fresh per run. Test: `test_fde_regtest()`.
- Also: `/api/delegatedpresigecdsa` (ECDSA variant), `/api/waters_solidity_params` (used by
  `ztest_htlc.ipynb`), `/api/verifyattest`, `/api/register`, `/api/benchmarkdelegateecdsa`
  (heavy — 100 iterations).

Denominations: `_DENOM_ETH = {1: 0.01, 2: 0.02, 5: 0.05, 10: 0.10, 20: 0.20, 50: 0.50, 100: 1.00}`
ETH. Add a denomination there only. Attestation budget: `_GS_TAG_BITS = 88`,
`_GS_NUSECOUNT = 94` = 5 GWat + 1 + 88, **exact** — a spare use breaks GS one-timeness. Keep in
sync with the Android `callToken(94, …)` / per-coin `OneTimeMemory(94)`.

## Hard rules

- **`beta_secret` (Waters master secret) never leaves the server.** Strip it from any `params`
  returned to a client.
- **Re-delegation is device-to-device and offline.** The recipient contacts the server only to
  withdraw.
- **One attested key per coin, with exactly `_GS_NUSECOUNT` uses.** Never pool the budget across
  coins or add spare uses (`CLAUDE_crypto.md`, "Budget").
- **Per-coin secrets use real randomness** (`rand::thread_rng()`), never `test_rng()`; only the
  Waters *params* use the fixed seed.
- Waters params are deterministic (`ark_std::test_rng()`), so the app bundles them as
  `res/raw/waters_params.json` instead of receiving them — don't change the seed.

## Gotchas

- Strip `0x` from contract ids with `removeprefix('0x')`, never `lstrip('0x')` (it also eats
  leading zeros → odd-length hex → `bytes.fromhex` fails).
- Gson ignores Kotlin defaults: guard parsed strings with `?: ""`.
- Keep `benchmark_delegate(...)` calls in `MainActivity.onCreate()` commented out.
- Txs stuck "not in the chain after N seconds" → nonce jam → `server/unstick.py`
  (`CLAUDE_contracts.md`).
- `rootcert.pem` includes the Android *software* attestation root (needed for devices without
  StrongBox) — see the attestation flaw below.

## Known open flaws (don't assume these are fixed)

Full list and status in `thesis_log/open-questions.md`; details in the topic files.
- **Critical — contract not redeployed:** the `memory` → `storage` fix in `zfairexchange.sol` is
  in source (tested locally, `server/test_htlc_state.py`), but `HTLC_ADDRESS` still points to the
  old contract, where withdrawals repeat and drain the pool (`CLAUDE_contracts.md`).
- **Denomination forgery** (supervisor's concern): fixed in code on `main`, not
  yet enforced end to end. The GS circuit garbles one slot for the fixed `_DDD_` bits, and
  `/api/pay` / `/api/redelegate` take the denomination from the on-chain contract. It only bites
  at payout once the tag-encoding mismatch is fixed; the Android `librust.so` needs a rebuild and
  old coins a re-mint (`CLAUDE_crypto.md`).
- **Tag-encoding mismatch:** client keys never pass the on-chain check; `/api/pay` substitutes a
  server-derived key and ignores the submitted one.
- Also: activation doesn't need the bank; hashlock shared per denomination; software attestation
  root trusted; sender can withdraw before the recipient.

## Possible next steps

- Redeploy `zfairexchange.sol` and update `HTLC_ADDRESS`.
- Fix the tag-encoding mismatch so `/api/pay` verifies submitted keys.
- Full paper redemption flow: `DSign` → `zecdsa.sol` (blocked by the secp256r1/secp256k1
  mismatch — `CLAUDE_contracts.md`).
- Real purchase flow: Alice locks her own ETH and the bank reveals the key on-chain.
- HTLC → adaptor-signature replacement (`CLAUDE_replace_HTLC.md`): server side done on Bitcoin
  regtest; next is the Android client.
- Re-expose the ECDSA variant in the UI.
