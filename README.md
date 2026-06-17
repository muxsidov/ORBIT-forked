# ORBIT — One-Shot Re-Delegatable Signatures for Scalable Off-Chain Payments

Research prototype accompanying the CCS 2025 paper. ORBIT lets a bank issue a cryptographic "coin" to Alice. Alice can either redeem it for ETH or pass the signing rights to Bob — exactly once, with no on-chain record of the transfer chain (history-freeness).

## How It Works

### The Two-Contract Architecture (Section 2.4)

The full system uses two Ethereum contracts for opposite directions of money:

**`zfairexchange.sol` — Alice buys a coin from the bank**
```
Alice: newContract(bank_address, alice_tag, timelock)  ← Alice locks ETH
Bank:  withdraw(contractId, {sk1,sk2,sk3})             ← Bank reveals Waters key, claims Alice's ETH
Alice: sees key on-chain → evaluates garbled circuit → gets one-shot signing key (osk)
```
The Waters key is the "preimage" — proving the bank delivered the activation key atomically.

**`zecdsa.sol` — Final holder redeems the coin**
```
Bank:  pre-locks ETH in zecdsa.sol once
Final: DSign(osk) → ECDSA signature → submit to zecdsa.sol → claims ETH
```
Any holder of a valid `osk` — Alice or Bob after re-delegation — can claim this ETH. No per-user contract needed.

> **Current implementation (Option A):** Re-delegate creates a fresh `zfairexchange.sol` HTLC for Bob at the same denomination, using Alice's same Waters key (`tag=denomination`). Bob scans the QR (which includes `denomination`) and can Pay immediately. Option B (full paper crypto) would use `garble_redelegate()` to give Bob a cryptographically distinct key at a new tag — see CLAUDE.md for details.

### Re-Delegation

When Alice re-delegates to Bob:
1. Alice runs `garble_redelegate(osk, tag=2)` offline — no server needed
2. Bob evaluates the new circuit → gets his own `osk2`
3. Bob calls `DSign(osk2)` → produces an ECDSA signature → submits to `zecdsa.sol` → claims ETH

The same pre-locked `zecdsa.sol` pays out to whoever presents the first valid signature. The full delegation chain is cryptographically unlinkable (history-freeness).

### Cryptographic Core

The garbled circuit encodes **two branches simultaneously**:
- **Waters branch** (`GWat`) — used by `RDelegate()` to produce a Waters IBE activation key for the next recipient
- **ECDSA branch** (`GECDSA`) — used by `DSign()` to produce the final ECDSA signature

Both branches are locked by the AndroidKeyStore n-use key (hardware-backed, limited to exactly N ECDH operations), enforcing one-timeness.

---

## Current Demo State

The demo is working end-to-end on Sepolia testnet, including device-to-device re-delegation via QR. It uses `zfairexchange.sol` for both issuance and redemption (a self-funding simplification — see "Demo vs. Paper" in CLAUDE.md). The correct final step (`zecdsa.sol` + `DSign`) is the next implementation milestone, currently blocked by a curve mismatch: the ECDSA garbled circuit signs on secp256r1 while `zecdsa.sol` verifies via `ecrecover` (secp256k1) — see CLAUDE.md "zecdsa.sol blockers" for the options.

| Action | What happens |
|--------|-------------|
| **Mint FAB** | Tap the floating "Mint +" button (bottom-right). A dropdown appears with denomination options (1 C / 0.01 ETH, 2 C / 0.02 ETH, …). Server garbles Waters circuit with `tag=denomination` + locks the corresponding ETH in `zfairexchange.sol`. Card appears in the grid with gold coin art (1 or 2 coins) and the denomination label. |
| **Pay** | App POSTs `{sk1,sk2,sk3,contract_id,denomination}` to server → `withdraw()` on Sepolia → TX hash shown → card removed. Recovers the locked ETH. |
| **Re-delegate** | App POSTs `{sk1,sk2,sk3,contract_id,denomination}` to server → withdraws Alice's HTLC, locks same denomination ETH in a fresh HTLC for recipient → shows QR of `{sk1,sk2,sk3,contract_id,denomination}`. Card removed on dismiss. Net cost: gas only. |
| **Scan** | Scans a QR from another device's Re-delegate. Adds a card with the scanned Waters key + contract_id + denomination, ready to Pay. |
| **Long-press a tile** | Delete the card without paying (cleanup for cards with no HTLC). |

**Gas costs (Sepolia, observed):** ~0.002 ETH for New (first issuance also runs one-time `setup()`, ~+0.001 ETH), ~0.003 ETH for Re-delegate, ~0.005–0.006 ETH for Pay (`withdraw()` runs BN254 pairing on-chain, ~389k gas). A full New → Re-delegate → Pay cycle costs ~0.007 ETH in gas; the locked ETH always returns to the wallet. At 0.01 ETH lock (1-token), Pay nets roughly +0.004 ETH to the server wallet balance.

**Troubleshooting:**
- *Transactions time out ("not in the chain after N seconds")* — the wallet's nonce queue is likely jammed by stuck or mempool-evicted transactions. Run `server/unstick.py` (with env vars set) to replace stuck nonces with 0-ETH self-transfers.
- *Card shows "no HTLC"* — it was created without blockchain credentials (or `newContract` timed out) and can never Pay. Long-press to delete it.
- *Need test ETH* — use the Google Cloud Web3 faucet or Alchemy's Sepolia faucet (note: some faucets require a mainnet balance; Google Cloud's does not).

---

## Components

- **`server/`** — Flask + Rust/PyO3 (WSL). Handles attestation, garbling, and Sepolia transactions.
- **`paymentbox_otp/`** — Android app (Windows/Android Studio). Card wallet UI + JNI cryptography.
- **`server/zfairexchange.sol`** — HTLC contract: locks ETH, releases on valid Waters key (BN254 pairing, ~389k gas).
- **`server/zecdsa.sol`** — ECDSA payout contract: releases ETH on valid ECDSA signature (~62k gas).
- **`server/ztest_htlc.ipynb`** — End-to-end test notebook for `zfairexchange.sol` on Sepolia.
- **`server/ztest.ipynb`** — End-to-end test notebook for `zecdsa.sol` on Sepolia.
- **`server/unstick.py`** — utility to clear a jammed Sepolia nonce queue (stuck/gapped transactions).

Both contracts are deployed on Sepolia (chain ID `11155111`):
- `zfairexchange.sol`: `0xF7cFB3FBE766A1Af18218e1498e2E504C231369B`
- `zecdsa.sol`: `0x5d40F709F6D24599a5043Bc54CfF97ab0d19aADD`

---

## Running the Demo

### 1. Server (WSL)

```bash
# Build Rust extension (first time only)
cd server
source $HOME/.cargo/env
source .venv/bin/activate
bash build.sh

# Set Sepolia credentials
export ETH_PRIVATE_KEY="<your Sepolia wallet private key>"
export ALCHEMY_URL="https://eth-sepolia.g.alchemy.com/v2/<your key>"

# Run
python3 server.py
```

### 2. Windows port forwarding (phone → WSL)

```powershell
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=5000 connectaddress=<WSL-IP> connectport=5000
```
Check WSL IP with `hostname -I`. Windows LAN IP is set in `MainActivity.kt` → `urlDest`.

### 3. Android app

Open `paymentbox_otp/` in Android Studio on Windows, build and run on device.

---

## Dependencies

**Server:** Python 3, Flask, maturin, Rust (stable), web3.py, eth-account, py-solc-x  
**Android:** Android Studio, NDK 23, BouncyCastle, ZXing, Gson  
**Blockchain:** Sepolia testnet wallet with test ETH, Alchemy RPC URL

---

## Architecture Notes

See `CLAUDE.md` for full implementation detail: activation flow, JNI interfaces, key data structures, RDelegate crypto notes, and WSL networking setup.
