# ORBIT — One-Shot Re-Delegatable Signatures for Scalable Off-Chain Payments

Research prototype accompanying the CCS 2025 paper. ORBIT lets a bank issue a cryptographic "coin" to Alice as a garbled circuit. Alice can either redeem it for ETH or pass the signing right to Bob — exactly once, with no on-chain record of the delegation chain (history-freeness).

---

## What This Prototype Demonstrates

| Property | Demonstrated? | Notes |
|----------|--------------|-------|
| Hardware-bound one-timeness | Yes | AndroidKeyStore ECDH key limited to N uses via `nusecount` attestation |
| Bank-to-Alice atomic issuance | Partial | `zfairexchange.sol` HTLC enforces atomicity; but server self-funds both sides (not Alice's wallet) |
| Offline device-to-device re-delegation | **Yes (end-to-end tested)** | Alice re-evaluates GS circuit with 57 ECDH ops → produces `ak2` QR; Bob scans offline; no server contact |
| On-chain Waters IBE key verification | Yes | BN254 pairing check in `zfairexchange.sol` (`hashlockMatches`), ~389k gas |
| History-freeness / unlinkability | Partial | Alice's card is deleted after re-delegation; on-chain there is no link between Alice and Bob |
| Full paper `DSign` payout | No | `zecdsa.sol` exists but is blocked by curve mismatch (circuit = secp256r1, ecrecover = secp256k1) |
| User-submitted key used for withdrawal | No | `/api/pay` uses the server's own `water_unlock_solidity(denomination)` key due to tag encoding mismatch (see below) |

---

## Cryptographic Architecture

### Waters IBE Activation Key

The bank garbles a Waters IBE circuit (`GWat`) using 5 ephemeral EC key pairs. Alice evaluates it by performing 5 ECDH operations against her AndroidKeyStore private key, recovering a Waters activation key:

| Paper name | Code name | Type | Role |
|------------|-----------|------|------|
| `dk1` | `sk1` | G1 | `g^α · H(tag)^r` — signing key + hashed identity |
| `dk2` | `sk2` | G1 | `g^r` — random factor in G1 |
| `dk3` | `sk3` | G2 | `g2^r` — random factor in G2 |

On-chain, `zfairexchange.sol` verifies two BN254 pairing equations (the Waters IBE verification equations):
- `e(g, sk3) = e(sk2, g2)` — confirms dk2 and dk3 use the same r
- `e(g^α, g2^β) · e(H(tag), sk3) = e(sk1, g2)` — main Waters equation

### GS Circuit — Offline Re-Delegation

The bank also garbles a second structure (`GS`) alongside `GWat`. `GS` has 1 branch slot + 56 bit-slots, each encrypting shares of the next recipient's Waters key components via ECDH with Alice's AndroidKeyStore key. Alice evaluates `GS` offline at Bob's tag bits (57 ECDH ops against her AndroidKeyStore), producing `ak2 = (dk1', dk2', dk3')` — Bob's fresh Waters activation key.

**Key properties of the GS-based offline re-delegation:**
- Fully offline after initial minting: no server contact, no network access
- Server contact count: **2 total** — once when Alice mints, once when Bob withdraws
- Alice's AndroidKeyStore key budget: 5 (GWat) + 57 (GS) = 62 ≤ 64 (`nusecount` limit)
- One-timeness: after 62 ops the key is exhausted; Alice cannot re-delegate a second time
- `ak2` is a valid Waters activation key for `tag=denomination` — Bob can call `/api/pay` directly against Alice's original `contract_id`; no new HTLC needed

### Known Cryptographic Gaps

#### 1. Tag encoding mismatch (blocks user key submission)

Three different tag→group-element computations exist in the codebase:

| Component | How it hashes the tag | Compatible? |
|-----------|-----------------------|-------------|
| `h_of_id()` in server Rust (GWat garbling, GS generation) | ASCII string bytes, bit-by-bit into `h_vec` indices | **No** |
| `water_unlock_solidity()` in server Rust | Integer denomination, bit-by-bit into `h_vec[0..40]` | Yes |
| `hashlockMatches` in `zfairexchange.sol` | Integer `hashlock`, bit-by-bit into `u_vec[0..40]` | Yes |

`garble_waters` and `generate_gs` use `h_of_id()` (path 1). The on-chain contract uses integer decomposition (path 3). For tag `"001_000"` (the DDD_UUU string), these produce entirely different BN254 group elements — a Waters key produced by `evaluate_paymentbox` or `evaluate_gs` will never pass the on-chain pairing check.

**Consequence:** `/api/pay` ignores the user-submitted `sk1/sk2/sk3` and calls `water_unlock_solidity(denomination)` to generate the server's own matching Waters key. The pairing is verified on-chain, but against the bank's key — not Alice's or Bob's.

**Fix (not implemented):** Unify all three paths to use integer bit-decomposition. Requires changing `h_of_id()` in server Rust, `generate_gs()`, and `computeGsAk2()` on Android (pass `denomination` as integer, not `"%03d_%03d"` string).

#### 2. `beta_secret` in params (security gap)

The server sends `beta_secret` (the Waters IBE master secret) to Alice inside `params`. This is not cryptographically necessary for the paper's design — Alice should only receive public parameters. However, stripping it is non-trivial: the Android Rust `evaluate_paymentbox()` calls `water_decrypt(&par, &tag, rtag)` which re-derives `dk1` using `param.g_alpha * param.beta_secret`. The `ParamWaters` struct in Android Rust requires `beta_secret` as a non-optional field; removing it from the JSON causes a SIGABRT at deserialisation.

**Fix (not implemented):** Redesign the garbled circuit to embed the decryption key material directly, so the client never needs the master secret.

#### 3. `DSign` / `zecdsa.sol` path not connected

`zecdsa.sol` exists and was tested with standard Ethereum signatures. The ORBIT garbled circuit produces ECDSA `(r,s)` on **secp256r1** (P-256), but `zecdsa.sol` uses `ecrecover` which is **secp256k1**. Connecting the two requires rewriting the Rust garbled circuit to use secp256k1 scalars (both server and Android JNI, plus `librust.so` rebuild for Android). Additionally, no code path converts a Waters `(sk1,sk2,sk3)` to an ECDSA `(r,s)` — the two circuits (`GWat` and `GECDSA`) are completely separate.

---

## Current Demo Flow

### 1. Mint (Alice, online)

1. Alice taps **Mint FAB** → picks denomination (1 C / 0.01 ETH, 2 C / 0.02 ETH, …)
2. App requests AndroidKeyStore attestation with `nusecount=64`
3. Server verifies attestation → garbles GWat (5 slots) + GS (57 slots) → calls `newContract()` on Sepolia locking the corresponding ETH → returns `{epk, params, msg, contract_id, denomination, gs_circuit}`
4. App performs 5 ECDH ops (GWat evaluation) → JNI `paymentbox()` → recovers `(sk1, sk2, sk3)`
5. Card stored with `gs_circuit` and `contract_id`; gold coin tile appears in grid

### 2a. Withdraw (any holder, online)

1. Select card → tap **Withdraw**
2. App POSTs `{sk1, sk2, sk3, contract_id, denomination}` to `/api/pay`
3. Server calls `water_unlock_solidity(denomination)` to produce its own Waters key (not the submitted key — see tag encoding mismatch above) → calls `withdraw()` on Sepolia → BN254 pairing verified on-chain (~389k gas)
4. TX hash shown → card removed

### 2b. Offline Re-delegate (Alice → Bob, fully offline)

1. Bob opens app → taps **My ID** → sets `uid` → shows identity QR `{"uid": N}`
2. Alice selects card → taps **Re-delegate** → scans Bob's identity QR
3. App constructs `bobTag = "%03d_%03d".format(denomination, uid)` → calls `computeGsAk2(card, bobTag)`:
   - 57 sequential ECDH ops against the GS circuit's ephemeral public keys using Alice's AndroidKeyStore key
   - JNI `evaluateGs()` → `ak2 = (dk1', dk2', dk3')`
   - Entirely offline; no server contact
4. App shows re-delegation QR: `{sk1: ak2.sk1, sk2: ak2.sk2, sk3: ak2.sk3, contract_id: alice_original, denomination}`
5. Alice's card removed (one-shot enforced); Bob scans QR → new card on Bob's device
6. Bob taps **Withdraw** → server uses server's own key to call `withdraw()` against Alice's original `contract_id`

> Note: Bob's `ak2` is a valid Waters key for `tag=denomination` but the tag encoding mismatch means it can't be submitted directly. The server re-derives a compatible key for on-chain use.

### Demo Table

| Action | Server contact | Notes |
|--------|---------------|-------|
| Mint | Yes (online) | Garbles GWat+GS, calls `newContract()` |
| Withdraw | Yes (online) | Calls `withdraw()` on Sepolia |
| Re-delegate | **No (offline)** | 57 ECDH ops on device, QR to Bob |
| Scan (Bob receives) | No | Parses QR, creates card |
| Bob Withdraw | Yes (online) | Uses Alice's original `contract_id` |

---

## Architecture

### The Two-Contract Architecture (Section 2.4 of paper)

**`zfairexchange.sol` — Alice purchases a coin from the bank**
```
Alice: newContract(bank_address, alice_tag, timelock)  ← Alice locks ETH
Bank:  withdraw(contractId, {sk1,sk2,sk3})             ← Bank reveals Waters key, claims Alice's ETH
Alice: sees key on-chain → evaluates garbled circuit → gets activation key (sk1,sk2,sk3)
```

**`zecdsa.sol` — Final holder redeems the coin (paper design)**
```
Bank:  pre-locks ETH in zecdsa.sol once
Final: DSign(osk) → ECDSA signature → submit to zecdsa.sol → claims ETH
```

**Current demo simplification:** The server self-funds both contracts. `newContract()` is called by the server wallet, not Alice's wallet — so there is no actual purchase. The demo proves the BN254 pairing verification works on-chain; it does not implement the full atomic swap (Alice pays, bank reveals key).

### Components

- **`server/`** — Flask + Rust/PyO3 (WSL). Handles attestation, circuit garbling, and Sepolia transactions.
- **`paymentbox_otp/`** — Android app. Card wallet UI + JNI cryptography (GWat evaluation, GS offline re-delegation).
- **`server/zfairexchange.sol`** — HTLC contract: locks ETH, releases on valid Waters key (BN254 pairing, ~389k gas).
- **`server/zecdsa.sol`** — ECDSA payout contract: releases ETH on valid ECDSA signature (~62k gas). Not connected to demo UI.
- **`server/ztest_htlc.ipynb`** — End-to-end Sepolia test notebook for `zfairexchange.sol`.
- **`server/ztest.ipynb`** — End-to-end Sepolia test notebook for `zecdsa.sol`.
- **`server/unstick.py`** — Clears jammed Sepolia nonce queues.

Deployed on Sepolia (chain ID `11155111`):
- `zfairexchange.sol`: `0xF7cFB3FBE766A1Af18218e1498e2E504C231369B`
- `zecdsa.sol`: `0x5d40F709F6D24599a5043Bc54CfF97ab0d19aADD`

---

## Running the Demo

### Server (WSL)

```bash
# Build Rust extension (first time or after code changes)
cd server
source $HOME/.cargo/env
source .venv/bin/activate
bash build.sh

# Set Sepolia credentials (required for Mint and Withdraw)
export ETH_PRIVATE_KEY="<your Sepolia wallet private key>"
export ALCHEMY_URL="https://eth-sepolia.g.alchemy.com/v2/<your key>"

python3 server.py
```

If `ETH_PRIVATE_KEY` / `ALCHEMY_URL` are not set, blockchain calls are skipped and `contract_id` is returned as `""`. Cards with `contract_id=""` show "no HTLC" and cannot Withdraw.

### USB tunnel (phone → WSL, recommended)

```bash
adb reverse tcp:5000 tcp:5000
```

Re-run after each USB reconnect or phone reboot. adb is at `C:\Users\<name>\AppData\Local\Android\Sdk\platform-tools\adb.exe`.

### Android app

Open `paymentbox_otp/` in Android Studio (Windows), build and run on device.

---

## Gas Costs (Sepolia, observed)

| Action | Gas | ETH cost (approx.) |
|--------|-----|---------------------|
| First `setup()` (one-time per server session) | ~80k | ~0.001 ETH |
| `newContract()` (Mint) | ~130k | ~0.002 ETH |
| `withdraw()` (Pay — BN254 pairing on-chain) | ~389k | ~0.005–0.006 ETH |
| `withdraw()` + `newContract()` (Re-delegate, server path) | ~520k | ~0.003 ETH net (ETH recovered = ETH re-locked) |

Full New → Re-delegate → Pay cycle: ~0.007 ETH in gas total; locked ETH always returns to wallet.

---

## Troubleshooting

- **TX times out ("not in the chain after N seconds"):** Nonce queue jammed. Run `server/unstick.py` (with env vars set) to replace stuck nonces with 0-ETH self-transfers at 5× gas.
- **Card shows "no HTLC":** Created without blockchain credentials or `newContract` timed out. Long-press tile → "Delete token?" to remove.
- **Test ETH:** Google Cloud Web3 Sepolia faucet (does not require mainnet balance), or Alchemy's Sepolia faucet.

---

## Dependencies

**Server:** Python 3.9+, Flask, maturin, Rust (stable), web3.py, eth-account, py-solc-x  
**Android:** Android Studio, NDK r23b, BouncyCastle, ZXing, Gson  
**Blockchain:** Sepolia testnet wallet with test ETH, Alchemy RPC URL

---

## Implementation Details

See `CLAUDE.md` for full implementation detail: activation flow, JNI interfaces, key data structures, RDelegate crypto notes including the known gaps, WSL networking, and Solidity contract internals.
