# ORBIT — Contracts & Sepolia

The smart contracts, how the demo uses them compared with the paper, Sepolia transaction
handling, and contract testing. Read this before touching `server/zfairexchange.sol`,
`server/zecdsa.sol`, `_send_tx`, or the on-chain parts of `server.py`.

## The paper's two contracts (§2.4)

**`zfairexchange.sol` — Alice buys a coin from the bank (paper steps 2–3).** Alice locks ETH;
the bank can only claim it by revealing the Waters activation key on-chain; Alice reads the key
from the chain and activates her dmk.
```
Alice: newContract(bank_address, alice_tag, timelock)   ← Alice locks her ETH
Bank:  withdraw(contractId, {sk1, sk2, sk3})            ← reveals the key, claims the ETH
Alice: reads the key on-chain → Activate(dmk, key) → osk
```

**`zecdsa.sol` — the final holder redeems the coin (paper step 10).** The bank pre-locks ETH
once; any holder of a valid `osk` (after any number of re-delegations) produces an ECDSA
signature via `DSign` and claims it. No per-hop contract is needed.
```
Bank:  pre-locks ETH in zecdsa.sol
Final: DSign(osk, skD, msg) → (r, s) → zecdsa.sol → ETH
```

## What the demo does instead

The demo uses `zfairexchange.sol` for everything, funded by the server wallet: Mint/lock calls
`newContract(server_address, hashlock=denomination, timelock)`; Withdraw calls `withdraw()` with
a server-derived key. It proves on-chain BN254 pairing verification works, not the payment flow.
Every contract names the server as receiver, and `hashlock = denomination` is shared by all
contracts of a denomination (the paper uses a fresh random tag per coin).

**`zecdsa.sol` blockers (June 2026):**
1. No code converts Waters `(sk1, sk2, sk3)` into ECDSA `(r, s)`; the paper's combined circuit
   (GWat + GECDSA in one `osk`) is not implemented.
2. The ECDSA circuit signs on secp256r1, but `ecrecover` is secp256k1. A proper fix switches the
   Rust circuit (server + Android) to secp256k1 and rebuilds `librust.so`.
3. Server-side `evaluate_ecdsa` returns nothing (verifies internally); only the Android JNI
   returns `{"r","s"}`.
4. `zecdsa.sol` pays a hardcoded 0.00001 ETH per claim and was only tested with `eth_sign`.

A plan exists (`so-all-of-this-breezy-lampson.md`): Option C (the server proxy-signs with its
secp256k1 key after verifying the card's `(r, s)`) as a demo shortcut; Option A (rewrite the
circuit to secp256k1) as the real fix.

## Contract state persistence — fixed in source, NOT yet redeployed

`withdraw()` and `refund()` used to load the contract as `LockContract memory c`, so
`withdrawn`, `refunded`, and `preimage` were never saved: the receiver could withdraw the same
contract repeatedly (draining the pooled balance), the sender could refund after a withdrawal,
and `getContract()` never returned the revealed key. Both now use `LockContract storage c`.

**The contract at `HTLC_ADDRESS` (`server.py`) is still the old, buggy one** until the fixed
source is deployed and `HTLC_ADDRESS` updated (then `setup()` runs on the first call as usual).
Contracts created on the old address keep the bug.

Regression test (local py-evm chain, no Sepolia): `cd server && python3 test_htlc_state.py`
(needs `pip install "eth-tester[py-evm]"`). It checks single withdraw, single refund, no refund
after withdraw, and that the pool isn't drained.

## Sepolia transaction handling (`_send_tx` in `server.py`)

- Nonce from the `'pending'` block tag — avoids "replacement transaction underpriced" on
  back-to-back txs (e.g. `setup()` then `newContract()`).
- Gas price 2× current — the going rate leaves txs stuck during gas spikes.
- Receipt timeout 300 s (web3's 120 s default was too short).
- Console: `[NEW]`, `[REDELEGATE]`, `[PAY]` lines print each `contract_id`; `[WARN]` marks
  skipped or failed calls.

**Stuck nonce queue.** If txs time out with "is not in the chain after N seconds", compare
`get_transaction_count(addr, 'latest')` with `'pending'`. If pending > latest, old low-gas txs
(or nonce gaps from mempool evictions) block the queue. Fix with `server/unstick.py`: it replaces
each stuck nonce with a 0-ETH self-transfer at 5× gas. Run it with the env vars set and enter the
highest stuck nonce.

## Gas economics

Lock amounts come from `_DENOM_ETH` (1C = 0.01 ETH … 100C = 1.00 ETH).
- Mint: −lock − ~0.002 ETH gas (the first issuance per server session also runs `setup()`,
  ~0.001 ETH).
- Withdraw: +lock − ~0.005–0.006 ETH gas (`withdraw()` runs the BN254 pairing, ~389k gas).
- Legacy re-delegate: withdraw + new `newContract()`, ~0.003 ETH gas.
- A full cycle loses only gas (~0.007 ETH). At 0.01 ETH lock, a withdrawal nets about +0.004 ETH.

## Contract testing (notebooks in `server/`)

- **`ztest.ipynb`** — `zecdsa.sol` (ECDSA verification + payout).
- **`ztest_htlc.ipynb`** — `zfairexchange.sol` (HTLC + BN254 pairing). Fill in `private_key`
  (cell 1) and the Alchemy URL (cell 2); needs the Flask server running (fetches params from
  `/api/waters_solidity_params`); run deploy → `setup()` → `newContract()` + `withdraw()`.

Both contracts are deployed on Sepolia (chain id `11155111`).
