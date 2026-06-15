"""Clear a jammed nonce queue by replacing stuck/gapped nonces with 0-ETH self-transfers.

Usage:
    export ETH_PRIVATE_KEY="..."
    export ALCHEMY_URL="https://eth-sepolia.g.alchemy.com/v2/..."
    python3 unstick.py
"""
import os
import time
from web3 import Web3
from eth_account import Account

w3 = Web3(Web3.HTTPProvider(os.environ['ALCHEMY_URL']))
acct = Account.from_key(os.environ['ETH_PRIVATE_KEY'])

latest = w3.eth.get_transaction_count(acct.address, 'latest')
pending = w3.eth.get_transaction_count(acct.address, 'pending')
print(f"address: {acct.address}")
print(f"latest nonce (mined): {latest}, pending: {pending}")

# Cover both stuck pending txs and any gapped nonces beyond them.
# Bump END if you know a tx sits at a higher nonce (e.g. the one in the WARN log).
END = int(input(f"replace nonces {latest}..N — enter N (e.g. 45): "))

gas_price = int(w3.eth.gas_price * 5)  # decisively outbid everything stuck
print(f"replacement gas price: {w3.from_wei(gas_price, 'gwei')} gwei")

for nonce in range(latest, END + 1):
    tx = {
        'from': acct.address,
        'to': acct.address,   # 0-ETH transfer to self
        'value': 0,
        'nonce': nonce,
        'gas': 21000,
        'gasPrice': gas_price,
        'chainId': 11155111,
    }
    signed = acct.sign_transaction(tx)
    try:
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        print(f"nonce {nonce}: replacement sent {tx_hash.hex()}")
    except Exception as e:
        # "already known" / "replacement underpriced" means something sits there; report and continue
        print(f"nonce {nonce}: {e}")

print("waiting for the queue to clear...")
while True:
    mined = w3.eth.get_transaction_count(acct.address, 'latest')
    print(f"  mined up to nonce {mined - 1}")
    if mined > END:
        break
    time.sleep(10)

print("Done — mempool unjammed.")
print(f"balance: {w3.from_wei(w3.eth.get_balance(acct.address), 'ether')} ETH")
