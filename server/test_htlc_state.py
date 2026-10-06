"""Local-EVM regression test for zfairexchange.sol withdraw()/refund() state persistence.

Deploys the contract on an in-memory py-evm chain (no Sepolia, no wallet) and checks that a
contract can be withdrawn or refunded only once. Before the `memory` → `storage` fix, a second
withdraw() paid out again from the pooled balance.

Setup (once):  pip install "eth-tester[py-evm]"
Run:           cd server && source .venv/bin/activate && python3 test_htlc_state.py
"""
import json
import os
import sys

from solcx import compile_source, install_solc
from web3 import EthereumTesterProvider, Web3

from rustcode import generate_params_waters, water_unlock_solidity

SOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'zfairexchange.sol')


def main():
    install_solc('0.8.0', show_progress=False)
    with open(SOL) as f:
        iface = compile_source(f.read(), output_values=['abi', 'bin'], solc_version='0.8.0').popitem()[1]
    w3 = Web3(EthereumTesterProvider())
    bank, alice, other = w3.eth.accounts[:3]
    tx = w3.eth.contract(abi=iface['abi'], bytecode=iface['bin']).constructor().transact({'from': bank, 'gas': 8_000_000})
    addr = w3.eth.get_transaction_receipt(tx)['contractAddress']
    htlc = w3.eth.contract(address=addr, abi=iface['abi'])

    g1 = lambda p: (int(p['x']), int(p['y']))
    g2 = lambda p: ([int(p['x'][0]), int(p['x'][1])], [int(p['y'][0]), int(p['y'][1])])
    sol = json.loads(water_unlock_solidity(generate_params_waters(), 1))
    htlc.functions.setup((g1(sol['g']), g2(sol['g2']), g1(sol['g1a']), g2(sol['g2b']), g1(sol['u0']),
                          [g1(u) for u in sol['u_vec']])).transact({'from': bank, 'gas': 8_000_000})
    preimage = (g1(sol['sk1']), g1(sol['sk2']), g2(sol['sk3']))

    def new_contract(timelock):
        tx = htlc.functions.newContract(alice, 1, timelock).transact({'from': other, 'value': 10**16, 'gas': 3_000_000})
        return htlc.events.HTLCETHNew().process_receipt(w3.eth.get_transaction_receipt(tx))[0]['args']['contractId']

    def revert_reason(fn, sender):
        """None if the call succeeds (and is then mined), else the revert message."""
        try:
            fn.call({'from': sender, 'gas': 3_000_000})
        except Exception as e:
            return str(e)
        receipt = w3.eth.get_transaction_receipt(fn.transact({'from': sender, 'gas': 3_000_000}))
        return None if receipt['status'] == 1 else 'reverted'

    failures = []
    def check(name, cond):
        print(('PASS ' if cond else 'FAIL ') + name)
        if not cond:
            failures.append(name)

    now = w3.eth.get_block('latest')['timestamp']
    # Two contracts in the pool, so a repeated withdraw would have balance to drain.
    cid1, cid2 = new_contract(now + 3600), new_contract(now + 3601)

    check('first withdraw succeeds', revert_reason(htlc.functions.withdraw(cid1, preimage), alice) is None)
    c = htlc.functions.getContract(cid1).call()
    check('withdrawn persisted', c[5] is True)
    check('preimage persisted', c[7][0][0] == preimage[0][0])
    check('second withdraw reverts', 'already withdrawn' in (revert_reason(htlc.functions.withdraw(cid1, preimage), alice) or ''))
    check('pool still holds the other contract', w3.eth.get_balance(addr) == 10**16)

    w3.provider.ethereum_tester.time_travel(now + 7200)
    w3.provider.ethereum_tester.mine_blocks()
    check('refund after withdraw reverts', 'already withdrawn' in (revert_reason(htlc.functions.refund(cid1), other) or ''))
    check('first refund succeeds', revert_reason(htlc.functions.refund(cid2), other) is None)
    check('second refund reverts', 'already refunded' in (revert_reason(htlc.functions.refund(cid2), other) or ''))
    check('pool empty', w3.eth.get_balance(addr) == 0)

    print('HTLC state test ' + ('FAILED: ' + ', '.join(failures) if failures else 'PASSED'))
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
