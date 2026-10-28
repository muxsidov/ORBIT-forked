"""
Flask Server
"""

from multiprocessing import Pool,cpu_count
import sys, os
# sys.path.append(os.path.join(os.path.dirname(__file__), '..', "..", ".."))
# sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from base64 import urlsafe_b64encode, urlsafe_b64decode
from flask import Flask, session, request, redirect, abort, jsonify

from rustcode import test_evaluate_gs, test_verify_gs_key, test_water, test_ecdsa, test_activate, test_unlock, test_dsign_local, test_rdelegate_local, garble_waters, garble_redelegate, garble_ecdsa, generate_params_waters,generate_params_ecdsa, test_encrypt, water_unlock_solidity, water_derive_ak, garble_waters_with_gs, decompress_waters_key
from rustcode import fde_keypair, fde_pubkey, fde_sign, fde_verify_sig, fde_make_offer, fde_verify_offer, btc_lock, btc_p2wpkh_address, btc_spend, fde_presign, fde_complete_claim, btc_sign_refund, fde_extract_decrypt
# poseidon

import os
import random
import json
import base64
import asn1
import pem
import math
import time

# ── Blockchain (zfairexchange.sol on Sepolia) ─────────────────────────────
from web3 import Web3
from eth_account import Account as EthAccount
from solcx import compile_source, install_solc as _install_solc

ETH_PRIVATE_KEY = os.environ.get("ETH_PRIVATE_KEY", "")
ALCHEMY_URL     = os.environ.get("ALCHEMY_URL", "")
HTLC_ADDRESS    = "0xF7cFB3FBE766A1Af18218e1498e2E504C231369B"
CHAIN_ID        = 11155111

_w3            = None
_eth_acct      = None
_htlc          = None   # contract instance
_htlc_setup_ok = False  # whether setup() has been called this session

def _init_web3():
    global _w3, _eth_acct, _htlc
    if _w3 is not None:
        return
    if not ETH_PRIVATE_KEY or not ALCHEMY_URL:
        raise RuntimeError("Set ETH_PRIVATE_KEY and ALCHEMY_URL env vars before using /api/pay")
    _w3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))
    _eth_acct = EthAccount.from_key(ETH_PRIVATE_KEY)
    _install_solc('0.8.0', show_progress=False)
    sol_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(sol_dir, 'zfairexchange.sol')) as f:
        src = f.read()
    compiled = compile_source(src, output_values=['abi', 'bin'], solc_version='0.8.0')
    _, iface = compiled.popitem()
    _htlc = _w3.eth.contract(
        address=Web3.to_checksum_address(HTLC_ADDRESS),
        abi=iface['abi']
    )

def _send_tx(fn, value=0):
    tx = fn.build_transaction({
        'from':     _eth_acct.address,
        'nonce':    _w3.eth.get_transaction_count(_eth_acct.address, 'pending'),
        'gas':      5_000_000,
        # 2x current gas price: Sepolia gas spikes leave exact-price txs stuck in the mempool
        'gasPrice': int(_w3.eth.gas_price * 2),
        'chainId':  CHAIN_ID,
        'value':    value,
    })
    signed = _eth_acct.sign_transaction(tx)
    tx_hash = _w3.eth.send_raw_transaction(signed.raw_transaction)
    return _w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)

def _g1(p):
    return (int(p['x']), int(p['y']))

def _g2(p):
    return ([int(p['x'][0]), int(p['x'][1])], [int(p['y'][0]), int(p['y'][1])])

def _ensure_setup():
    global _htlc_setup_ok
    if _htlc_setup_ok:
        return
    sol = json.loads(water_unlock_solidity(water_parameter, 1))
    param_tuple = (
        _g1(sol['g']),
        _g2(sol['g2']),
        _g1(sol['g1a']),
        _g2(sol['g2b']),
        _g1(sol['u0']),
        [_g1(u) for u in sol['u_vec']],
    )
    _send_tx(_htlc.functions.setup(param_tuple))
    _htlc_setup_ok = True

# Denomination → ETH amount mapping.
# To add a new denomination just add an entry here.
_DENOM_ETH = {1: 0.01, 2: 0.02, 5: 0.05, 10: 0.10, 20: 0.20, 50: 0.50, 100: 1.00}

# User registry: persists for the lifetime of the server process.
# Maps user_id (int) → {"pubkeys": [bytes, ...], "nusecount": int}
_user_registry: dict = {}
_next_user_id: int = 1

def make_tag(denom: int, user_id: int) -> str:
    """Format a Waters IBE tag as 'UUU_DDD' (3-digit user_id, 3-digit denomination)."""
    return f"{user_id:03d}_{denom:03d}"

def denomination_config(denom: int, user_id: int = 0) -> dict:
    """Return tag, hashlock, and ETH amount for a given denomination."""
    if denom not in _DENOM_ETH:
        raise ValueError(f"Unsupported denomination: {denom}. Supported: {list(_DENOM_ETH)}")
    return {"tag": make_tag(denom, user_id), "hashlock": denom, "eth": _DENOM_ETH[denom]}
# ─────────────────────────────────────────────────────────────────────────
from asn1crypto.core import Sequence
from pyasn1.codec.ber import decoder as pyasn1decoder
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtensionOID,ObjectIdentifier
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac, hashes
from functools import reduce

def sha256(data: bytes) -> bytes:
    """Produces a SHA256 hash of the input.

    :param data: The input data to hash.
    :return: The resulting hash.
    """
    h = hashes.Hash(hashes.SHA256(), default_backend())
    h.update(data)
    return h.finalize()

# from paymentbox_garbleprogram import get_delegated_signing_capability, get_delegated_signing_capability_wordbased

app = Flask(__name__, static_url_path="")
app.secret_key = os.urandom(32)  # Used for session.

filename = "rootcert.pem"

# # Registered credentials are stored globally, in memory only. Single user
# # support, state is lost when the server terminates.
# credentials = []
# credentials_userprofile = {}


@app.route("/")
def index():
    return redirect("/index.html")

# @app.route("/api/records", methods=["GET"])
# def getcred():
#     return jsonify(credentials_userprofile)

water_parameter = generate_params_waters()
ecdsa_parameter = generate_params_ecdsa(water_parameter)

_GS_TAG_BITS = 88  # 11 bytes × 8 bits for "UUU_DDD_CCC" tag format (uid + denomination + per-recipient coin counter)
# 5 GWat + 1 GS branch + 88 GS bits, exactly: GS is all-or-nothing and linked to GWat, so any
# spare use would let a client open both slots of a tag bit and derive keys for extra tags.
_GS_NUSECOUNT = 94


def _garble_with_gs(raw_pk, shared_key_arr, num_selectable_elem, num_possible_item_per_elem, tag, denomination):
    """Garble GWat (from shared_key_arr) plus its linked GS circuit for raw_pk.

    The coin's denomination is baked into the GS circuit: only the matching slot of each fixed
    "_DDD_" tag bit is garbled, so a re-delegator cannot evaluate it at another denomination.
    Returns (garble_msg, gs_circuit_dict) where gs_circuit_dict includes its "epk".
    """
    gs_epk = b""
    gs_shared_keys = []
    for _ in range(1 + _GS_TAG_BITS * 2):
        priv = ec.generate_private_key(ec.SECP256R1())
        gs_epk += priv.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        gs_shared_keys.append(priv.exchange(ec.ECDH(), raw_pk))
    garble_msg, gs_str = garble_waters_with_gs(
        water_parameter, shared_key_arr, num_selectable_elem, num_possible_item_per_elem, tag,
        gs_shared_keys, _GS_TAG_BITS, denomination,
    )
    gs_json = json.loads(gs_str)
    gs_json["epk"] = urlsafe_b64encode(gs_epk).decode("ascii")
    return garble_msg, gs_json

def getpresig_fn(att_json, tag="001_000", denomination=1):
    # att_json = json.loads((request.args.get('attestation')))
    is_valid_att, targetpk, nusecount = verify_attestation(att_json)
    assert nusecount==40 or nusecount==5 or nusecount==10 or nusecount==_GS_NUSECOUNT, "Currently only support nUSE Count = 40/5/10/" + str(_GS_NUSECOUNT) + ", received:" +  str(nusecount)
    # nusecount==_GS_NUSECOUNT: GWat uses 5 positions (same as nusecount==5), GS uses the remaining slots
    if nusecount==40:
        num_selectable_elem = 40
        num_possible_item_per_elem = 2
    elif nusecount==10:
        num_selectable_elem = 10
        num_possible_item_per_elem = 16
    else:  # nusecount==5 or nusecount==_GS_NUSECOUNT
        num_selectable_elem = 5
        num_possible_item_per_elem = 256
    if not is_valid_att:
        return None
    raw_pk = targetpk

    epk=b""
    shared_key_arr = []
    for _ in range(num_selectable_elem):
        for _ in range(num_possible_item_per_elem):
            private_key = ec.generate_private_key(ec.SECP256R1())
            epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
            shared_key_arr.append(private_key.exchange(ec.ECDH(), raw_pk))

    gs_circuit = None
    if nusecount == _GS_NUSECOUNT:
        garble_msg, gs_circuit = _garble_with_gs(raw_pk, shared_key_arr, num_selectable_elem, num_possible_item_per_elem, tag, denomination)
    else:
        garble_msg = garble_waters(water_parameter, shared_key_arr, num_selectable_elem, num_possible_item_per_elem, tag)

    return garble_msg, epk, gs_circuit


def _garble_one_circuit(raw_pk, tag, denomination):
    """Garble one Waters circuit (GWat + GS) for a single AndroidKeyStore pubkey and tag.

    Always generates the GS circuit (1 + 2 × _GS_TAG_BITS slots) alongside GWat (5 positions × 256 items),
    so the returned circuit supports both Pay and offline Re-delegate.
    Returns (epk_bytes, garble_msg, gs_circuit_dict).
    """
    num_selectable_elem = 5
    num_possible_item_per_elem = 256

    epk = b""
    shared_key_arr = []
    for _ in range(num_selectable_elem):
        for _ in range(num_possible_item_per_elem):
            priv = ec.generate_private_key(ec.SECP256R1())
            epk += priv.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
            shared_key_arr.append(priv.exchange(ec.ECDH(), raw_pk))
    garble_msg, gs_json = _garble_with_gs(raw_pk, shared_key_arr, num_selectable_elem, num_possible_item_per_elem, tag, denomination)

    return epk, garble_msg, gs_json


# TODO: merge with above / call the above function
@app.route("/api/delegatedpresig", methods=["GET"])
def getpresig():
    att_json = json.loads((request.args.get('attestation')))
    is_valid_att, targetpk, nusecount = verify_attestation(json.loads(request.args.get('attestation'))["att"])
    assert nusecount==40 or nusecount==5 or nusecount==10 or nusecount==_GS_NUSECOUNT, "Currently only support nUSE Count = 40/5/10/" + str(_GS_NUSECOUNT) + ", received:" +  str(nusecount)
    if nusecount==40:
        num_selectable_elem = 40
        num_possible_item_per_elem = 2
    elif nusecount==10:
        num_selectable_elem = 10
        num_possible_item_per_elem = 16
    else:  # nusecount==5 or nusecount==_GS_NUSECOUNT
        num_selectable_elem = 5
        num_possible_item_per_elem = 256

    if not is_valid_att:
        return jsonify("NONE")
    raw_pk = targetpk

    epk=b""
    shared_key_arr = []
    for _ in range(num_selectable_elem):
        for _ in range(num_possible_item_per_elem):
            private_key = ec.generate_private_key(ec.SECP256R1())
            epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
            shared_key_arr.append(private_key.exchange(ec.ECDH(), raw_pk))
    denomination = int(request.args.get('denomination', 1))
    cfg = denomination_config(denomination)

    gs_circuit = None
    if nusecount == _GS_NUSECOUNT:
        garble_msg, gs_circuit = _garble_with_gs(raw_pk, shared_key_arr, num_selectable_elem, num_possible_item_per_elem, cfg["tag"], denomination)
    else:
        garble_msg = garble_waters(water_parameter, shared_key_arr, num_selectable_elem, num_possible_item_per_elem, cfg["tag"])

    # Bank locks ETH in HTLC — this card now represents a redeemable coin
    contract_id_hex = ""
    try:
        _init_web3()
        _ensure_setup()
        timelock = int(time.time()) + 3600
        receipt_new = _send_tx(
            _htlc.functions.newContract(_eth_acct.address, cfg["hashlock"], timelock),
            value=_w3.to_wei(cfg["eth"], 'ether')
        )
        logs = _htlc.events.HTLCETHNew().process_receipt(receipt_new)
        contract_id_hex = logs[0]['args']['contractId'].hex()
        print(f"[NEW] HTLC created, denomination={denomination}, contract_id={contract_id_hex}")
    except Exception as e:
        print(f"[WARN] HTLC newContract skipped: {e}")

    params_public = json.loads(water_parameter)
    params_public.pop('beta_secret', None)
    resp = {"epk": urlsafe_b64encode(epk).decode("ascii"), "params": json.dumps(params_public), "msg": garble_msg, "contract_id": contract_id_hex, "denomination": denomination}
    if gs_circuit is not None:
        resp["gs_circuit"] = gs_circuit
    return jsonify(resp)

def getpresigecdsa_fn(att_json):
    is_valid_att, targetpk, nusecount = verify_attestation(att_json)
    assert nusecount==256 or nusecount==32 or nusecount==64, "Currently only support nUSE Count = 256/32, received:" +  str(nusecount)
    num_selectable_elem = nusecount
    if nusecount==256:
        num_possible_item_per_elem = 2 #Bit version is 2, byte version is 256
    elif nusecount==64:
        num_possible_item_per_elem = 16
    else:
        num_possible_item_per_elem = 256
        
    if not is_valid_att:
        return None
    targetpk = [targetpk]*num_selectable_elem #Assuming n-Use-Key

    epk=b""
    shared_key_arr = []
    for i in range(num_selectable_elem):
        for _ in range(num_possible_item_per_elem):
            # Sha256
            private_key = ec.generate_private_key(
                ec.SECP256R1()
            )
            epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
            shared_key = private_key.exchange(
                ec.ECDH(), targetpk[i]
            )
            shared_key_arr.append(shared_key)
    garble_msg = garble_ecdsa(ecdsa_parameter, shared_key_arr, num_selectable_elem, num_possible_item_per_elem)
    return garble_msg
# TODO: merge with above
@app.route("/api/delegatedpresigecdsa", methods=["GET"])
def getpresigecdsa():
    att_json = json.loads((request.args.get('attestation')))
    is_valid_att, targetpk, nusecount = verify_attestation(json.loads(request.args.get('attestation'))["att"])
    assert nusecount==256 or nusecount==32 or nusecount==64, "Currently only support nUSE Count = 256/32, received:" +  str(nusecount)
    num_selectable_elem = nusecount
    if nusecount==256:
        num_possible_item_per_elem = 2 #Bit version is 2, byte version is 256
    elif nusecount==64:
        num_possible_item_per_elem = 16
    else:
        num_possible_item_per_elem = 256
        
    print(f"DEBUG attestation check: is_valid_att={is_valid_att}, nusecount={nusecount}")
    if not is_valid_att:
        return jsonify("NONE")
    targetpk = [targetpk]*num_selectable_elem #Assuming n-Use-Key

    epk=b""
    shared_key_arr = []
    for i in range(num_selectable_elem):
        for _ in range(num_possible_item_per_elem):
            # Sha256
            private_key = ec.generate_private_key(
                ec.SECP256R1()
            )
            epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
            shared_key = private_key.exchange(
                ec.ECDH(), targetpk[i]
            )
            shared_key_arr.append(shared_key)
    garble_msg = garble_ecdsa(ecdsa_parameter, shared_key_arr, num_selectable_elem, num_possible_item_per_elem)

    return jsonify({"epk": urlsafe_b64encode(epk).decode("ascii"), "params": ecdsa_parameter, "msg": garble_msg})


used_signatures = set()

@app.route("/api/verifypayment", methods=["POST"])
def verifypayment():
    data = request.get_json()
    r_hex = data.get("r", "")
    s_hex = data.get("s", "")
    sig_key = f"{r_hex}:{s_hex}"
    if sig_key in used_signatures:
        print(f"PAYMENT REJECTED: signature already used r={r_hex[:16]}...")
        return jsonify({"valid": False, "reason": "signature already used"})
    used_signatures.add(sig_key)
    print(f"PAYMENT ACCEPTED: r={r_hex[:16]}...")
    return jsonify({"valid": True})


@app.route("/api/waters_solidity_params", methods=["GET"])
def waters_solidity_params():
    id = int(request.args.get('id', 1))
    result = water_unlock_solidity(water_parameter, id)
    return jsonify(json.loads(result))

class _BadRequest(Exception):
    """Client error in a contract-spending endpoint; mapped to HTTP 400."""

def _contract_denomination(body):
    """Resolve (contract_id_hex, contract_id_bytes, denomination) for a spend request.

    The denomination comes from the on-chain contract (its hashlock is fixed per denomination),
    never from the request. A denomination in the body is only accepted if it agrees.
    Raises _BadRequest for a missing/malformed/unknown contract or a mismatching denomination.
    """
    contract_id_hex = (body.get('contract_id') or '').strip()
    if not contract_id_hex:
        raise _BadRequest('contract_id missing — was this card created with blockchain enabled?')
    try:
        contract_id_bytes = bytes.fromhex(contract_id_hex.removeprefix('0x'))
    except ValueError:
        raise _BadRequest('contract_id is not valid hex')
    if len(contract_id_bytes) != 32:
        raise _BadRequest('contract_id must be 32 bytes')

    _init_web3()
    _ensure_setup()
    try:
        *_, hashlock, _timelock, withdrawn, refunded, _preimage = _htlc.functions.getContract(contract_id_bytes).call()
    except Exception as e:
        raise _BadRequest(f'unknown contract {contract_id_hex}: {e}')
    if withdrawn or refunded:
        raise _BadRequest('contract already withdrawn or refunded')
    by_hashlock = {denomination_config(d)['hashlock']: d for d in _DENOM_ETH}
    if hashlock not in by_hashlock:
        raise _BadRequest(f'contract has unsupported hashlock {hashlock}')
    denomination = by_hashlock[hashlock]

    claimed = body.get('denomination')
    try:
        mismatch = claimed is not None and int(claimed) != denomination
    except (TypeError, ValueError):
        mismatch = True
    if mismatch:
        raise _BadRequest(f'denomination {claimed} does not match the contract ({denomination})')
    return contract_id_hex, contract_id_bytes, denomination

@app.route('/api/redelegate', methods=['POST'])
def redelegate():
    """Withdraw Alice's HTLC and create a fresh HTLC for Bob at the same denomination.

    Body: {contract_id, denomination?}
    Returns: {contract_id} — Bob's new HTLC id.
    Alice has already computed ak2 offline via GS evaluation; the server only handles HTLCs.
    The denomination is taken from Alice's on-chain contract; a request denomination that
    differs is rejected. Bob's HTLC is only created after Alice's withdrawal is confirmed.
    """
    try:
        body = request.get_json(silent=True) or {}
        alice_contract_id_hex, alice_contract_id_bytes, denomination = _contract_denomination(body)
        cfg = denomination_config(denomination)

        # Withdraw Alice's HTLC using server-derived key (beta_secret on server)
        try:
            sol = json.loads(water_unlock_solidity(water_parameter, denomination))
            preimage = (_g1(sol['sk1']), _g1(sol['sk2']), _g2(sol['sk3']))
            receipt_old = _send_tx(_htlc.functions.withdraw(alice_contract_id_bytes, preimage))
        except Exception as e:
            return jsonify({'error': f"withdrawing Alice's HTLC failed: {e}"}), 500
        if receipt_old['status'] != 1:
            return jsonify({'error': "withdrawing Alice's HTLC failed on-chain"}), 500
        print(f"[REDELEGATE] withdrew Alice's HTLC {alice_contract_id_hex[:10]}...")

        # Create Bob's HTLC at same denomination
        timelock = int(time.time()) + 3600
        receipt = _send_tx(
            _htlc.functions.newContract(_eth_acct.address, cfg["hashlock"], timelock),
            value=_w3.to_wei(cfg["eth"], 'ether')
        )
        if receipt['status'] != 1:
            return jsonify({'error': 'newContract for Bob failed'}), 500

        logs = _htlc.events.HTLCETHNew().process_receipt(receipt)
        contract_id_hex = logs[0]['args']['contractId'].hex()
        print(f"[REDELEGATE] Bob's HTLC created denomination={denomination} contract_id={contract_id_hex}")
        return jsonify({'contract_id': contract_id_hex})
    except _BadRequest as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/replenish', methods=['POST'])
def replenish():
    """Batch-issue Waters dmks to top up Alice's wallet to her target coin counts.

    Body: {
        "attestations": [{ "att": [...] }, ...],   # one per coin, in request order
        "request": [{"denomination": N, "count": K}, ...]
    }
    Each coin gets its own AndroidKeyStore key with nusecount == _GS_NUSECOUNT. A shared key
    with a pooled budget would let a client leave one coin unused and spend its ECDH uses on
    opening both slots of another coin's GS bits.
    Returns: {
        "params": "<Waters public params JSON, beta_secret stripped>",
        "circuits": [{"denomination", "contract_id", "epk", "msg", "gs_circuit"}, ...]
    }
    """
    body = request.get_json()
    request_list = body.get('request', [])
    total_count = sum(int(r['count']) for r in request_list)
    if total_count == 0:
        return jsonify({'error': 'no checks requested'}), 400

    attestations = body.get('attestations', [])
    if len(attestations) != total_count:
        return jsonify({'error': f'{len(attestations)} attestations for {total_count} coins (need one key per coin)'}), 400
    raw_pks = []
    for att in attestations:
        is_valid_att, raw_pk, nusecount = verify_attestation(att['att'])
        if not is_valid_att:
            return jsonify({'error': 'invalid attestation'}), 400
        if nusecount != _GS_NUSECOUNT:
            return jsonify({'error': f'nusecount {nusecount} != {_GS_NUSECOUNT}'}), 400
        raw_pks.append(raw_pk)

    params_public = json.loads(water_parameter)
    params_public.pop('beta_secret', None)

    circuits = []
    for req in request_list:
        denomination = int(req['denomination'])
        count = int(req['count'])
        cfg = denomination_config(denomination)
        for _ in range(count):
            epk, garble_msg, gs_circuit = _garble_one_circuit(raw_pks[len(circuits)], cfg['tag'], denomination)
            circuits.append({
                'denomination': denomination,
                'contract_id': "",
                'epk': urlsafe_b64encode(epk).decode('ascii'),
                'msg': garble_msg,
                'gs_circuit': gs_circuit,
            })

    return jsonify({'params': json.dumps(params_public), 'circuits': circuits})


@app.route('/api/lock', methods=['POST'])
def lock():
    """Lock capital for one dormant dmk right before it's spent (Withdraw or Re-delegate).

    Body: {"denomination": N}
    Returns: {"contract_id": hex}  (or {"error": ...}, 500/400)
    """
    try:
        _init_web3()
        _ensure_setup()
        denomination = int(request.json.get('denomination', 1))
        cfg = denomination_config(denomination)
        timelock = int(time.time()) + 3600
        receipt = _send_tx(
            _htlc.functions.newContract(_eth_acct.address, cfg['hashlock'], timelock),
            value=_w3.to_wei(cfg['eth'], 'ether')
        )
        if receipt['status'] != 1:
            return jsonify({'error': 'newContract failed'}), 500
        logs = _htlc.events.HTLCETHNew().process_receipt(receipt)
        contract_id_hex = logs[0]['args']['contractId'].hex()
        print(f"[LOCK] denomination={denomination} contract_id={contract_id_hex}")
        return jsonify({'contract_id': contract_id_hex})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _user_id_from_tag(tag: str) -> int:
    """Extract user_id from a 'UUU_DDD' tag string."""
    try:
        return int(tag.split('_')[0])
    except (IndexError, ValueError):
        return 0

@app.route('/api/pay', methods=['POST'])
def pay():
    try:
        contract_id_hex, contract_id_bytes, denomination = _contract_denomination(request.get_json(silent=True) or {})
        print(f"[PAY] withdraw requested for contract_id={contract_id_hex}, denomination={denomination}")
        sol = json.loads(water_unlock_solidity(water_parameter, denomination))

        preimage = (_g1(sol['sk1']), _g1(sol['sk2']), _g2(sol['sk3']))
        receipt_withdraw = _send_tx(_htlc.functions.withdraw(contract_id_bytes, preimage))
        if receipt_withdraw['status'] != 1:
            return jsonify({'error': 'withdraw failed on-chain'}), 500

        return jsonify({
            'tx_hash':     receipt_withdraw['transactionHash'].hex(),
            'contract_id': contract_id_hex,
        })
    except _BadRequest as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── FDE purchase on Bitcoin regtest (Part C of CLAUDE_replace_HTLC.md) ───────
# Alternative to the zfairexchange.sol HTLC, alongside it: Alice buys a coin by fair exchange.
# The Bank sends a signed offer (encrypted Waters key, Y_chain = x·G, cross-group proof); Alice
# checks it, locks BTC in a two-signature P2WSH output and pre-signs the Bank's claim; the claim
# reveals x on-chain and Alice decrypts sk3 herself. No pairing on-chain, no beta_secret to Alice.
# Regtest only: bitcoind -regtest -datadir=$BTC_DATADIR (thesis_log/ecdsa-adaptor-secp256k1.md).
import subprocess
import secrets

BTC_DATADIR = os.environ.get("BTC_DATADIR", os.path.expanduser("~/btc-regtest"))
# Bank's secp256k1 chain key; Alice must know the public key in advance (shipped with the app).
# Without BTC_BANK_KEY a fresh key is drawn per server run, so open offers die with the server.
_FDE_BANK_SK = os.environ.get("BTC_BANK_KEY", "") or fde_keypair()[0]
_FDE_BANK_PK = fde_pubkey(_FDE_BANK_SK)
_FDE_PAYOUT = btc_p2wpkh_address(_FDE_BANK_PK)
_DENOM_SAT = {d: round(v * 100_000_000) for d, v in _DENOM_ETH.items()}  # same nominal amounts, in BTC
FDE_TIMELOCK_BLOCKS = 144  # ~1 day on mainnet
FDE_CLAIM_MARGIN = 12      # the claim must CONFIRM before the timelock (B3.11b); ~2 h on mainnet
FDE_MIN_CONF = 1
FDE_CLAIM_FEE = 1_000      # sat; fixed by Alice's pre-signature (SIGHASH_ALL)

# offer_id -> {"terms": dict, "x": hex, "state": "offered" | "claimed" | "expired"}
_fde_offers: dict = {}

def _btc(*args):
    out = subprocess.run(["bitcoin-cli", "-regtest", f"-datadir={BTC_DATADIR}", *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip())
    return out.stdout.strip()

@app.route('/api/fde/bank', methods=['GET'])
def fde_bank():
    """The Bank's chain key and lock parameters (Alice pins bank_pk)."""
    return jsonify({'bank_pk': _FDE_BANK_PK, 'network': 'regtest', 'denominations_sat': _DENOM_SAT,
                    'timelock_blocks': FDE_TIMELOCK_BLOCKS, 'claim_margin': FDE_CLAIM_MARGIN,
                    'claim_fee': FDE_CLAIM_FEE})

@app.route('/api/fde/offer', methods=['POST'])
def fde_offer():
    """Issue a signed offer for one coin to an attested device.

    Body: {"attestation": [cert, ...], "denomination": N, "alice_pk": hex, "user_id": U}
    Returns: {"terms": canonical JSON string, "sig": Bank's ECDSA signature over it}
    """
    try:
        body = request.get_json(silent=True) or {}
        if not body.get('attestation'):
            raise _BadRequest('attestation missing')
        # Identity binding (gate): offers go only to an attested AndroidKeyStore key.
        try:
            is_valid_att, attested_pk, _nusecount = verify_attestation(body['attestation'])
        except Exception:
            is_valid_att = False
        if not is_valid_att:
            return jsonify({'error': 'attestation rejected'}), 403
        try:
            denomination = int(body.get('denomination', 1))
            user_id = int(body.get('user_id', 0))
        except (TypeError, ValueError):
            raise _BadRequest('denomination and user_id must be integers')
        if denomination not in _DENOM_SAT:
            raise _BadRequest(f'unsupported denomination {denomination}')
        alice_pk = body.get('alice_pk') or ''
        timelock = int(_btc('getblockcount')) + FDE_TIMELOCK_BLOCKS
        try:
            lock = json.loads(btc_lock(alice_pk, _FDE_BANK_PK, timelock))
        except ValueError as e:
            raise _BadRequest(f'alice_pk: {e}')
        tag = make_tag(denomination, user_id)
        made = json.loads(fde_make_offer(water_parameter, tag))
        offer_id = secrets.token_hex(16)
        terms = {
            'offer_id': offer_id, 'tag': tag, 'denomination': denomination,
            'amount_sat': _DENOM_SAT[denomination], 'timelock': timelock,
            'lock_address': lock['address'], 'lock_script': lock['script'],
            'payout_address': _FDE_PAYOUT, 'claim_fee': FDE_CLAIM_FEE,
            'alice_pk': alice_pk, 'bank_pk': _FDE_BANK_PK,
            'attested_key': sha256(attested_pk.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)).hex(),
            'offer': made['offer'],
        }
        terms_str = json.dumps(terms, sort_keys=True, separators=(',', ':'))
        _fde_offers[offer_id] = {'terms': terms, 'x': made['x'], 'state': 'offered'}
        print(f"[FDE] offer {offer_id} tag={tag} amount={terms['amount_sat']} sat timelock={timelock}")
        return jsonify({'terms': terms_str, 'sig': fde_sign(_FDE_BANK_SK, terms_str)})
    except _BadRequest as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/fde/claim', methods=['POST'])
def fde_claim():
    """Claim Alice's lock, revealing x: check the lock on-chain and her pre-signature, complete it.

    Body: {"offer_id": id, "txid": hex, "vout": n, "presig": {...}}
    Returns: {"txid": claim txid}. 409 if not yet confirmed, already claimed, or too close to
    the timelock (the Bank then never reveals x for this offer, and Alice refunds).
    """
    try:
        body = request.get_json(silent=True) or {}
        rec = _fde_offers.get(body.get('offer_id') or '')
        if rec is None:
            return jsonify({'error': 'unknown offer'}), 404
        if rec['state'] != 'offered':
            return jsonify({'error': f"offer already {rec['state']}"}), 409
        t = rec['terms']
        try:
            txid, vout = str(body['txid']), int(body['vout'])
            presig = body['presig'] if isinstance(body['presig'], str) else json.dumps(body['presig'])
        except (KeyError, TypeError, ValueError):
            raise _BadRequest('txid, vout and presig required')

        utxo = _btc('gettxout', txid, str(vout)) if all(c in '0123456789abcdef' for c in txid) and len(txid) == 64 else ''
        if not utxo:
            raise _BadRequest('lock output not found or already spent')
        utxo = json.loads(utxo)
        if utxo['scriptPubKey'].get('address') != t['lock_address'] or round(utxo['value'] * 100_000_000) != t['amount_sat']:
            raise _BadRequest('output is not the agreed lock (address or amount differs)')
        if utxo['confirmations'] < FDE_MIN_CONF:
            return jsonify({'error': 'lock not confirmed yet'}), 409
        height = int(_btc('getblockcount'))
        if not height + FDE_CLAIM_MARGIN < t['timelock']:
            rec['state'] = 'expired'
            return jsonify({'error': f"too close to the timelock ({height} + {FDE_CLAIM_MARGIN} >= {t['timelock']}); not revealing x"}), 409

        unsigned = json.loads(btc_spend(t['lock_script'], txid, vout, t['amount_sat'], t['payout_address'], t['claim_fee'], 0))
        try:
            claim_hex = fde_complete_claim(unsigned['tx'], t['lock_script'], t['amount_sat'], t['alice_pk'],
                                           t['offer']['y_chain'], presig, rec['x'], _FDE_BANK_SK)
        except ValueError as e:
            raise _BadRequest(str(e))
        claim_txid = _btc('sendrawtransaction', claim_hex)
        rec['state'] = 'claimed'
        print(f"[FDE] claimed offer {t['offer_id']}: {claim_txid}")
        return jsonify({'txid': claim_txid})
    except _BadRequest as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/api/verifyattest", methods=["GET"])
def verifyattest():
    att_json = json.loads((request.args.get('attestation')))
    is_valid_att, targetpk, nusecount = verify_attestation(json.loads(request.args.get('attestation'))["att"])
    return jsonify({"status": "ok"})

@app.route("/api/register", methods=["GET"])
def register_user():
    global _next_user_id
    att_json = json.loads(request.args.get('attestation'))
    _is_valid, targetpk, nusecount = verify_attestation(att_json["att"])

    user_id = _next_user_id
    _next_user_id += 1

    pubkeys_b64 = [
        base64.urlsafe_b64encode(pk.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)).decode()
        for pk in targetpk
    ]
    _user_registry[user_id] = {"pubkeys": pubkeys_b64, "nusecount": nusecount}

    print(f"[REGISTER] user_id={user_id} nusecount={nusecount}")
    return jsonify({"user_id": user_id, "pubkeys": pubkeys_b64})

def verify_attestation(att):
    cert_arr = []
    cert_raw_arr =[]
    for cert_b64 in att:
        cert_raw = base64.urlsafe_b64decode(cert_b64)
        temp_cert = x509.load_der_x509_certificate(cert_raw)
        cert_arr.append(temp_cert)
        cert_raw_arr.append(cert_raw)

    is_valid_chain = True
    for i in reversed(range(len(cert_arr))):
        if i==0:
            break
        signer_cert = cert_arr[i]
        issued_cert = cert_arr[i-1]
        try:
            # This method verifies that the certificate issuer name matches the issuer subject name and that the certificate is signed by the issuer’s private key. Note missing checking cert validity date or revocation list if exist
            is_signed_by = issued_cert.verify_directly_issued_by(signer_cert)
        except:
            is_valid_chain= False
            break
    has_valid_root_cert = False
    root_cert_raw_bytes= cert_raw_arr[-1]
    cert_obj = pem.parse_file(filename)
    for co in cert_obj:
        rootcert = x509.load_pem_x509_certificate(co.as_bytes())     
        if root_cert_raw_bytes == rootcert.public_bytes(Encoding.DER):
            has_valid_root_cert = True
            break
    
    
        
    has_valid_property = False
    # See https://cs.android.com/android/platform/superproject/+/master:prebuilts/vndk/v30/arm/include/generated-headers/hardware/interfaces/keymaster/4.1/android.hardware.keymaster@4.1_genc++_headers/gen/android/hardware/keymaster/4.1/IKeymasterDevice.h?q=1.3.6.1.4.1.11129.2.1.17&ss=android%2Fplatform%2Fsuperproject
    # Check Limited N-times usage is present, exact verification depends on trust/threat model and compactability requirement
    # The check below is not complete, IE security level, and key use count should be checked according to the correct upperbound imposed by the actual functional requirement.
    # The check below is only done for convenient of benchmarking across different configurations.
    oid_string = '1.3.6.1.4.1.11129.2.1.17'
    extension_obj = cert_arr[0].extensions.get_extension_for_oid(ObjectIdentifier(oid_string))
    extension_data = extension_obj.value.value
    seq = Sequence.load(extension_data)
    
    asn1_sequence_obj = seq[1]

    asn1_sequence_obj = seq[7]
    decoder = asn1.Decoder()
    decoder.start(asn1_sequence_obj._contents)
    tag, value = decoder.read()
    keycount = 0
    while tag != None:
        if tag.nr == 405:
            if isinstance(value, bytes):
                value, _ = pyasn1decoder.decode(value)
            if isinstance(value, list):
                value = value[0] if value else 0
            keycount = int(value)
            if keycount in {1, 5, 10, 20, 32, 40, 64, 160, 256, _GS_NUSECOUNT}:
                has_valid_property = True
        read_result = decoder.read()
        if read_result!=None:
            tag, value = read_result
        else:
            tag=None
            value = None
    asn1_sequence_obj = seq[6]
    decoder = asn1.Decoder()
    decoder.start(asn1_sequence_obj._contents)
    tag, value = decoder.read()
    while tag != None:
        if tag.nr == 405:
            if isinstance(value, bytes):
                value, _ = pyasn1decoder.decode(value)
            if isinstance(value, list):
                value = value[0] if value else 0
            keycount = int(value)
            has_valid_property = True
        read_result = decoder.read()
        if read_result!=None:
            tag, value = read_result
        else: 
            tag=None
            value = None
    # Extract PK 
    pk = cert_arr[0].public_key()

    print(f"DEBUG verify_attestation: is_valid_chain={is_valid_chain}, has_valid_root_cert={has_valid_root_cert}, has_valid_property={has_valid_property}, keycount={keycount}")

    return (is_valid_chain and has_valid_root_cert and has_valid_property, pk, int(keycount) )


# def run_server():
#     app.run(ssl_context="adhoc", debug=False)

def internal_presig_bench(x):
    getpresig_fn(x)
def internal_presigecdsa_bench(x):
    getpresigecdsa_fn(x)
@app.route("/api/benchmarkdelegatewaters", methods=["GET"])
def benchmark_delegation():
    num_iter  = 1
    # number_of_thread = 1
    number_of_thread = cpu_count()
    print(json.loads(request.args.get('attestation'))["att"])
    work = [json.loads(request.args.get('attestation'))["att"]]*(num_iter)
    parallel_start= time.time()
    with Pool(number_of_thread) as p:
        exe_time = p.map(internal_presig_bench, work)
    parallel_time = time.time() - parallel_start
    print(f"BENCHMARK RDelegate Waters")
    print(f"Avg using {number_of_thread} thread : {(parallel_time*1.0/num_iter):.6f} seconds")
    return jsonify({"Avg Parallel": f"{parallel_time*1.0/num_iter} seconds", "Thread Count": f"{number_of_thread}"})

def benchmark_delegation_noserver():
    json_dict_water = json.loads('{"att":["MIICsjCCAligAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIDQwZTljMDExYjE2YjYzMmI0ZDYxOGE4ZmFmM2Q3NmRhMB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQvqDxMkSWFoT7ntwD0Y6BfKS4sfxEZmCgQVoZknE_6nefVW_3gZ6W78GQ_FcAnE7GAJA1QDte8ezQcgkvyMyO5o4IBaTCCAWUwDgYDVR0PAQH_BAQDAgMIMIIBUQYKKwYBBAHWeQIBEQSCAUEwggE9AgIBkAoBAQICAZAKAQEEA0BBQgQAMIGIv4MVAwIBBb-FPQgCBgGadzSZc7-FRUsESTBHMSEwHwQaY29tLmV4YW1wbGUucGF5bWVudGJveF9vdHACAQExIgQg88CV7x5Y5z4mf-6R6vg8_5d7PJUOKb4VxdOKiU5ENXC_hVQiBCD0j63uE68iNhycWDHb5MPeIigL6RpKr_LEGcTDfY7kijCBmqEFMQMCAQaiAwIBA6MEAgIBAKoDAgEBv4N3AgUAv4U-AwIBAL-FQEwwSgQgMyevYthKuJevJSOhbctYAeYMXVuX9ByhvQmcR4T3t0MBAf8KAQAEIECtUXTH1E8T-jSy-TsHOluhOFA4WsgN5zikvhXyKHQAv4VBBQIDAnEAv4VCBQIDAxcOv4VOBgIEATUBfb-FTwYCBAE1AX0wCgYIKoZIzj0EAwIDSAAwRQIhAJobF2Oedslo19M8BopQn4NWIDyAiz-kioF7c9QMR0uHAiAG2VyRcsJEwsLoHxw8MWk3YR2HnBt_kQEzKbg3-H32YA==","MIIB3jCCAYSgAwIBAgIQQOnAEbFrYytNYYqPrz122jAKBggqhkjOPQQDAjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTMwHhcNMjUxMDIwMTcwMDIxWhcNMjUxMTE0MTgyNDUyWjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIDQwZTljMDExYjE2YjYzMmI0ZDYxOGE4ZmFmM2Q3NmRhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnE731oWWQf70hlc5pconKKLfHTtbSs8CqnNasjo4RFuFH-1G4qkV21hb3L1KlGk0KmXq7m3kiR3TbMYhSByMjqN-MHwwHQYDVR0OBBYEFBE_dI1ahOW2GTHnCqlu_FQ172EYMB8GA1UdIwQYMBaAFE5EpOYn5Yx2pewd1LFHCU5o68_HMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgIEMBkGCisGAQQB1nkCAR4EC6IBCANmR29vZ2xlMAoGCCqGSM49BAMCA0gAMEUCIQC6cyfer4YiUHg9vVrm6arNbvK6SqzgT7vmZ0MV8XvigAIgZsfUkjKDRd4Pnu6Nd-2k4UpuiiZJeXTYzAUfsjIFd_U=","MIIB1jCCAV2gAwIBAgIUAJZYwD0Cye4q0BUT37V0-UqcQbEwCgYIKoZIzj0EAwMwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMB4XDTI1MTAyMTE2MjQxOFoXDTI1MTIzMDE2MjQxN1owKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHFUJMCMP9HmSvHcD7draJRFoYOo3yGR9Uh1q774evbYWDDKpd5c0ovKEFqxpum1t-3SXwqksoK6ZuQ2zrr2hbqNjMGEwDgYDVR0PAQH_BAQDAgIEMA8GA1UdEwEB_wQFMAMBAf8wHQYDVR0OBBYEFE5EpOYn5Yx2pewd1LFHCU5o68_HMB8GA1UdIwQYMBaAFDmYBwY6MxKe9RQGOoBBDHGAzhqtMAoGCCqGSM49BAMDA2cAMGQCMBpKS5ZmtiKJ42rknBCwR7EU-GBeyC2Y07FZ2-zUgSgTloEH1pxyC2Vr7EDcFPjFqAIwPrrcn-4UAvE-h5xF5ha5xqrVP-CsSoexiH8KAnmRQKmQCrEESXykzwvWU4MfnM1C","MIIDgDCCAWigAwIBAgIKA4gmZ2BliZaGDzANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIyMDEyNjIyNTAyMFoXDTM3MDEyMjIyNTAyMFowKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE_t-4AI454D8pM32ZUEpuaS0ewLjFP9EBOnCF4Kkz2jqcDECp0fjy34AaTCgJnpGdCLIU3u_WXBs3pEECgMuS9RVSKqj584wdbpcxiJahZWSzHqPK1Nn5LZYdQIpLJ9cUo2YwZDAdBgNVHQ4EFgQUOZgHBjozEp71FAY6gEEMcYDOGq0wHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR_8aTMnqTxIwEgYDVR0TAQH_BAgwBgEB_wIBAjAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAD0FO58gwWQb6ROp4c7hkOwQiWiCTG2Ud9Nww5cKlsMU8YlZOk8nXn5OwAfuFT01Kgcbau1CNDECX7qA1vJyQ9HBsoqa7fmi0cf1j_RRBvvAuGvg3zRy0-OckwI2832399l_81FMShS-GczTWfhLJY_ObkVBFkanRCpDhE_SxNHL_5nJzYaH8OdjAKufnD9mcFyYvzjixbcPEO5melGwk7KfCx9miSpVuB6mN1NdoCsSi96ZYQGBlZsE8oLdazckCygTvp2s77GtIswywOHf3HEa39OQm8B8g2cHcy4u5kKoFeSPI9zo6jx-WDb1Er8gKZT1u7lrwCW-JUQquYbGHLzSDIsRfGh0sTjoRH_s4pD371OYAkkPMHVguBZE8iv5uv0j4IBwN_eLyoQb1jmBv_dEUU9ceXd_s8b5-8k7PYhYcDMA0oyFQcvrhLoWbqy7BrY25iWEY5xH6EsHFre5vp1su17Rdmxby3nt7mXz1NxBQdA3rM-kcZlfcK9sHTNVTI290Wy9IS-8_xalrtalo4PA6EwofyXy18XI9AddNs754KPf8_yAMbVc_2aClm1RF7_7vB0fx3eQmLE4WS01SsqsWnCsHCSbyjdIaIyKBFQhABtIIxLNYLFw-0nnA7DBU_M1e9gWBLh8dz1xHFo-Tn5edYaY1bYyhlGBKUKG4M8l","MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd_dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy_4lj4_7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1-di-y9TFRtv6y__0rb-T-W8a9nsNL_ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB_M0n1n_W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl_m00QLVWutHQoVJYnFPlXTcHYvASLu-RhhsbDmxMgJJ0mcDpvsC4PjvB-TxywElgS70vE0XmLD-OJtvsBslHZvPBKCOdT0MS-tgSOIfga-z1Z1g7-DVagf7quvmag8jfPioyKvxnK_EgsTUVi2ghzq8wm27ud_mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws-W0rB5N-er5_2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI_-MRPjy02i59lINMRRev56GKtcd9qO_0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab-9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ-8PTWm2QgBR_bkwSWc-NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf_GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf_GkzJ6k8SMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83Uh6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG-mEkN8_TA6p3cnoL_sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5_cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC_vAD32KdNQ-c3N-vl2OTsUVMC1GiWkngNx1OO1-kXW-YTnnTUOtOIswUP_Vqd5SYgAImMAfY8U9_iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz-Jucth-IqoWFua9v1R93_k98p41pjtFX-H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe_A91oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL-H7qJguBw09ojm6xNIrw2OocrDKsudk_okr_AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK_xyZFiRcrPJPb41zgbQj9XAEyLKCHex0SdDrx-tWUDqG8At2JHA=="]}')["att"]
    json_dict_ecdsa = json.loads('{"att":["MIICsTCCAligAwIBAgIBATAKBggqhkjOPQQDAjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIDQwZTljMDExYjE2YjYzMmI0ZDYxOGE4ZmFmM2Q3NmRhMB4XDTcwMDEwMTAwMDAwMFoXDTQ4MDEwMTAwMDAwMFowHzEdMBsGA1UEAxMUQW5kcm9pZCBLZXlzdG9yZSBLZXkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATeQIN5Hwk2_BLN4-xc27eA9gjHWtkY4kZDoaZLlpACWbqD343erlVyPnMjedOSuk3yMGms9kCGJNsNrDcm3YZso4IBaTCCAWUwDgYDVR0PAQH_BAQDAgMIMIIBUQYKKwYBBAHWeQIBEQSCAUEwggE9AgIBkAoBAQICAZAKAQEEA0BBQgQAMIGIv4MVAwIBIL-FPQgCBgGad1mMWL-FRUsESTBHMSEwHwQaY29tLmV4YW1wbGUucGF5bWVudGJveF9vdHACAQExIgQg88CV7x5Y5z4mf-6R6vg8_5d7PJUOKb4VxdOKiU5ENXC_hVQiBCD0j63uE68iNhycWDHb5MPeIigL6RpKr_LEGcTDfY7kijCBmqEFMQMCAQaiAwIBA6MEAgIBAKoDAgEBv4N3AgUAv4U-AwIBAL-FQEwwSgQgMyevYthKuJevJSOhbctYAeYMXVuX9ByhvQmcR4T3t0MBAf8KAQAEIECtUXTH1E8T-jSy-TsHOluhOFA4WsgN5zikvhXyKHQAv4VBBQIDAnEAv4VCBQIDAxcOv4VOBgIEATUBfb-FTwYCBAE1AX0wCgYIKoZIzj0EAwIDRwAwRAIgTsfBK0b6oq3euXpxC_jhhaEyuLAYq-AO5i8x0zr_-TMCIGo8TC32zEwRgx2yVTZ6YWZjlN_o-OqivH99hlru0vOt","MIIB3jCCAYSgAwIBAgIQQOnAEbFrYytNYYqPrz122jAKBggqhkjOPQQDAjApMRMwEQYDVQQKEwpHb29nbGUgTExDMRIwEAYDVQQDEwlEcm9pZCBDQTMwHhcNMjUxMDIwMTcwMDIxWhcNMjUxMTE0MTgyNDUyWjA5MQwwCgYDVQQKEwNURUUxKTAnBgNVBAMTIDQwZTljMDExYjE2YjYzMmI0ZDYxOGE4ZmFmM2Q3NmRhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnE731oWWQf70hlc5pconKKLfHTtbSs8CqnNasjo4RFuFH-1G4qkV21hb3L1KlGk0KmXq7m3kiR3TbMYhSByMjqN-MHwwHQYDVR0OBBYEFBE_dI1ahOW2GTHnCqlu_FQ172EYMB8GA1UdIwQYMBaAFE5EpOYn5Yx2pewd1LFHCU5o68_HMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgIEMBkGCisGAQQB1nkCAR4EC6IBCANmR29vZ2xlMAoGCCqGSM49BAMCA0gAMEUCIQC6cyfer4YiUHg9vVrm6arNbvK6SqzgT7vmZ0MV8XvigAIgZsfUkjKDRd4Pnu6Nd-2k4UpuiiZJeXTYzAUfsjIFd_U=","MIIB1jCCAV2gAwIBAgIUAJZYwD0Cye4q0BUT37V0-UqcQbEwCgYIKoZIzj0EAwMwKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMB4XDTI1MTAyMTE2MjQxOFoXDTI1MTIzMDE2MjQxN1owKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHFUJMCMP9HmSvHcD7draJRFoYOo3yGR9Uh1q774evbYWDDKpd5c0ovKEFqxpum1t-3SXwqksoK6ZuQ2zrr2hbqNjMGEwDgYDVR0PAQH_BAQDAgIEMA8GA1UdEwEB_wQFMAMBAf8wHQYDVR0OBBYEFE5EpOYn5Yx2pewd1LFHCU5o68_HMB8GA1UdIwQYMBaAFDmYBwY6MxKe9RQGOoBBDHGAzhqtMAoGCCqGSM49BAMDA2cAMGQCMBpKS5ZmtiKJ42rknBCwR7EU-GBeyC2Y07FZ2-zUgSgTloEH1pxyC2Vr7EDcFPjFqAIwPrrcn-4UAvE-h5xF5ha5xqrVP-CsSoexiH8KAnmRQKmQCrEESXykzwvWU4MfnM1C","MIIDgDCCAWigAwIBAgIKA4gmZ2BliZaGDzANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTIyMDEyNjIyNTAyMFoXDTM3MDEyMjIyNTAyMFowKTETMBEGA1UEChMKR29vZ2xlIExMQzESMBAGA1UEAxMJRHJvaWQgQ0EyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE_t-4AI454D8pM32ZUEpuaS0ewLjFP9EBOnCF4Kkz2jqcDECp0fjy34AaTCgJnpGdCLIU3u_WXBs3pEECgMuS9RVSKqj584wdbpcxiJahZWSzHqPK1Nn5LZYdQIpLJ9cUo2YwZDAdBgNVHQ4EFgQUOZgHBjozEp71FAY6gEEMcYDOGq0wHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR_8aTMnqTxIwEgYDVR0TAQH_BAgwBgEB_wIBAjAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggIBAD0FO58gwWQb6ROp4c7hkOwQiWiCTG2Ud9Nww5cKlsMU8YlZOk8nXn5OwAfuFT01Kgcbau1CNDECX7qA1vJyQ9HBsoqa7fmi0cf1j_RRBvvAuGvg3zRy0-OckwI2832399l_81FMShS-GczTWfhLJY_ObkVBFkanRCpDhE_SxNHL_5nJzYaH8OdjAKufnD9mcFyYvzjixbcPEO5melGwk7KfCx9miSpVuB6mN1NdoCsSi96ZYQGBlZsE8oLdazckCygTvp2s77GtIswywOHf3HEa39OQm8B8g2cHcy4u5kKoFeSPI9zo6jx-WDb1Er8gKZT1u7lrwCW-JUQquYbGHLzSDIsRfGh0sTjoRH_s4pD371OYAkkPMHVguBZE8iv5uv0j4IBwN_eLyoQb1jmBv_dEUU9ceXd_s8b5-8k7PYhYcDMA0oyFQcvrhLoWbqy7BrY25iWEY5xH6EsHFre5vp1su17Rdmxby3nt7mXz1NxBQdA3rM-kcZlfcK9sHTNVTI290Wy9IS-8_xalrtalo4PA6EwofyXy18XI9AddNs754KPf8_yAMbVc_2aClm1RF7_7vB0fx3eQmLE4WS01SsqsWnCsHCSbyjdIaIyKBFQhABtIIxLNYLFw-0nnA7DBU_M1e9gWBLh8dz1xHFo-Tn5edYaY1bYyhlGBKUKG4M8l","MIIFHDCCAwSgAwIBAgIJANUP8luj8tazMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTkxMTIyMjAzNzU4WhcNMzQxMTE4MjAzNzU4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd_dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy_4lj4_7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1-di-y9TFRtv6y__0rb-T-W8a9nsNL_ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB_M0n1n_W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl_m00QLVWutHQoVJYnFPlXTcHYvASLu-RhhsbDmxMgJJ0mcDpvsC4PjvB-TxywElgS70vE0XmLD-OJtvsBslHZvPBKCOdT0MS-tgSOIfga-z1Z1g7-DVagf7quvmag8jfPioyKvxnK_EgsTUVi2ghzq8wm27ud_mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws-W0rB5N-er5_2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI_-MRPjy02i59lINMRRev56GKtcd9qO_0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab-9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ-8PTWm2QgBR_bkwSWc-NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf_GkzJ6k8SMB8GA1UdIwQYMBaAFDZh4QB8iAUJUYtEbEf_GkzJ6k8SMA8GA1UdEwEB_wQFMAMBAf8wDgYDVR0PAQH_BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQBOMaBc8oumXb2voc7XCWnuXKhBBK3e2KMGz39t7lA3XXRe2ZLLAkLM5y3J7tURkf5a1SutfdOyXAmeE6SRo83Uh6WszodmMkxK5GM4JGrnt4pBisu5igXEydaW7qq2CdC6DOGjG-mEkN8_TA6p3cnoL_sPyz6evdjLlSeJ8rFBH6xWyIZCbrcpYEJzXaUOEaxxXxgYz5_cTiVKN2M1G2okQBUIYSY6bjEL4aUN5cfo7ogP3UvliEo3Eo0YgwuzR2v0KR6C1cZqZJSTnghIC_vAD32KdNQ-c3N-vl2OTsUVMC1GiWkngNx1OO1-kXW-YTnnTUOtOIswUP_Vqd5SYgAImMAfY8U9_iIgkQj6T2W6FsScy94IN9fFhE1UtzmLoBIuUFsVXJMTz-Jucth-IqoWFua9v1R93_k98p41pjtFX-H8DslVgfP097vju4KDlqN64xV1grw3ZLl4CiOe_A91oeLm2UHOq6wn3esB4r2EIQKb6jTVGu5sYCcdWpXr0AUVqcABPdgL-H7qJguBw09ojm6xNIrw2OocrDKsudk_okr_AwqEyPKw9WnMlQgLIKw1rODG2NvU9oR3GVGdMkUBZutL8VuFkERQGt6vQ2OCw0sV47VMkuYbacK_xyZFiRcrPJPb41zgbQj9XAEyLKCHex0SdDrx-tWUDqG8At2JHA=="]}')["att"]
    
    num_iter  = 9600
    # number_of_thread = 1
    number_of_thread = cpu_count()
    work = [json_dict_water]*(num_iter)
    parallel_start= time.time()
    with Pool(number_of_thread) as p:
        exe_time = p.map(internal_presig_bench, work)
    parallel_time = time.time() - parallel_start
    print(f"BENCHMARK Waters")
    print(f"Avg using {number_of_thread} thread : {(parallel_time*1.0/num_iter):.6f} seconds")
    
    
    number_of_thread = cpu_count()
    work = [json_dict_ecdsa]*(num_iter)
    parallel_start= time.time()
    with Pool(number_of_thread) as p:
        exe_time = p.map(internal_presigecdsa_bench, work)
    parallel_time = time.time() - parallel_start
    print(f"BENCHMARK ECDSA")
    print(f"Avg using {number_of_thread} thread : {(parallel_time*1.0/num_iter):.6f} seconds")
    
    return 0
@app.route("/api/benchmarkdelegateecdsa", methods=["GET"])
def benchmark_delegation_ecdsa():
    num_iter  = 100
    # number_of_thread = 1
    number_of_thread = cpu_count()
    work = [json.loads(request.args.get('attestation'))["att"]]*(num_iter)
    parallel_start= time.time()
    with Pool(number_of_thread) as p:
        exe_time = p.map(internal_presigecdsa_bench, work)
    parallel_time = time.time() - parallel_start
    print(f"BENCHMARK ECDSA Waters")
    print(f"Avg using {number_of_thread} thread : {(parallel_time*1.0/num_iter):.6f} seconds")
    return jsonify({"Avg Parallel": f"{parallel_time*1.0/num_iter} seconds", "Thread Count": f"{number_of_thread}"})

def test():
    # parameter = generate_params()
    # print("public parameter: generated")
    # epk=b""
    # shared_key_arr = []
    # aon_key = None
    # nusecount =160 
    # targetsk = ec.generate_private_key(
    #     ec.SECP256R1()
    # )
    # targetpk =targetsk.public_key()
    # targetpk_arr = [targetpk] * nusecount
    # for i in range(nusecount):
    #     private_key = ec.generate_private_key(
    #         ec.SECP256R1()
    #     )
   
    #     epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
    #     shared_key = private_key.exchange(
    #         ec.ECDH(), targetpk_arr[i]
    #     )
    #     shared_key_arr.append(shared_key)
    #     # TODO: derive shared_key+aon material correctly
    # aon_key= shared_key_arr[0] #TODO: derive AON Key    
    
    # Bit variant 
    # nusecount = 40
    # num_selectable_elem = nusecount
    # num_possible_item_per_elem = 2 #Bit version is 2, byte version is 256
    
    # w=4 variant
    nusecount = 10
    num_selectable_elem = nusecount
    num_possible_item_per_elem = 16 #Bit version is 2, byte version is 256
    
    targetsk = ec.generate_private_key(
        ec.SECP256R1()
    )
    targetpk =targetsk.public_key()
    targetpk = [targetpk] * nusecount
    
    parameter = generate_params_waters()
    print("public parameter: generated")
    epk=b""
    shared_key_arr = []
    key_space_mod = 2**256
    aon_key_array = [random.randint(0,key_space_mod-1) for i in range(num_selectable_elem)]
    aon_key = reduce(lambda x, y: (x ^ y), aon_key_array) #Bitwise XOR
    aon_key_array_byte = [i.to_bytes(length=32) for i in aon_key_array]
    for i in range(num_selectable_elem):
        for j in range(num_possible_item_per_elem):
            private_key = ec.generate_private_key(
                ec.SECP256R1()
            )
            # print(private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint))
            # print(private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint).__len__())
            epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
            shared_key = private_key.exchange(
                ec.ECDH(), targetpk[i]
            )
            shared_key_arr.append(shared_key)
    garble_msg = garble_waters(parameter, shared_key_arr, nusecount, num_possible_item_per_elem, make_tag(1, 0))
    # print("garble:", output)
    
    nusecount = 5
    num_selectable_elem = nusecount
    num_possible_item_per_elem = 256
    targetsk = ec.generate_private_key(
        ec.SECP256R1()
    )
    targetpk =targetsk.public_key()
    targetpk = [targetpk] * nusecount
    
    parameter = generate_params_waters()
    print("public parameter: generated")
    epk=b""
    shared_key_arr = []
    key_space_mod = 2**256
    aon_key_array = [random.randint(0,key_space_mod-1) for i in range(num_selectable_elem)]
    aon_key = reduce(lambda x, y: (x ^ y), aon_key_array) #Bitwise XOR
    aon_key_array_byte = [i.to_bytes(length=32) for i in aon_key_array]
    for i in range(num_selectable_elem):
        for _ in range(num_possible_item_per_elem):
            private_key = ec.generate_private_key(
                ec.SECP256R1()
            )
            # print(private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint))
            # print(private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint).__len__())
            epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
            shared_key = private_key.exchange(
                ec.ECDH(), targetpk[i]
            )
            shared_key_arr.append(shared_key)
    garble_msg = garble_waters(parameter, shared_key_arr, num_selectable_elem, num_possible_item_per_elem, make_tag(1, 0))

def test_ecdsa_full():   
    # nusecount = 256
    # num_selectable_elem = nusecount
    # num_possible_item_per_elem = 2 #Bit version is 2, byte version is 256
    
    nusecount = 64
    num_selectable_elem = nusecount
    num_possible_item_per_elem = 16 #Bit version is 2, byte version is 256
    targetsk = ec.generate_private_key(
        ec.SECP256R1()
    )
    targetpk =targetsk.public_key()
    targetpk = [targetpk] * nusecount
    
    parameter = generate_params_ecdsa(water_parameter)
    print("public parameter: generated")
    epk=b""
    shared_key_arr = []
    key_space_mod = 2**256
    aon_key_array = [random.randint(0,key_space_mod-1) for i in range(num_selectable_elem)]
    aon_key = reduce(lambda x, y: (x ^ y), aon_key_array) #Bitwise XOR
    aon_key_array_byte = [i.to_bytes(length=32) for i in aon_key_array]
    for i in range(num_selectable_elem):
        for j in range(num_possible_item_per_elem):
            private_key = ec.generate_private_key(
                ec.SECP256R1()
            )
            # print(private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint))
            # print(private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint).__len__())
            epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
            shared_key = private_key.exchange(
                ec.ECDH(), targetpk[i]
            )
            shared_key_arr.append(shared_key)
    garble_msg = garble_ecdsa(parameter, shared_key_arr, num_selectable_elem, num_possible_item_per_elem)
    # print("garble:", output)
    
    nusecount = 32
    num_selectable_elem = nusecount
    num_possible_item_per_elem = 256
    targetsk = ec.generate_private_key(
        ec.SECP256R1()
    )
    targetpk =targetsk.public_key()
    targetpk = [targetpk] * nusecount
    
    parameter = generate_params_ecdsa(water_parameter)
    print("public parameter: generated")
    epk=b""
    shared_key_arr = []
    key_space_mod = 2**256
    aon_key_array = [random.randint(0,key_space_mod-1) for i in range(num_selectable_elem)]
    aon_key = reduce(lambda x, y: (x ^ y), aon_key_array) #Bitwise XOR
    aon_key_array_byte = [i.to_bytes(length=32) for i in aon_key_array]
    for i in range(num_selectable_elem):
        for _ in range(num_possible_item_per_elem):
            private_key = ec.generate_private_key(
                ec.SECP256R1()
            )
            # print(private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint))
            # print(private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint).__len__())
            epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
            shared_key = private_key.exchange(
                ec.ECDH(), targetpk[i]
            )
            shared_key_arr.append(shared_key)
    garble_msg = garble_ecdsa(parameter, shared_key_arr, num_selectable_elem, num_possible_item_per_elem)
    
def test_dsign_rdelegate_native_pc():
    # nusecount_arr = [32,64,256]
    # num_possible_item_per_elem_arr = [256,16,2]
    nusecount_arr = [256,64,32]
    num_possible_item_per_elem_arr = [2,16,256]
    test_scenario_description_str_arr = ["dsign w=1","dsign w=4","dsign w=8"]
    num_iter= 100
    
    for test_scenario in range(3):
        nusecount = nusecount_arr[test_scenario]
        num_possible_item_per_elem = num_possible_item_per_elem_arr[test_scenario] #Bit version is 2, byte version is 256
        exe_time = []
        for i in range(num_iter):
            num_selectable_elem = nusecount
            targetsk = ec.generate_private_key(
                ec.SECP256R1()
            )
            targetpk =targetsk.public_key()
            targetpk = [targetpk] * nusecount
            
            parameter = generate_params_ecdsa(water_parameter)
            print("public parameter: generated")
            epk=b""
            shared_key_arr = []
            target_shared_key_arr = []
            message_pattern = []
            key_space_mod = 2**256
            aon_key_array = [random.randint(0,key_space_mod-1) for i in range(num_selectable_elem)]
            aon_key = reduce(lambda x, y: (x ^ y), aon_key_array) #Bitwise XOR
            aon_key_array_byte = [i.to_bytes(length=32) for i in aon_key_array]
            for i in range(num_selectable_elem):
                for j in range(num_possible_item_per_elem):
                    private_key = ec.generate_private_key(
                        ec.SECP256R1
                    )
                    # print(private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint))
                    # print(private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint).__len__())
                    epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
                    shared_key = private_key.exchange(
                        ec.ECDH(), targetpk[i]
                    )
                    shared_key_arr.append(shared_key)
                    if j==1:
                        target_shared_key_arr.append(shared_key)
                        message_pattern.append(1)
            garble_msg = garble_ecdsa(parameter, shared_key_arr, num_selectable_elem, num_possible_item_per_elem)
            start = time.time()
            ret = test_dsign_local(parameter, garble_msg, target_shared_key_arr, message_pattern,num_selectable_elem, num_possible_item_per_elem)
            exe_time.append( time.time() - start)
            # print("garble:", output)
        avg_execution_time = sum(exe_time) / num_iter
        variance = sum((x - avg_execution_time) ** 2 for x in exe_time) / (num_iter)
        std_deviation = math.sqrt(variance)
        print(f"BENCHMARK ", test_scenario_description_str_arr[test_scenario])
        print(f"Avg: {avg_execution_time:.6f} seconds")
        print(f"Std: {std_deviation:.6f} seconds")
        
    nusecount_arr = [5,10,40]
    num_possible_item_per_elem_arr = [256,16,2]
    test_scenario_description_str_arr = ["rdelegate w=8","redelegate w=4","rdelegate w=1"]
    for test_scenario in range(3):
        nusecount = nusecount_arr[test_scenario]
        num_possible_item_per_elem = num_possible_item_per_elem_arr[test_scenario] #Bit version is 2, byte version is 256
        exe_time = []
        for i in range(num_iter):
            num_selectable_elem = nusecount
            targetsk = ec.generate_private_key(
                ec.SECP256R1()
            )
            targetpk =targetsk.public_key()
            targetpk = [targetpk] * nusecount
            
            parameter = generate_params_ecdsa(water_parameter)
            print("public parameter: generated")
            epk=b""
            shared_key_arr = []
            target_shared_key_arr = []
            message_pattern = []
            key_space_mod = 2**256
            aon_key_array = [random.randint(0,key_space_mod-1) for i in range(num_selectable_elem)]
            aon_key = reduce(lambda x, y: (x ^ y), aon_key_array) #Bitwise XOR
            aon_key_array_byte = [i.to_bytes(length=32) for i in aon_key_array]
            for i in range(num_selectable_elem):
                for j in range(num_possible_item_per_elem):
                    private_key = ec.generate_private_key(
                        ec.SECP256R1
                    )
                    # print(private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint))
                    # print(private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint).__len__())
                    epk += private_key.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
                    shared_key = private_key.exchange(
                        ec.ECDH(), targetpk[i]
                    )
                    shared_key_arr.append(shared_key)
                    if j==1:
                        target_shared_key_arr.append(shared_key)
                        message_pattern.append(1)
            garble_msg = garble_waters(water_parameter, shared_key_arr, num_selectable_elem, num_possible_item_per_elem, make_tag(1, 0))
            start = time.time()
            ret = test_rdelegate_local(water_parameter, garble_msg, target_shared_key_arr, message_pattern,num_selectable_elem, num_possible_item_per_elem)
            exe_time.append( time.time() - start)
            # print("garble:", output)
        avg_execution_time = sum(exe_time) / num_iter
        variance = sum((x - avg_execution_time) ** 2 for x in exe_time) / (num_iter)
        std_deviation = math.sqrt(variance)
        print(f"BENCHMARK ", test_scenario_description_str_arr[test_scenario])
        print(f"Avg: {avg_execution_time:.6f} seconds")
        print(f"Std: {std_deviation:.6f} seconds")
    

def benchmark_activate():
    num_iter  = 100
    exe_time = []
    
    for _ in range(num_iter):
        start = time.time()
   
        test_unlock(water_parameter)
        exe_time.append( time.time() - start)
    avg_execution_time_unlock = sum(exe_time) / num_iter
    variance = sum((x - avg_execution_time_unlock) ** 2 for x in exe_time) / (num_iter)
    std_deviation = math.sqrt(variance)
    print(f"BENCHMARK unlock")
    print(f"Avg: {avg_execution_time_unlock:.6f} seconds")
    print(f"Std: {std_deviation:.6f} seconds")

    exe_time=[]
    for _ in range(num_iter):
        start = time.time()
   
        test_activate(water_parameter)

        exe_time.append( time.time() - start)
    avg_execution_time = sum(exe_time) / num_iter
    variance = sum((x - avg_execution_time) ** 2 for x in exe_time) / (num_iter)
    std_deviation = math.sqrt(variance)
    print(f"BENCHMARK Activate")
    # Because activation include computing unlock key in the test implementation (artifact from implementation).
    print(f"Avg: {(avg_execution_time-avg_execution_time_unlock):.6f} seconds") 
    print(f"Std: {std_deviation:.6f} seconds")
    
    
    print(f"BENCHMARK RDelegate/Dsign")
    
    


def test_redelegate_full():
    """End-to-end test: server delegates to Alice, then Alice re-delegates offline to Bob."""
    nusecount = 5
    num_possible_item_per_elem = 256

    # --- Step 1: Bank issues garbled circuit to Alice ---
    targetsk_alice = ec.generate_private_key(ec.SECP256R1())
    targetpk_alice = targetsk_alice.public_key()
    shared_key_arr_alice = []
    target_shared_alice = []
    message_pattern_alice = []
    for i in range(nusecount):
        for j in range(num_possible_item_per_elem):
            priv = ec.generate_private_key(ec.SECP256R1())
            sk = priv.exchange(ec.ECDH(), targetpk_alice)
            shared_key_arr_alice.append(sk)
            if j == 1:  # Alice's ECDH output byte = 1 for every slot (test fixture)
                target_shared_alice.append(sk)
                message_pattern_alice.append(1)

    alice_box = garble_waters(water_parameter, shared_key_arr_alice, nusecount, num_possible_item_per_elem, make_tag(1, 0))

    # --- Step 2: Alice evaluates to recover (sk1, sk2, sk3) ---
    (sk1, sk2, sk3) = test_rdelegate_local(
        water_parameter, alice_box,
        target_shared_alice, message_pattern_alice,
        nusecount, num_possible_item_per_elem
    )
    print("Alice evaluated: sk1 len", len(sk1), "sk2 len", len(sk2), "sk3 len", len(sk3))

    # --- Step 3: Alice re-delegates to Bob (no server) ---
    targetsk_bob = ec.generate_private_key(ec.SECP256R1())
    targetpk_bob = targetsk_bob.public_key()
    shared_key_arr_bob = []
    target_shared_bob = []
    message_pattern_bob = []
    for i in range(nusecount):
        for j in range(num_possible_item_per_elem):
            priv = ec.generate_private_key(ec.SECP256R1())
            sk = priv.exchange(ec.ECDH(), targetpk_bob)
            shared_key_arr_bob.append(sk)
            if j == 1:
                target_shared_bob.append(sk)
                message_pattern_bob.append(1)

    bob_box = garble_redelegate(
        water_parameter, sk1, sk2, sk3,
        shared_key_arr_bob, nusecount, num_possible_item_per_elem, make_tag(1, 1)  # denom=1, bob=user 001
    )
    print("Alice garbled Bob's circuit")

    # --- Step 4: Bob evaluates his garbled circuit ---
    test_rdelegate_local(
        water_parameter, bob_box,
        target_shared_bob, message_pattern_bob,
        nusecount, num_possible_item_per_elem
    )
    print("RDelegate full test PASSED: Bob's Waters key verified")


def test_gs_full():
    """End-to-end test of the masked, all-or-nothing GS circuit linked to GWat.

    Simulates the device with one secp256r1 key and counts its ECDH uses against _GS_NUSECOUNT.
    Run: python3 -c "from server import test_gs_full; test_gs_full()"
    """
    import secrets
    assert 5 + 1 + _GS_TAG_BITS == _GS_NUSECOUNT, "budget must be exact: GWat 5 + GS branch 1 + tag bits"

    device = ec.generate_private_key(ec.SECP256R1())
    uses = [0]
    def ecdh(epk_bytes, idx):
        uses[0] += 1
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), epk_bytes[idx * 33:(idx + 1) * 33])
        return device.exchange(ec.ECDH(), pub)

    def gs_eval(gs, tag, keys, gwat_sk2, gwat_sk3):
        return test_evaluate_gs(json.dumps(gs), tag, b"".join(keys), gwat_sk2, gwat_sk3)

    def gs_keys(gs_epk, tag, override=None):
        """Branch key + one key per tag bit; override maps bit index -> key used instead."""
        bits = [(tag.encode()[i // 8] >> (i % 8)) & 1 for i in range(len(tag) * 8)]
        keys = [ecdh(gs_epk, 0)]
        for i, b in enumerate(bits):
            keys.append(override[i] if override and i in override else ecdh(gs_epk, 1 + 2 * i + b))
        return keys

    def mint(denomination=1):
        epk, garble_msg, gs = _garble_one_circuit(device.public_key(), make_tag(1, 0), denomination)
        return epk, garble_msg, gs, urlsafe_b64decode(gs["epk"])

    # --- Honest flow: activate (GWat, 5 uses) then re-delegate once (GS, 1 + 88 uses) ---
    epk, garble_msg, gs, gs_epk = mint()
    pattern = [secrets.randbelow(256) for _ in range(5)]
    gwat_keys = [ecdh(epk, i * 256 + v) for i, v in enumerate(pattern)]
    sk1, sk2, sk3 = test_rdelegate_local(water_parameter, garble_msg, gwat_keys, pattern, 5, 256)

    bob_tag = "002_001_000"
    ak2 = gs_eval(gs, bob_tag, gs_keys(gs_epk, bob_tag), sk2, sk3)
    assert test_verify_gs_key(water_parameter, bob_tag, *ak2), "honest GS key must verify"
    assert not test_verify_gs_key(water_parameter, "002_001_001", *ak2), "key must not verify for another tag"
    assert uses[0] == _GS_NUSECOUNT, f"honest flow used {uses[0]} ECDH ops, budget is {_GS_NUSECOUNT}"
    print(f"[ok] honest activate + re-delegate: key verifies for {bob_tag}, {uses[0]} ECDH uses")

    # --- Fixed bits: denomination and separators have one slot only ---
    n_fixed = sum(1 for i in range(_GS_TAG_BITS) if gs["key_mat0"][i] == "" or gs["key_mat1"][i] == "")
    assert n_fixed == 40, f"expected 40 single-slot bits ('_DDD_'), got {n_fixed}"
    assert all(gs["key_mat0"][i] and gs["key_mat1"][i] for i in list(range(24)) + list(range(64, 88))), "UUU/CCC bits must keep both slots"
    assert all((gs["key_mat0"][i] == "") == (gs["slots_c0"][i] == "") and (gs["key_mat1"][i] == "") == (gs["slots_c1"][i] == "") for i in range(_GS_TAG_BITS))
    print(f"[ok] {n_fixed} fixed bits are single-slot, UUU/CCC bits keep both")

    # --- Re-delegation to a different UUU and CCC at the same denomination still works ---
    # (uses a fresh coin: each coin's device key has exactly one evaluation's worth of budget)
    epk_d, garble_msg_d, gs_d, gs_epk_d = mint(1)
    pattern_d = [secrets.randbelow(256) for _ in range(5)]
    _, sk2_d, sk3_d = test_rdelegate_local(water_parameter, garble_msg_d, [ecdh(epk_d, i * 256 + v) for i, v in enumerate(pattern_d)], pattern_d, 5, 256)
    other_tag = "017_001_123"
    ak_d = gs_eval(gs_d, other_tag, gs_keys(gs_epk_d, other_tag), sk2_d, sk3_d)
    assert test_verify_gs_key(water_parameter, other_tag, *ak_d), "key for another UUU/CCC must verify"
    print(f"[ok] re-delegation to {other_tag} (other UUU and CCC, same denomination) verifies")

    # --- Denomination forgery: a denomination-1 coin cannot be evaluated at a denomination-100 tag ---
    epk_f, garble_msg_f, gs_f, gs_epk_f = mint(1)
    pattern_f = [secrets.randbelow(256) for _ in range(5)]
    _, sk2_f, sk3_f = test_rdelegate_local(water_parameter, garble_msg_f, [ecdh(epk_f, i * 256 + v) for i, v in enumerate(pattern_f)], pattern_f, 5, 256)
    forged_tag = "002_100_000"
    try:
        # Alice's device would happily do the ECDH for the forged tag; the circuit has no slot.
        ak_f = gs_eval(gs_f, forged_tag, gs_keys(gs_epk_f, forged_tag), sk2_f, sk3_f)
        assert not test_verify_gs_key(water_parameter, forged_tag, *ak_f), "forged denomination produced a valid key"
    except OSError as e:
        assert "fixed by the coin" in str(e), e
        print(f"[ok] denomination-1 coin at denomination-100 tag rejected: {e}")

    # --- A coin minted at denomination 100 does evaluate at a denomination-100 tag, not at 1 ---
    epk_h, garble_msg_h, gs_h, gs_epk_h = mint(100)
    pattern_h = [secrets.randbelow(256) for _ in range(5)]
    _, sk2_h, sk3_h = test_rdelegate_local(water_parameter, garble_msg_h, [ecdh(epk_h, i * 256 + v) for i, v in enumerate(pattern_h)], pattern_h, 5, 256)
    ak_h = gs_eval(gs_h, "002_100_000", gs_keys(gs_epk_h, "002_100_000"), sk2_h, sk3_h)
    assert test_verify_gs_key(water_parameter, "002_100_000", *ak_h)
    try:
        gs_eval(gs_h, "002_001_000", gs_keys(gs_epk_h, "002_001_000"), sk2_h, sk3_h)
        raise AssertionError("denomination-100 coin evaluated at a denomination-1 tag")
    except OSError:
        pass
    print("[ok] denomination-100 coin evaluates at its own denomination only")

    # --- GS without this coin's GWat key (skipping activation to save 5 uses) fails ---
    _, garble_msg_b, gs_b, gs_epk_b = mint()
    try:
        gs_eval(gs_b, bob_tag, gs_keys(gs_epk_b, bob_tag), sk2, sk3)  # GWat key of the other coin
        raise AssertionError("GS opened with another coin's GWat key")
    except OSError as e:
        print(f"[ok] GS with another coin's GWat key rejected: {e}")

    # --- Opening both slots of bit k leaves the budget one short: some bit j goes unopened ---
    # With 94 uses: GWat 5 + branch 1 + both slots of bit k (2) + 86 other bits = 94, so bit j
    # has no key and nothing decrypts, for either value of bit k.
    epk_c, garble_msg_c, gs_c, gs_epk_c = mint()
    pattern = [secrets.randbelow(256) for _ in range(5)]
    _, sk2_c, sk3_c = test_rdelegate_local(water_parameter, garble_msg_c, [ecdh(epk_c, i * 256 + v) for i, v in enumerate(pattern)], pattern, 5, 256)
    k, j = 3, 40
    tag0 = "002_001_000"
    tag1 = tag0[:k // 8] + chr(ord(tag0[k // 8]) ^ (1 << (k % 8))) + tag0[k // 8 + 1:]  # tag0 with bit k flipped
    for tag in (tag0, tag1):
        try:
            gs_eval(gs_c, tag, gs_keys(gs_epk_c, tag, override={j: secrets.token_bytes(32)}), sk2_c, sk3_c)
            raise AssertionError("GS evaluated with an unopened bit slot")
        except OSError:
            pass
    print("[ok] evaluation with any bit slot unopened fails (no second tag from spare uses)")

    # --- Fresh randomness per coin: circuits for the same device and tag differ ---
    assert gs["base_enc"] != gs_b["base_enc"] and gs["slots_c1"][0] != gs_b["slots_c1"][0]
    assert json.loads(garble_msg)["sig2"] != json.loads(garble_msg_b)["sig2"]
    print("[ok] two coins get independent GS masks and GWat r")
    print("GS full test PASSED")


def test_denomination_trust():
    """/api/redelegate and /api/pay take the denomination from the on-chain contract.

    Flask test client with web3 and _htlc mocked (no chain, no env vars needed).
    Run: python3 -c "from server import test_denomination_trust; test_denomination_trust()"
    """
    from unittest import mock

    cid = bytes(range(32))
    state = {'hashlock': 1, 'withdrawn': False, 'withdraw_status': 1, 'raise_on_withdraw': False}
    sent = []  # ('withdraw' | 'newContract', args)

    htlc = mock.MagicMock()
    htlc.functions.getContract.side_effect = lambda c: mock.MagicMock(call=lambda: (
        'sender', 'receiver', 1, state['hashlock'], 0, state['withdrawn'], False, None))
    htlc.functions.withdraw.side_effect = lambda c, pre: ('withdraw', c)
    htlc.functions.newContract.side_effect = lambda r, h, t: ('newContract', h)
    new_id = bytes([0xAB]) * 32
    htlc.events.HTLCETHNew.return_value.process_receipt.return_value = [{'args': {'contractId': new_id}}]
    w3 = mock.MagicMock()
    w3.to_wei.side_effect = lambda v, unit: int(v * 10**18)

    def fake_send_tx(fn, value=0):
        sent.append((fn, value))
        if fn[0] == 'withdraw' and state['raise_on_withdraw']:
            raise RuntimeError('execution reverted')
        return {'status': state['withdraw_status'] if fn[0] == 'withdraw' else 1, 'transactionHash': b'\x01' * 32}

    sol_stub = json.dumps({k: {'x': '1', 'y': '2'} for k in ('sk1', 'sk2')} | {'sk3': {'x': ['1', '2'], 'y': ['3', '4']}})
    cases = []
    def check(name, ok):
        cases.append((name, ok))
        print(f"[{'ok' if ok else 'FAIL'}] {name}")
        assert ok, name

    with mock.patch.multiple(sys.modules[__name__], _init_web3=lambda: None, _ensure_setup=lambda: None, _htlc=htlc,
                             _w3=w3, _eth_acct=mock.MagicMock(address='0xbank'), _send_tx=fake_send_tx,
                             water_unlock_solidity=lambda param, d: sol_stub):
        client = app.test_client()
        cid_hex = cid.hex()

        # /api/redelegate
        for body in ({'denomination': 100}, {'contract_id': '', 'denomination': 100}, {}):
            sent.clear()
            r = client.post('/api/redelegate', json=body)
            check(f"redelegate {body} -> 400, nothing sent", r.status_code == 400 and not sent)

        sent.clear()
        r = client.post('/api/redelegate', json={'contract_id': cid_hex, 'denomination': 100})
        check("redelegate: denomination 100 on a 1-coin contract -> 400, nothing sent", r.status_code == 400 and not sent)

        state['raise_on_withdraw'] = True
        sent.clear()
        r = client.post('/api/redelegate', json={'contract_id': cid_hex, 'denomination': 1})
        check("redelegate: withdraw raises -> 500, newContract never called",
              r.status_code == 500 and [f[0] for f, _ in sent] == ['withdraw'])
        state['raise_on_withdraw'] = False

        state['withdraw_status'] = 0
        sent.clear()
        r = client.post('/api/redelegate', json={'contract_id': cid_hex, 'denomination': 1})
        check("redelegate: withdraw reverts (status 0) -> 500, newContract never called",
              r.status_code == 500 and [f[0] for f, _ in sent] == ['withdraw'])
        state['withdraw_status'] = 1

        for hashlock in (2, 100):
            state['hashlock'] = hashlock
            sent.clear()
            r = client.post('/api/redelegate', json={'contract_id': '0x' + cid_hex})  # no denomination in the request
            check(f"redelegate: contract of denomination {hashlock}, no denomination sent -> new contract at {hashlock}",
                  r.status_code == 200 and r.get_json() == {'contract_id': new_id.hex()}
                  and [f[0] for f, _ in sent] == ['withdraw', 'newContract']
                  and sent[1][0][1] == hashlock and sent[1][1] == w3.to_wei(_DENOM_ETH[hashlock], 'ether'))
        state['hashlock'] = 1

        sent.clear()
        r = client.post('/api/redelegate', json={'contract_id': cid_hex, 'denomination': 1})
        check("redelegate: honest request -> 200, withdraw then newContract at denomination 1",
              r.status_code == 200 and [f[0] for f, _ in sent] == ['withdraw', 'newContract'] and sent[1][1] == w3.to_wei(0.01, 'ether'))

        state['hashlock'] = 77
        r = client.post('/api/redelegate', json={'contract_id': cid_hex})
        check("redelegate: unsupported hashlock -> 400", r.status_code == 400)
        state['hashlock'] = 1

        state['withdrawn'] = True
        r = client.post('/api/redelegate', json={'contract_id': cid_hex})
        check("redelegate: already-withdrawn contract -> 400", r.status_code == 400)
        state['withdrawn'] = False

        # /api/pay
        sent.clear()
        r = client.post('/api/pay', json={'contract_id': '', 'denomination': 1})
        check("pay: empty contract_id -> 400", r.status_code == 400 and not sent)
        r = client.post('/api/pay', json={'contract_id': cid_hex, 'denomination': 100})
        check("pay: denomination 100 on a 1-coin contract -> 400, nothing sent", r.status_code == 400 and not sent)
        r = client.post('/api/pay', json={'contract_id': cid_hex, 'denomination': 'abc'})
        check("pay: non-numeric denomination -> 400", r.status_code == 400 and not sent)
        state['hashlock'] = 20
        r = client.post('/api/pay', json={'contract_id': cid_hex})
        check("pay: denomination derived from the contract, withdraw sent", r.status_code == 200 and [f[0] for f, _ in sent] == ['withdraw'])
    print(f"Denomination trust test PASSED ({len(cases)} cases)")


def test_fde_regtest():
    """Part C: buy a coin by fair exchange on Bitcoin regtest through /api/fde/* (Flask test client).

    The test plays Alice: her own secp256k1 key, the node's wallet to fund the lock, the node to
    read the chain. Only verify_attestation is mocked. Needs bitcoind running:
      bitcoind -regtest -datadir=$HOME/btc-regtest -daemon -fallbackfee=0.0001
    Run: python3 -c "from server import test_fde_regtest; test_fde_regtest()"
    """
    from unittest import mock

    def wallet(*args):
        return _btc('-rpcwallet=orbit', *args)
    def mine(n=1):
        _btc('generatetoaddress', str(n), wallet('getnewaddress'))
    def mine_to(h):
        n = h - int(_btc('getblockcount'))
        if n > 0:
            mine(n)
    try:
        _btc('getblockcount')
    except Exception as e:
        print(f"[SKIP] bitcoind regtest not reachable: {e}")
        return
    try:
        _btc('createwallet', 'orbit')
    except RuntimeError:
        try:
            _btc('loadwallet', 'orbit')
        except RuntimeError:
            pass  # already loaded
    if float(wallet('getbalance')) < 1.0:
        mine(101)

    device = ec.generate_private_key(ec.SECP256R1())  # the attested AndroidKeyStore key
    fake_verify = lambda att: (att == ['valid-chain'], device.public_key(), _GS_NUSECOUNT)
    client = app.test_client()
    alice_sk, alice_pk = fde_keypair()
    params_public = json.loads(water_parameter)
    params_public.pop('beta_secret')
    params_public = json.dumps(params_public)
    results = []
    def check(name, cond):
        assert cond, name
        results.append(name)
        print(f"[ok] {name}")

    def fund(terms):
        txid = wallet('sendtoaddress', terms['lock_address'], f"{terms['amount_sat'] / 1e8:.8f}")
        tx = json.loads(_btc('getrawtransaction', txid, 'true'))
        vout = next(o['n'] for o in tx['vout'] if o['scriptPubKey'].get('address') == terms['lock_address'])
        return txid, vout
    def claim_sighash(terms, txid, vout, to=None):
        return json.loads(btc_spend(terms['lock_script'], txid, vout, terms['amount_sat'],
                                    to or terms['payout_address'], terms['claim_fee'], 0))['sighash']
    def spent_in_tip(txid, vout):
        block = json.loads(_btc('getblock', _btc('getbestblockhash'), '2'))
        return next((t for t in block['tx'] if any(i.get('txid') == txid and i.get('vout') == vout for i in t['vin'])), None)

    with mock.patch.object(sys.modules[__name__], 'verify_attestation', side_effect=fake_verify):
        # ---- C1 Alice pins the Bank's chain key ----
        bank = client.get('/api/fde/bank').get_json()
        bank_pk = bank['bank_pk']
        check("C1 Bank key and lock parameters published", bank['claim_margin'] == FDE_CLAIM_MARGIN)

        # ---- C2 attestation gate ----
        r = client.post('/api/fde/offer', json={'attestation': ['forged'], 'denomination': 1, 'alice_pk': alice_pk})
        check("C2 offer to a device with a rejected attestation -> 403", r.status_code == 403)
        r = client.post('/api/fde/offer', json={'denomination': 1, 'alice_pk': alice_pk})
        check("C2 offer without attestation -> 400", r.status_code == 400)
        r = client.post('/api/fde/offer', json={'attestation': ['valid-chain'], 'denomination': 1, 'alice_pk': 'zz'})
        check("C2 offer with a malformed Alice key -> 400", r.status_code == 400)

        # ---- C3 honest offer; Alice's checks before she pays ----
        def get_offer(denomination=1):
            r = client.post('/api/fde/offer', json={'attestation': ['valid-chain'], 'denomination': denomination,
                                                    'alice_pk': alice_pk, 'user_id': 7})
            assert r.status_code == 200, r.get_json()
            return r.get_json()
        resp = get_offer(2)
        terms_str, sig = resp['terms'], resp['sig']
        terms = json.loads(terms_str)
        check("C3 offer signed by the pinned Bank key", fde_verify_sig(bank_pk, terms_str, sig))
        check("C3 terms carry no beta_secret", 'beta_secret' not in terms_str)
        expected_lock = json.loads(btc_lock(alice_pk, bank_pk, terms['timelock']))
        check("C3 lock address rebuilt by Alice matches the terms",
              expected_lock['address'] == terms['lock_address'] and expected_lock['script'] == terms['lock_script'])
        check("C3 amount matches the denomination", terms['amount_sat'] == _DENOM_SAT[2] and terms['tag'] == make_tag(2, 7))
        check("C3 offer bound to the attested device key",
              terms['attested_key'] == sha256(device.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)).hex())
        t0 = time.time()
        ok = fde_verify_offer(params_public, terms['tag'], json.dumps(terms['offer']))
        check(f"C3 encrypted key + cross-group proof verify with public params ({(time.time() - t0) * 1000:.0f} ms, "
              f"offer {len(json.dumps(terms['offer']))} bytes)", ok)

        # ---- C4 Alice refuses tampered offers ----
        bad = dict(terms, amount_sat=1)
        check("C4 terms altered in transit fail the Bank signature",
              not fde_verify_sig(bank_pk, json.dumps(bad, sort_keys=True, separators=(',', ':')), sig))
        other = json.loads(get_offer(2)['terms'])
        mixed = dict(terms['offer'], c2=other['offer']['c2'])
        check("C4 ciphertext from another offer fails verification",
              not fde_verify_offer(params_public, terms['tag'], json.dumps(mixed)))
        mixed = dict(terms['offer'], y_chain=other['offer']['y_chain'])
        check("C4 Y_chain from another offer fails the cross-group proof",
              not fde_verify_offer(params_public, terms['tag'], json.dumps(mixed)))
        check("C4 key offered for another tag fails verification",
              not fde_verify_offer(params_public, make_tag(100, 7), json.dumps(terms['offer'])))

        # ---- C5 Alice locks; the Bank waits for confirmation ----
        txid, vout = fund(terms)
        presig = fde_presign(alice_sk, claim_sighash(terms, txid, vout), terms['offer']['y_chain'])
        r = client.post('/api/fde/claim', json={'offer_id': terms['offer_id'], 'txid': txid, 'vout': vout, 'presig': presig})
        check("C5 claim before the lock confirms -> 409", r.status_code == 409)
        mine(1)

        # ---- C6/C7 the Bank rejects a bad pre-signature or a wrong output ----
        wrong = fde_presign(alice_sk, claim_sighash(terms, txid, vout, to=btc_p2wpkh_address(alice_pk)), terms['offer']['y_chain'])
        r = client.post('/api/fde/claim', json={'offer_id': terms['offer_id'], 'txid': txid, 'vout': vout, 'presig': wrong})
        check("C6 pre-signature on a different transaction -> 400, nothing broadcast",
              r.status_code == 400 and 'pre-signature invalid' in r.get_json()['error']
              and _btc('gettxout', txid, str(vout)) != '')
        # Alice underfunds: the right lock address, 1000 sat short.
        short_txid = wallet('sendtoaddress', terms['lock_address'], f"{(terms['amount_sat'] - 1000) / 1e8:.8f}")
        short_vout = next(o['n'] for o in json.loads(_btc('getrawtransaction', short_txid, 'true'))['vout']
                          if o['scriptPubKey'].get('address') == terms['lock_address'])
        mine(1)
        short_presig = fde_presign(alice_sk, claim_sighash(terms, short_txid, short_vout), terms['offer']['y_chain'])
        r = client.post('/api/fde/claim', json={'offer_id': terms['offer_id'], 'txid': short_txid, 'vout': short_vout, 'presig': short_presig})
        check("C7 claim against an underfunded lock -> 400 (not the agreed lock)",
              r.status_code == 400 and 'not the agreed lock' in r.get_json()['error'])

        # ---- C8 honest claim; Alice extracts x from the block and decrypts ----
        r = client.post('/api/fde/claim', json={'offer_id': terms['offer_id'], 'txid': txid, 'vout': vout, 'presig': presig})
        check("C8 Bank's claim accepted by the node", r.status_code == 200)
        mine(1)
        spend = spent_in_tip(txid, vout)
        check("C8 claim confirmed, paying the Bank's payout address",
              spend is not None and spend['vout'][0]['scriptPubKey']['address'] == terms['payout_address'])
        key = json.loads(fde_extract_decrypt(spend['hex'], presig, json.dumps(terms['offer'])))
        sk = [bytes.fromhex(key[k]) for k in ('sk1', 'sk2', 'sk3')]
        check("C8 Alice decrypts sk3 from x read on-chain; the key verifies for her tag",
              test_verify_gs_key(water_parameter, terms['tag'], *sk))
        check("C8 ... and not for another tag", not test_verify_gs_key(water_parameter, make_tag(2, 8), *sk))

        # ---- C9 one claim per offer ----
        r = client.post('/api/fde/claim', json={'offer_id': terms['offer_id'], 'txid': txid, 'vout': vout, 'presig': presig})
        check("C9 second claim on the same offer -> 409", r.status_code == 409)

        # ---- C10 margin: the Bank stays silent near the timelock; Alice refunds ----
        terms = json.loads(get_offer(1)['terms'])
        txid, vout = fund(terms)
        mine(1)
        presig = fde_presign(alice_sk, claim_sighash(terms, txid, vout), terms['offer']['y_chain'])
        mine_to(terms['timelock'] - FDE_CLAIM_MARGIN)
        r = client.post('/api/fde/claim', json={'offer_id': terms['offer_id'], 'txid': txid, 'vout': vout, 'presig': presig})
        check(f"C10 claim within {FDE_CLAIM_MARGIN} blocks of the timelock -> 409, x not revealed",
              r.status_code == 409 and _btc('gettxout', txid, str(vout)) != '')
        refund = json.loads(btc_spend(terms['lock_script'], txid, vout, terms['amount_sat'],
                                      btc_p2wpkh_address(alice_pk), terms['claim_fee'], terms['timelock']))
        signed = btc_sign_refund(refund['tx'], terms['lock_script'], terms['amount_sat'], alice_sk)
        try:
            _btc('sendrawtransaction', signed)
            early = True
        except RuntimeError as e:
            early = 'non-final' not in str(e)
        check("C10 Alice's refund before the timelock is rejected (non-final)", not early)
        mine_to(terms['timelock'])
        _btc('sendrawtransaction', signed)
        mine(1)
        spend = spent_in_tip(txid, vout)
        check("C10 Alice's refund at the timelock confirms", spend is not None
              and spend['vout'][0]['scriptPubKey']['address'] == btc_p2wpkh_address(alice_pk))
        r = client.post('/api/fde/claim', json={'offer_id': terms['offer_id'], 'txid': txid, 'vout': vout, 'presig': presig})
        check("C10 later claim on the expired offer -> 409", r.status_code == 409)

    print(f"\ntest_fde_regtest PASSED: {len(results)} checks at regtest height {_btc('getblockcount')}")

def main():
    # benchmark_delegation_noserver()
    # return

    print(__doc__)
    # benchmark_delegation()
    # ssl_context=("/home/azureuser/fullchain.pem","/home/azureuser/privkey.pem")
    # host="0.0.0.0"
    url = None
    # url = "127.0.0.1"
    import subprocess
    try:
        # Run the command and capture the output
        # url = subprocess.check_output(['ipconfig', 'getifaddr', 'en0'], text=True).strip()
        # print(f"IP address for en0: {url}")
        url = subprocess.check_output(['hostname', '-I'], text=True).strip().split()[0]
        print(f"IP address: {url}")
    except subprocess.CalledProcessError:
        print("Failed to get IP address.")

    test_encrypt("message","keyneedtobelongkeyneedtobelongkeyneedtobelong")
    test_res = test_water(1)
    test_res2 = test_ecdsa(1)
    if test_res != 1:
        print("Error from TestCodes")
        return 
    test()
    test_ecdsa_full()
    
    benchmark_activate()
    # test_dsign_rdelegate_native_pc()

    # app.run(host=url, port=5000, debug=False)
    app.run(host="0.0.0.0", port=5000)

if __name__ == "__main__":
    main()