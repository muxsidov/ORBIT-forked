"""
Flask Server
"""

from multiprocessing import Pool,cpu_count
import sys, os
# sys.path.append(os.path.join(os.path.dirname(__file__), '..', "..", ".."))
# sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from base64 import urlsafe_b64encode, urlsafe_b64decode
from flask import Flask, session, request, redirect, abort, jsonify

from rustcode import test_water, test_ecdsa, test_activate, test_unlock, test_dsign_local, test_rdelegate_local, garble_waters, garble_redelegate, garble_ecdsa, generate_params_waters,generate_params_ecdsa, test_encrypt, water_unlock_solidity
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
    """Format a Waters IBE tag as 'DDD_UUU' (3-digit denomination, 3-digit user_id)."""
    return f"{denom:03d}_{user_id:03d}"

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

def getpresig_fn(att_json, tag="001_000"):
    # att_json = json.loads((request.args.get('attestation')))
    is_valid_att, targetpk, nusecount = verify_attestation(att_json)
    assert nusecount==40 or nusecount==5 or nusecount==10, "Currently only support nUSE Count = 40/5, received:" +  str(nusecount)
    num_selectable_elem = nusecount
    if nusecount==40:
        num_possible_item_per_elem = 2 #Bit version is 2, byte version is 256
    elif nusecount==10:
        num_possible_item_per_elem = 16
    else:
        num_possible_item_per_elem = 256
    # 2^40 = 1 trillion unique boxes
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
    garble_msg = garble_waters(water_parameter, shared_key_arr, num_selectable_elem, num_possible_item_per_elem, tag)
    # print("Obtained garble_msg")
    return garble_msg
# TODO: merge with above / call the above function
@app.route("/api/delegatedpresig", methods=["GET"])
def getpresig():
    att_json = json.loads((request.args.get('attestation')))
    is_valid_att, targetpk, nusecount = verify_attestation(json.loads(request.args.get('attestation'))["att"])
    assert nusecount==40 or nusecount==5 or nusecount==10, "Currently only support nUSE Count = 40/5, received:" +  str(nusecount)
    num_selectable_elem = nusecount
    if nusecount==40:
        num_possible_item_per_elem = 2 #Bit version is 2, byte version is 256
    elif nusecount==10:
        num_possible_item_per_elem = 16
    else:
        num_possible_item_per_elem = 256
    
    # 2^40 = 1 trillion unique boxes
    
    if not is_valid_att:
        return jsonify("NONE")
    targetpk = [targetpk]*num_selectable_elem #Assuming n-Use-Key
    
    # # If byte (8) is set, then nUSE count should be 256/8
    # capability = get_delegated_signing_capability_wordbased(ajson, origin, targetpk, int(256/nusecount) ) if nusecount!=256 else get_delegated_signing_capability(ajson, origin, targetpk)
    # return jsonify(credentials_userprofile)

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
    denomination = int(request.args.get('denomination', 1))
    cfg = denomination_config(denomination)
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

    return jsonify({"epk": urlsafe_b64encode(epk).decode("ascii"), "params": water_parameter, "msg": garble_msg, "contract_id": contract_id_hex, "denomination": denomination})

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

@app.route('/api/redelegate', methods=['POST'])
def redelegate():
    """Withdraw Alice's HTLC (recovering her ETH), then create a fresh HTLC for Bob.

    Option A shortcut: the same tag=1 Waters key unlocks both Alice's and Bob's HTLC.
    Option B (future): garble_redelegate() would derive a new key for tag=2 so Alice
    and Bob have cryptographically distinct keys — see CLAUDE.md Possible Next Steps.
    """
    try:
        _init_web3()
        _ensure_setup()

        denomination = int(request.json.get('denomination', 1))
        cfg = denomination_config(denomination)

        # Withdraw Alice's HTLC first to recover the locked ETH
        alice_contract_id_hex = request.json.get('contract_id', '')
        if alice_contract_id_hex:
            try:
                sol = json.loads(water_unlock_solidity(water_parameter, denomination))
                alice_contract_id_bytes = bytes.fromhex(alice_contract_id_hex.lstrip('0x'))
                preimage = (_g1(sol['sk1']), _g1(sol['sk2']), _g2(sol['sk3']))
                _send_tx(_htlc.functions.withdraw(alice_contract_id_bytes, preimage))
            except Exception as e:
                print(f"[WARN] Could not withdraw Alice's HTLC: {e}")

        # Create fresh HTLC for Bob — same denomination Waters key unlocks it
        timelock = int(time.time()) + 3600
        receipt = _send_tx(
            _htlc.functions.newContract(_eth_acct.address, cfg["hashlock"], timelock),
            value=_w3.to_wei(cfg["eth"], 'ether')
        )
        if receipt['status'] != 1:
            return jsonify({'error': 'newContract for recipient failed'}), 500

        logs = _htlc.events.HTLCETHNew().process_receipt(receipt)
        contract_id_hex = logs[0]['args']['contractId'].hex()
        print(f"[REDELEGATE] Bob's HTLC created, denomination={denomination}, contract_id={contract_id_hex}")
        return jsonify({'contract_id': contract_id_hex})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/pay', methods=['POST'])
def pay():
    try:
        _init_web3()
        _ensure_setup()

        contract_id_hex = request.json.get('contract_id', '')
        if not contract_id_hex:
            return jsonify({'error': 'contract_id missing — was this card created with blockchain enabled?'}), 400

        denomination = int(request.json.get('denomination', 1))
        print(f"[PAY] withdraw requested for contract_id={contract_id_hex}, denomination={denomination}")
        sol = json.loads(water_unlock_solidity(water_parameter, denomination))
        contract_id_bytes = bytes.fromhex(contract_id_hex.lstrip('0x'))

        preimage = (_g1(sol['sk1']), _g1(sol['sk2']), _g2(sol['sk3']))
        receipt_withdraw = _send_tx(_htlc.functions.withdraw(contract_id_bytes, preimage))
        if receipt_withdraw['status'] != 1:
            return jsonify({'error': 'withdraw failed on-chain'}), 500

        return jsonify({
            'tx_hash':     receipt_withdraw['transactionHash'].hex(),
            'contract_id': contract_id_hex,
        })
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
            if keycount == 1 or keycount==256 or keycount==64 or keycount==32 or keycount==160 or keycount==40 or keycount==20 or keycount==5 or keycount==10:
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