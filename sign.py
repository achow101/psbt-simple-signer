#! /usr/bin/env python3

from serializations import PSBT, make_p2sh, make_p2pkh, is_witness, make_p2wsh, sighash_witness, sighash_non_witness, ser_uint256, bytes_to_hex_str
from base58 import get_privkey
from secp256k1 import PrivateKey, PublicKey, ffi
import struct

import argparse

parser = argparse.ArgumentParser(description='Signs a BIP 174 PSBT with the simple signer algorithm')
parser.add_argument('psbt', help='BIP 174 PSBT to sign')
parser.add_argument('privkey', help='Private key in WIF to sign with')

args = parser.parse_args()

# Deserialize PSBT
try:
    psbt = PSBT()
    psbt.deserialize(args.psbt)
except Exception as e:
    print('Invalid PSBT')
    exit(-1)

# Deserialize the key and get it's pubkey
b_key, compressed = get_privkey(args.privkey)
key = PrivateKey(b_key)
pubkey = key.pubkey
b_pubkey = pubkey.serialize(compressed)

def sign(script_code, i, sighash_func):
    psbt_in = psbt.inputs[i]
    for in_pubkey in psbt_in.hd_keypaths.keys():
        if in_pubkey == b_pubkey:
            # Sighash and sign
            sighash = sighash_func(script_code, psbt, i)
            sig_obj = key.ecdsa_sign(sighash, raw=True)
            sig = key.ecdsa_serialize_compact(sig_obj)

            # Grind for low R
            counter = 0
            while sig[0] > 0x80:
                sig_obj = key.ecdsa_sign(sighash, raw=True, custom_nonce=(ffi.NULL, struct.pack('<I', counter)))
                sig = key.ecdsa_serialize_compact(sig_obj)
                counter += 1

            # Serialize DER and add to partial sigs
            _, sig_obj = key.ecdsa_signature_normalize(sig_obj)
            psbt_in.partial_sigs[b_pubkey] = key.ecdsa_serialize(sig_obj)

            break

for i, input in enumerate(psbt.inputs):
    if input.non_witness_utxo:
        assert(input.non_witness_utxo.sha256 == psbt.tx.vin[i].prevout.hash)
        if input.redeem_script:
            assert(input.non_witness_utxo.vout[psbt.tx.vin[i].prevout.n].scriptPubKey == make_p2sh(input.redeem_script))
            sign(input.redeem_script, i, sighash_non_witness)
        else:
            sign(input.non_witness_utxo.vout[psbt.tx.vin[i].prevout.n].scriptPubKey, i, sighash_non_witness)
    elif input.witness_utxo:
        if input.redeem_script:
            assert(input.witness_utxo.scriptPubKey == make_p2sh(input.redeem_script))
            script = input.redeem_script
        else:
            script = input.witness_utxo.scriptPubKey

        is_wit, wit_ver, wit_prog = is_witness(script)
        assert(is_wit)
        assert(wit_ver == 0)
        if len(wit_prog) == 20:
            sign(make_p2pkh(script[2:22]), i, sighash_witness)
        elif len(wit_prog) == 32:
            assert(script == make_p2wsh(input.witness_script))
            sign(input.witness_script, i, sighash_witness)

print(psbt.serialize())
