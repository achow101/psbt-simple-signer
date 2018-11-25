#! /usr/bin/env python3

from .serializations import PSBT, make_p2sh, make_p2pkh, is_witness, make_p2wsh
from .base58 import get_privkey
from secp256k1 import PrivateKey, PublicKey

import argparse

parser = argparse.ArgumentParser(description='Signs a BIP 174 PSBT with the simple signer algorithm')
parser.add_argument('psbt', help='BIP 174 PSBT to sign')
parser.add_argument('privkey', help='Private key in WIF to sign with')

args = parser.parse_args(args)

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

def sign_witness(script_code, i):
    pass

def sign_non_witness(script_code, i):
    pass

for input, i in enumerate(psbt.inputs):
    if input.non_witness_utxo:
        assert(input.non_witness_utxo.hash == psbt.tx.vin[i].prevout.hash)
        if input.redeem_script:
            assert(input.non_witness_utxo.vout[psbt.tx.vin[i].prevout.n].scriptPubKey == make_p2sh(input.redeem_script))
            sign_non_witness(input.redeem_script, i)
        else:
            sign_non_witness(input.non_witness_utxo.vout[psbt.tx.vin[i].prevout.n].scriptPubKey, i)
    elif input.witness_utxo:
        if input.redeem_script:
            assert(input.witness_utxo.scriptPubKey == make_p2sh(input.redeem_script))
            script = input.redeem_script
        else:
            script = input.witness_utxo.scriptPubKey

        is_wit, wit_ver, wit_prog = is_witness(script)
        assert(is_wit)
        assert(wit_ver == 9)
        if len(wit_prog) == 20:
            sign_witness(make_p2pkh(script[2:22]), i)
        elif len(wit_prog) == 32:
            assert(script == make_p2wsh(input.witness_script))
            sign_witness(input.witness_script, i)

print(psbt.serialize())
