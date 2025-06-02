from io import BytesIO
from ecc.Script import *
from ecc.Transaction import *
from helper.tools import *
from helper.op import *

BTC = 100000000  # 1 BTC = 100,000,000 satoshis

passphrase = b'Hope Sam get A+ on Programming Bitcoin'
secret = little_endian_to_int(hash256(passphrase))
priv = PrivateKey(secret=secret)
change_address = PrivateKey(secret=secret).point.address(testnet=True)
change_amount = 0.000009
print(f'My address: {change_address}')

prev_tx_id = 'b171e5db53495eb9952eb5574441059f2d5f14750a491babc6745d558a3ca2e9' # 0.0001 BTC
prev_tx = bytes.fromhex(prev_tx_id)
prev_index = 0
target_address = 'mqKbipRYFvkSEwcMdyXyTvcKZRd4EWvb6Q'   
target_amount = 0.00009

tx_ins = []
tx_ins.append(TxIn(prev_tx, prev_index))
tx_outs = []

h160 = decode_base58(target_address)
script_pubkey = p2pkh_script(h160)
target_satoshis = int(target_amount * BTC)
tx_outs.append(TxOut(target_satoshis, script_pubkey))

h160 = decode_base58(change_address)
script_pubkey = p2pkh_script(h160)
change_satoshis = int(change_amount * BTC)

tx_outs.append(TxOut(change_satoshis, script_pubkey))

tx_obj = Tx(1, tx_ins, tx_outs, 0, testnet=True)
tx_obj.sign_input(0, priv)

print(tx_obj.verify())

print('My Transaction:')
print(tx_obj)

print('My Transaction Hex:')
print(tx_obj.serialize().hex())