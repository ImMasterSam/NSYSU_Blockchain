from io import BytesIO
from ecc.Transaction import Tx

hex_transaction = '010000000117e18a4a4a0af876b1b0a4764ee77c74106e07667dd94c4d61271f3d356cbf62000000006b4830450221009e661e94622a66f6c65f270d859828360c825ee755d675c9cbb2214685ba08fc022005aa4abaf21a84519f0c8ff40c633a0e4a624c639d25c0ea908d0d5e463749a80121036ddc934a5fbd5222ead406a4334462aaa62f83d0b02255c0a582f9038a17bbfdffffffff02cc162c00000000001976a914051b07716871833694a762ad15565b86da46622488ac16ae0e00000000001976a914c03ee4258550c77bcf61829c7cb636cd521ebfc588ac00000000'
# hex_transaction = '01000 ... 0000'

stream = BytesIO(bytes.fromhex(hex_transaction))
tx_obj = Tx.parse(stream)
print("ScriptSig from the first input:")
print(tx_obj.tx_ins[0].script_sig)
print("ScriptPubKey from the first output:")
print(tx_obj.tx_outs[0].script_pubkey)
print("The amount of the second output:")
print(tx_obj.tx_outs[1].amount)