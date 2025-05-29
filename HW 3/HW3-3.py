from ecc.Script import Script

script_pubkey = Script([0x76, 0x76, 0x95, 0x93, 0x56, 0x87])
script_sig = Script([0x52]) # OP_2
combined_script = script_sig + script_pubkey
# 2 + (2 * 2) == 6
print("Evaluate:", combined_script)
print(combined_script.evaluate(0))