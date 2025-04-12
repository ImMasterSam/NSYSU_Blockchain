from ecc.S256 import *

# HW 4-1
secret1_1 = 23396051
secret1_2 = 23396052
privateKey1_1 = PrivateKey(secret1_1)
privateKey1_2 = PrivateKey(secret1_2)
print(f'the address corresponding to Public Keys whose Private Key secrets = {secret1_1} (uncompressed, testnet) :')
print(privateKey1_1.point.address(compressed = False, testnet = True))
print(f'the address corresponding to Public Keys whose Private Key secrets = {secret1_2} (compressed, testnet) :')
print(privateKey1_2.point.address(compressed = True, testnet = True))

print()

# HW 4-2
secret2 = 23396053
privateKey2 = PrivateKey(secret2)
print(f'the WIF for Private Key whose secrets = {secret2} (compressed, testnet) :')
print(privateKey2.wif(compressed = True, testnet = True))
