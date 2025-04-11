from ecc.S256 import *

# HW 4-1
secret1_1 = 23396051
secret1_2 = 23396052
privateKey1_1 = PrivateKey(secret1_1)
privateKey1_2 = PrivateKey(secret1_2)
print(privateKey1_1.point.address(compressed = False, testnet = True))
print(privateKey1_2.point.address(compressed = True, testnet = True))

# HW 4-2
secret2 = 23396053
privateKey2 = PrivateKey(secret2)
print(privateKey2.wif(compressed = True, testnet = True))
