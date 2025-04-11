from ecc.S256 import *

secret1 = 23396049
privateKey1 = PrivateKey(secret1)
print(privateKey1.point.sec())

