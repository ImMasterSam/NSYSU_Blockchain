from ecc.S256 import *

# HW 3-1
secret1 = 23396049
privateKey1 = PrivateKey(secret1)
print(privateKey1.point.sec(compressed = False).hex())

# HW 3-2
secret2 = 23396050
privateKey2 = PrivateKey(secret2)
print(privateKey2.point.sec(compressed = True).hex())

# HW 3-3
r = 0x8208f5abf04066bad1db9d46f8bcf5a6cc11d0558ab523e7bd3c0ec08bdb782f 
s = 0x22afcd685b7c0c8b525c2a52529423fcdff22f69f3e9c175ac9cb3ec08de87d8
sig = Signature(r, s)
print(sig.der().hex())
