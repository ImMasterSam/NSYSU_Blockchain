from ecc.S256 import *
from helper.tools import *

e = 1234567
z = int.from_bytes(hash256(b'Introduction to Bitcoin homework 2.2'), 'big')
k = 1234567

r = (k * G).x.num
k_inv = pow(k, N - 2, N)
s = ((z + r*e) * k_inv) % N
point = e * G

print(point)
print(hex(z))
print(hex(r))
print(hex(s))
