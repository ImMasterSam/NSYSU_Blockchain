from ecc.S256 import *

Px = 0x801be5a7c4faf73dd1c3f28cebf78d6ba7885ead88879b76ffb815d59056af14
Py = 0x826ddfcc38dafe6b8d463b609facc009083c8173e21c5fc45b3424964e85f49e
z  = 0x90d7aecf3f2855d60026f10faab852562c76e7e043cf243474ba5018447c2c22
r  = 0xf01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f
s  = 0x22afcd685b7c0c8b525c2a52529423fcdff22f69f3e9c175ac9cb3ec08de87d8

sig = Signature(r, s)
point = S256Point(Px, Py)

if point.verify(z, sig):
    print("The signature is valid")
else:
    print("The signature is NOT valid")