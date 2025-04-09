from __future__ import annotations
import hashlib, hmac

from ecc.FieldElement import *
from ecc.Point import *

A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

class S256Field(FieldElement):
    '''
    The FieldElement under secp256k1 curve
    '''
    
    # Constructor
    def __init__(self, num, prime = None):
        super().__init__(num = num, prime = P)

class S256Point(Point):
    '''
    The Point under secp256k1 curve
    ''' 
    
    # Constructor
    def __init__(self, x, y, a = None, b = None):
        
        a = S256Field(A)
        b = S256Field(B)

        if isinstance(x, int):
            super().__init__(x = S256Field(x), y = S256Field(y), a = a, b = b)
        else:
            super().__init__(x = x, y = y, a = a, b = b)

    # Multiplication Overloading (Right)
    # Mod coef to make sure coef is within N
    def __rmul__(self, coefficient) -> Point:
        coef = coefficient % N
        return super().__rmul__(coef)

    # Verify if the signatiure is valid
    def verify(self, z: int, sig: Signature) -> bool:
        s_inv = pow(sig.s, N - 2, N)
        u = (z * s_inv) % N
        v = (sig.r * s_inv) % N   
        total = u * G + v * self
        return total.x.num == sig.r
    
G = S256Point(Gx, Gy)
    
class Signature:

    # Constructor
    def __init__(self, r, s):
        self.r = r
        self.s = s

    # Representation
    def __repr__(self):
        return f'Signature({self.r}, {self.s})'
    
class PrivateKey:

    # Constructor
    def __init__(self, secret):
        self.secret = secret        # Private Key
        self.point = secret * G     # Public Key

    # Return private key in hex Format
    def hex(self):
        return f'{self.secret}'.zfill(64)
    
    # Create a Signature
    def sign(self, z: int) -> Signature:
        k = self.deterministic_k(z)
        r = (k * G).x.num
        k_inv = pow(k, N-2, N)
        s = ((z + r * self.secret) * k_inv) % N
        if s > N / 2:
            s = N - s
        return Signature(r, s)

    # Deterministic K create unique k ervery time
    def deterministic_k(self, z: int) -> int:
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()
    

