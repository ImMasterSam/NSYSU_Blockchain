from __future__ import annotations
import hashlib, hmac

from ecc.FieldElement import *
from ecc.Point import *
from helper.tools import *

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

    # Return square root in S256 field
    def sqrt(self):
        return self**((P + 1) // 4)

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

    # Representation
    def __repr__(self):
        return f'S256Point({hex(self.x.num)}, {hex(self.y.num)})'

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

    # Returns the binary version of the SEC format
    def sec(self, compressed = True) -> bytes:
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32, 'big')
        
    # Decode a serialized SEC publickey
    @classmethod
    def parse(self, sec_bin: bytes) -> S256Point:
        #Uncompressed
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(x, y)
        # Compressed
        else:
            is_even = sec_bin[0] == 2
            x = int.from_bytes(sec_bin[1:], 'big')
            alpha: S256Field = x**3 + S256Field(B)
            beta: S256Field  = alpha.sqrt()

            if beta.num % 2 == 0:
                if is_even:
                    return S256Point(x, beta)
                else:
                    return S256Point(x, S256Field(P - beta.num))
            else:
                if is_even:
                    return S256Point(x, S256Field(P - beta.num))
                else:
                    return S256Point(x, beta)
                
    # Return the hash160 version for the public key
    def hash160(self, compressed = True) -> bytes:
        return hash160(self.sec(compressed))
    
    # Return the address string of the public key
    def address(self, compressed = True, testnet = False) -> str:
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + h160)
        

G = S256Point(Gx, Gy)
    
class Signature:

    # Constructor
    def __init__(self, r, s):
        self.r: int = r
        self.s: int = s

    # Representation
    def __repr__(self) -> str:
        return f'Signature({self.r}, {self.s})'
    
    # Returns the binary version of the DER format
    def der(self) -> bytes:
        rbin = self.r.to_bytes(32, byteorder = 'big')
        rbin = rbin.lstrip(b'\x00')
        # if rbin has high bit, add a \x00
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin
        result = bytes([2, len(rbin)]) + rbin

        sbin = self.s.to_bytes(32, byteorder = 'big')
        sbin = sbin.lstrip(b'\x00')
        # if sbin has high bit, add a \x00
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
        result += bytes([2, len(rbin)]) + sbin
        return bytes([0x30, len(result)]) + result
    
    
class PrivateKey:

    # Constructor
    def __init__(self, secret):
        self.secret: int = secret                    # Private Key
        self.point: S256Point = secret * G      # Public Key

    # Return private key in hex Format
    def hex(self) -> str:
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
    
    # Return the WIF format of the private key
    def wif(self, compressed = True, testnet = False) -> str:
        secret_bytes = self.secret.to_bytes(32, 'big')

        if testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'
        
        if compressed:
            suffix = b'\x01'
        else:
            suffix = b''

        return encode_base58_checksum(prefix + secret_bytes + suffix)
