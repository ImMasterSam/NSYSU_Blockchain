import hashlib
from io import BytesIO

SIGHASH_ALL = 1

def hash256(s):
    '''Two rounds of sha256'''
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def encode_base58(s: bytes) -> str:
    '''Transform the bytes into base58 format'''

    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result

    return prefix + result

def decode_base58(s: str) -> bytes:

    BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    combined = num.to_bytes(25, 'big')
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError(f'Bad Address: {checksum} {hash256(combined[:-4])[:4]}')
    return combined[1:-4]

def hash160(s: bytes) -> bytes:
    '''SHA256 folllowed by RIPEMD160'''
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()

def encode_base58_checksum(b: bytes) -> bytes:
    '''Return the encoded format of the address'''
    return encode_base58(b + hash256(b)[:4])

# Transactions Part

def little_endian_to_int(b: bytes) -> int:
    '''
    little_endian_to_int takes a byte sequence as a little-endian number.
    Returns an integer.
    '''
    return int.from_bytes(b, 'little')

def int_to_little_endian(i: int, length: int) -> bytes:
    '''
    int_to_little_endian takes an integer and returns a byte sequence
    of the specified length in little-endian format.
    '''
    return i.to_bytes(length, 'little')

def read_varint(s: BytesIO) -> int:
    '''read_varint reads a variable integer from the stream'''
    i = s.read(1)[0]
    if i == 0xfd:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # Anything else is just the integer itself
        return i
    
def encode_varint(i: int) -> bytes:
    '''envode integer as a varint'''
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + i.to_bytes(2, 'little')
    elif i < 0x100000000:
        return b'\xfe' + i.to_bytes(4, 'little')
    elif i < 0x10000000000000000:
        return b'\xff' + i.to_bytes(8, 'little')
    else:
        raise ValueError(f'Integer too large: {i}')