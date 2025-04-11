import hashlib

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