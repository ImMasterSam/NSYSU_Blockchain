import hashlib

from ecc.S256 import *
from helper.tools import *

import hashlib


def encode_num(num: int) -> bytes:
    if num == 0:
        return b''
    
    abs_num = abs(num)
    negative = num < 0
    result = bytearray()

    while abs_num:
        result.append(abs_num & 0xff)
        abs_num >>= 8
    
    if result[-1] & 0x80:
        if negative:
            result.append(0x80)
        else:
            result.append(0)
    elif negative:
        result[-1] |= 0x80

    return bytes(result)


def decode_num(element: bytes) -> int:
    if element == b'':
        return 0
    
    big_endian = element[::-1]
    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7f
    else:
        negative = False
        result = big_endian[0]

    for c in big_endian[1:]:
        result <<= 8
        result += c

    if negative:
        return -result
    else:
        return result
    


def op_0(stack: list) -> bool:
    stack.append(encode_num(0))
    return True


def op_1(stack: list):
    stack.append(encode_num(1))
    return True


def op_2(stack: list):
    stack.append(encode_num(2))
    return True


def op_3(stack: list):
    stack.append(encode_num(3))
    return True


def op_4(stack: list):
    stack.append(encode_num(4))
    return True


def op_5(stack: list):
    stack.append(encode_num(5))
    return True


def op_6(stack: list):
    stack.append(encode_num(6))
    return True


def op_7(stack: list):
    stack.append(encode_num(7))
    return True


def op_8(stack: list):
    stack.append(encode_num(8))
    return True


def op_9(stack: list):
    stack.append(encode_num(9))
    return True


def op_10(stack: list):
    stack.append(encode_num(10))
    return True


def op_11(stack: list):
    stack.append(encode_num(11))
    return True


def op_12(stack: list):
    stack.append(encode_num(12))
    return True


def op_13(stack: list):
    stack.append(encode_num(13))
    return True


def op_14(stack: list):
    stack.append(encode_num(14))
    return True


def op_15(stack: list):
    stack.append(encode_num(15))
    return True


def op_16(stack: list):
    stack.append(encode_num(16))
    return True


def op_verify(stack: list):
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        return False
    return True

def op_dup(stack: list):
    if len(stack) < 1:  
        return False
    stack.append(stack[-1])  
    return True


def op_equal(stack: list):
    if len(stack) < 2:
        return False
    element1 = stack.pop()
    element2 = stack.pop()
    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True



def op_add(stack: list):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element1 + element2))
    return True


def op_sub(stack: list):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element2 - element1))
    return True


def op_mul(stack: list):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element2 * element1))
    return True


def op_ripemd160(stack: list):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.new('ripemd160', element).digest())
    return True


def op_hash160(stack: list):
    # check that there's at least 1 element on the stack
    if len(stack) < 1:
        return False
    # pop off the top element from the stack
    element = stack.pop()
    # push a hash160 of the popped off element to the stack
    h160 = hash160(element)
    stack.append(h160)
    return True


def op_hash256(stack: list):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash256(element))
    return True


def op_checksig(stack: list, z):
    # check that there are at least 2 elements on the stack
    if len(stack) < 2:
        return False
    # the top element of the stack is the SEC pubkey
    sec_pubkey = stack.pop()
    # the next element of the stack is the DER signature
    # take off the last byte of the signature as that's the hash_type
    der_signature = stack.pop()[:-1]
    # parse the serialized pubkey and signature into objects
    try:
        point = S256Point.parse(sec_pubkey)
        sig = Signature.parse(der_signature)
    except (ValueError, SyntaxError) as e:
        return False
    # verify the signature using S256Point.verify()
    # push an encoded 1 or 0 depending on whether the signature verified
    stack.append(encode_num(1) if point.verify(z, sig) else encode_num(0))
    
    return True


OP_CODE_FUNCTIONS = {
    0: op_0,
    81: op_1,
    82: op_2,
    83: op_3,
    84: op_4,
    85: op_5,
    86: op_6,
    87: op_7,
    88: op_8,
    89: op_9,
    90: op_10,
    91: op_11,
    92: op_12,
    93: op_13,
    94: op_14,
    95: op_15,
    96: op_16,
    105: op_verify,
    118: op_dup,
    135: op_equal,
    147: op_add,
    148: op_sub,
    149: op_mul,
    166: op_ripemd160,
    169: op_hash160,
    170: op_hash256,
    172: op_checksig,
}

OP_CODE_NAMES = {
    0: 'OP_0',
    81: 'OP_1',
    82: 'OP_2',
    83: 'OP_3',
    84: 'OP_4',
    85: 'OP_5',
    86: 'OP_6',
    87: 'OP_7',
    88: 'OP_8',
    89: 'OP_9',
    90: 'OP_10',
    91: 'OP_11',
    92: 'OP_12',
    93: 'OP_13',
    94: 'OP_14',
    95: 'OP_15',
    96: 'OP_16',
    105: 'OP_VERIFY',
    118: 'OP_DUP',
    135: 'OP_EQUAL',
    147: 'OP_ADD',
    148: 'OP_SUB',
    149: 'OP_MUL',
    166: 'OP_RIPEMD160',
    169: 'OP_HASH160',
    170: 'OP_HASH256',
    172: 'OP_CHECKSIG'
}