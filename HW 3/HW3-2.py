from ecc.S256 import S256Point, Signature
from helper.op import encode_num

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
