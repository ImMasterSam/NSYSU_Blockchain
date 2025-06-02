from io import BytesIO
from ecc.Script import *
from ecc.Transaction import *
from helper.tools import *
from helper.op import *

def op_checkmultisig(stack: list, z) -> bool:
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    sec_pubkeys = []
    for _ in range(n):
        sec_pubkeys.append(stack.pop())
    m = decode_num(stack.pop())
    if len(stack) < m + 1:
        return False
    der_signatures = []
    for _ in range(m):
        # signature is assumed to be using SIGHASH_ALL
        der_signatures.append(stack.pop()[:-1])
    stack.pop() # Take care of the off-by-one error by consuming

    try:
        # parse all the points, signatures
        points = [S256Point.parse(sec) for sec in sec_pubkeys]
        sigs = [Signature.parse(der) for der in der_signatures]
        # loop through the signatures
        for sig in sigs:
            # if we have no more points, signatures are invalid
            if len(points) == 0:
                return False
            # we loop until we find the point which works with this signature
            while points:
                # get the current point from the list of points
                point = points.pop(0)
                # we check if this signature goes with the current point
                if point.verify(z, sig):
                    break
        # the signatures are valid, so push a 1 to the stack
        stack.append(encode_num(1))
    except (ValueError, SyntaxError):
        return False
    return True