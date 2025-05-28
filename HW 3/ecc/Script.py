from __future__ import annotations
from io import BytesIO

from helper.tools import *
from helper.op import *

def p2pkh_script(h160: bytes) -> Script:
    '''Takes a h160 and returns the p2pkh scriptPubKey'''
    return Script([0x76, 0xa9, h160, 0x88, 0xac])

class Script:

    def __init__(self, cmds = None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __repr__(self) -> str:
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    @classmethod
    def parse(cls, s: BytesIO) -> Script:
        length = read_varint(s)
        cmds = []
        count = 0
        while count < length:
            current = s.read(1)
            count += 1
            current_byte = current[0]

            if current_byte >= 1 and current_byte <= 75:
                n = current_byte
                cmds.append(s.read(n))
                count += n
            elif current_byte == 76:
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                op_code = current_byte
                cmds.append(op_code)

        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)
    
    def raw_serialize(self) -> bytes:
        result = b''
        for cmd in self.cmds:
            if isinstance(cmd, int):
                result += cmd.to_bytes(1, 'little')
            else:
                length = len(cmd)
                if length < 75:
                    result += int_to_little_endian(length, 1)
                elif length > 75 and length < 0x100:
                    result += int_to_little_endian(76, 1) + int_to_little_endian(length, 1)
                elif length > 0x100 and length < 520:
                    result += int_to_little_endian(77, 1) + int_to_little_endian(length, 2)
                else:
                    raise ValueError('too long an cmd')
                result += cmd
        return result
    
    def serialize(self) -> bytes:
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result
    
    def evaluate(self, z) -> bool:
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            if isinstance(cmd, int):
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100):                # OP_IF, OP_NOTIF
                    if not operation(stack, cmds):
                        return False
                elif cmd in (107, 108):             # OP_TOALTSTACK, OP_FROMALTSTACK
                    if not operation(stack, altstack):
                        return False
                elif cmd in (172, 173, 174, 175):   # OP_CHECKSIG, OP_CHECKMULTISIG, OP_CHECKSIGVERIFY, OP_CHECKMULTISIGVERIFY
                    if not operation(stack, z):
                        return False
                else:
                    if not operation(stack):
                        return False
            else:
                stack.append(cmd)

        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True
    
    def __add__(self, other: Script) -> Script:
        return Script(self.cmds + other.cmds)