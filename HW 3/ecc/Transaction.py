from __future__ import annotations
from helper.tools import *
from io import BytesIO
import requests

class Tx:

    def __init__(self, version, tx_ins: list[TxIn], tx_outs: list[TxOut], locktime, testnet = False):
        '''The constructor for the Tx class'''
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def __repr__(self) -> str:
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n' 
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return f'tx: {self.id()}\nversion: {self.version}\ntx_ins:\n{tx_ins}tx_outs:\n{tx_outs}locktime: {self.locktime}'
        
    def id(self) -> str:
        '''Human-readable hexadecimal of the transaction hash'''
        return self.hash().hex()
    
    def hash(self) -> bytes:
        '''Binary hash of the legacy serialization'''
        return hash256(self.serialize())[::-1] # little-endian
    
    @classmethod
    def parse(cls, s: BytesIO, testnet: bool = False) -> Tx:
        version = little_endian_to_int(s.read(4))
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime, testnet)

    def serialize(self) -> bytes:
        '''Returns the byte serialization bytes of the transaction'''
        result = self.version.to_bytes(4, 'little')
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += self.locktime.to_bytes(4, 'little')
        return result
    
    def fee(self, testnet: bool = False) -> int:
        '''Returns the transaction fee'''
        input_sum, output_sum = 0, 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(testnet)
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum

class TxIn:
    def __init__(self, prev_tx: bytes, prev_index: int, script_sig: bytes = None, sequence: int = 0xffffffff):
        '''The constructor for the TxIn class'''
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:  
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self) -> str:
        return f'{self.prev_tx.hex()}:{self.prev_index}'
    
    @classmethod
    def parse(cls, s: BytesIO) -> TxIn:
        '''
        Takes a bytes stream and parses the tx_input at the start.
        Returns a TxIn object.
        '''
        # prev_tx is 32 bytes, little-endian
        prev_tx = s.read(32)[::-1]
        # prev_index is an integer in 4 bytes, little-endian
        prev_index = little_endian_to_int(s.read(4))
        # Use Script.parse to get the ScriptSig
        script_sig = Script.parse(s)
        # sequence is an integer in 4 bytes, little-endian
        sequence = little_endian_to_int(s.read(4))
        # Return an instance of the class (see __init__ for args)
        return cls(prev_tx, prev_index, script_sig, sequence)
    
    def serialize(self) -> bytes:
        '''Returns the byte serialization bytes of the transaction input'''
        result = self.prev_tx[::-1]
        result += self.prev_index.to_bytes(4, 'little')
        result += self.script_sig.serialize()
        result += self.sequence.to_bytes(4, 'little')
        return result
    
    def fetch_tx(self, testnet: bool = False) -> Tx:
        '''Use the TxFetcher class to fetch the transaction'''
        return TxFetcher.fetch(self.prev_tx.hex(), testnet)
    
    def value(self, testnet: bool = False) -> int:
        '''
        Get the output value by looking up the tx hash.
        Return the amount in satoshis.
        '''
        tx = self.fetch_tx(testnet)
        return tx.tx_outs[self.prev_index].amount
    
    def script_pubkey(self, testnet: bool = False) -> Script:
        '''
        Get the ScriptPubKey by looking up the tx hash.
        Return the Script object.
        '''
        tx = self.fetch_tx(testnet)
        return tx.tx_outs[self.prev_index].script_pubkey
    
class TxOut:

    def __init__(self, amount: int, script_pubkey: bytes = None):
        '''The constructor for the TxOut class'''
        self.amount = amount
        self.script_pubkey = script_pubkey
    
    def __repr__(self) -> str:
        return f'{self.amount}:{self.script_pubkey.hex()}'
    
    @classmethod
    def parse(cls, s: BytesIO) -> TxOut:
        '''
        Takes a bytes stream and parses the tx_output at the start.
        Returns a TxOut object.
        '''
        # amount is an integer in 8 bytes, little-endian
        amount = little_endian_to_int(s.read(8))
        # Use Script.parse to get the ScriptPubKey
        script_pubkey = Script.parse(s)
        # Return an instance of the class (see __init__ for args)
        return cls(amount, script_pubkey)
    
    def serialize(self) -> bytes:
        '''Returns the byte serialization bytes of the transaction output'''
        result = self.amount.to_bytes(8, 'little')
        result += self.script_pubkey.serialize()
        return result
    
class TxFetcher:
    cache: set[str] = {}

    @classmethod
    def get_url(cls, testnet: bool = False) -> str:
        if testnet:
            return 'https://blockstream.info/testnet/api/'
        else:
            return 'https://blockstream.info/api/'
        
    @classmethod
    def fetch(cls, tx_id: str, testnet: bool = False, fresh: bool = False) -> Tx:
        if fresh or (tx_id not in cls.cache):
            url = f'{cls.get_url(testnet)}/tx/{tx_id}/hex'
            response = requests.get(url)

            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError(f'Unexpected response: {response.text}')
            
            if raw[4] == 0:
                raw = raw[:4] + raw[5:]
                tx = Tx.parse(BytesIO(raw), testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet)

            if tx.id() != tx_id:
                raise ValueError(f'Not the same id : {tx.id()} vs {tx_id}')

            cls.cache[tx_id] = tx

        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]        