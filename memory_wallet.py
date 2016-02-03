
import configparser
import os
from bitcoinlib.wallet import CBitcoinSecret
import base58
import fileencrypt
import StringIO
from plain_wallet import PlainWallet


class MemoryWallet(PlainWallet):
    def __init__(self, private_key_hex):
        super(MemoryWallet, self).__init__()
        self.private_key_hex = private_key_hex

    def instance(self):
        self.private_key_wif = base58.base58_check_encode(0x80, self.private_key_hex.decode("hex"))
        self.private_key = CBitcoinSecret(self.private_key_wif)
