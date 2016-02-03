
import configparser
import os
from bitcoinlib.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from bitcoinlib.signmessage import BitcoinMessage, VerifyMessage, SignMessage
import base58


class PlainWallet(object):
    """An encapsulated wallet for notary stuff.
    """
    def __init__(self):
        self.file_name = 'notarywallet.data'
        self.section_name = 'NotaryWallet'
        self.private_key_hex = None
        self.private_key_wif = None
        self.private_key = None

    def sign(self, message):
        bitcoin_message = BitcoinMessage(message)
        signature = SignMessage(self.private_key, bitcoin_message)
        return signature

    def verify(self, message, signature):
        bitcoin_message = BitcoinMessage(message)
        return VerifyMessage(self.get_bitcoin_address(), bitcoin_message, signature)

    def get_private_key(self):
        return self.private_key

    def get_public_key(self):
        return self.private_key.pub

    def get_public_key_hex(self):
        return self.private_key.pub.encode("hex")

    def get_bitcoin_address(self):
        return P2PKHBitcoinAddress.from_pubkey(self.private_key.pub)

    def get_private_key_wif(self):
        return self.private_key_wif

    def wallet_exists(self):
        if os.path.exists(self.file_name) and os.path.isfile(self.file_name):
            return True
        else:
            return False

    def instance(self):
        if not self.wallet_exists():
            self.create_new_wallet()
        self.private_key_hex = self.read_private_key()
        self.private_key_wif = base58.base58_check_encode(0x80, self.private_key_hex.decode("hex"))
        self.private_key = CBitcoinSecret(self.private_key_wif)

    def create_new_wallet(self):
        private_key = os.urandom(32)
        private_hex = private_key.encode("hex")

        config = configparser.ConfigParser()
        config.add_section(self.section_name)
        config.set(self.section_name, 'private_key',  private_hex)

        with open(self.file_name, 'w') as configfile:
            config.write(configfile)

    def read_private_key(self):
        if self.wallet_exists():
            config = configparser.ConfigParser()
            config.read(self.file_name)
            if config.has_option(self.section_name, 'private_key'):
                private_hex = config.get(self.section_name, 'private_key')
                return private_hex
            else:
                raise ValueError('Private key does not exist!')
        else:
            raise ValueError('Wallet does not exist!')

    def generate_encrypted_private_key(self):
        private_key = os.urandom(32)
        private_hex = private_key.encode("hex")
        encrypted_hex = self.encrypt_to_hex(private_hex)
        return encrypted_hex

    def encrypt_to_hex(self, plaintext):
        return plaintext

    def decrypt_from_hex(self, ciphertext):
        return ciphertext
