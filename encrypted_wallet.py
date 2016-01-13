import configparser
import os
from bitcoinlib.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from bitcoinlib.signmessage import BitcoinMessage, VerifyMessage, SignMessage
import base58
import fileencrypt
import StringIO

section_name = 'NotaryWallet'
file_name = 'notarywallet.data'


def wallet_exists():
    if os.path.exists(file_name) and os.path.isfile(file_name):
        return True
    else:
        return False


def read_private_key(password):
    if wallet_exists():
        plain_text = fileencrypt.read_encrypted(password, file_name, string=True)
        buf = StringIO.StringIO(plain_text)
        config = configparser.ConfigParser()
        config.readfp(buf)
        if config.has_option(section_name, 'private_key'):
            private_hex = config.get(section_name, 'private_key')
            return private_hex
        else:
            raise ValueError('Private key does not exist!')
    else:
        raise ValueError('Wallet does not exist!')


def create_new_wallet(password):
    if wallet_exists():
        raise ValueError('Wallet already exists!')
    # Create private key
    private_key = os.urandom(32)
    private_hex = private_key.encode("hex")

    config = configparser.ConfigParser()
    config.add_section(section_name)
    config.set(section_name, 'private_key',  private_hex)
    with open(file_name, 'w') as configfile:
        config.write(configfile)

    wallet_file = open(file_name, 'r')
    plain_text = wallet_file.read()

    fileencrypt.write_encrypted(password, file_name, plain_text)


class NotaryWallet(object):
    """An encapsulated wallet for notary stuff.

    """
    def __init__(self, password):
        if not wallet_exists():
            create_new_wallet(password)
        self.private_key_hex = read_private_key(password)
        self.private_key_wif = base58.base58_check_encode(0x80, self.private_key_hex.decode("hex"))
        self.private_key = CBitcoinSecret(self.private_key_wif)

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


def main():
    notary_obj = NotaryWallet()
