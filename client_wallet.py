
import configparser
import os
from bitcoinlib.wallet import CBitcoinSecret
import base58
import fileencrypt
import StringIO
from plain_wallet import PlainWallet


class ClientWallet(PlainWallet):
    def __init__(self, password):
        super(ClientWallet, self).__init__()
        self.password = password

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

        wallet_file = open(self.file_name, 'r')
        plain_text = wallet_file.read()

        fileencrypt.write_encrypted(self.password, self.file_name, plain_text)

    def read_private_key(self):
        if self.wallet_exists():
            if self.password is None:
                return super(PlainWallet, self).read_private_key()
            else:
                plain_text = fileencrypt.read_encrypted(self.password, self.file_name, string=True)
                buf = StringIO.StringIO(plain_text)
                config = configparser.ConfigParser()
                config.readfp(buf)
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
