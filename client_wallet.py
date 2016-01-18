
import configparser
import os
from bitcoinlib.wallet import CBitcoinSecret
import base58
import fileencrypt
import StringIO
from plain_wallet import PlainWallet


class ClientWallet(PlainWallet):
    def __init__(self, password):
        super(PlainWallet, self).__init__()
        self.password = password
        try:
            if not self.wallet_exists():
                self.create_new_wallet()
            self.private_key_hex = self.read_private_key()
            self.private_key_wif = base58.base58_check_encode(0x80, self.private_key_hex.decode("hex"))
            self.private_key = CBitcoinSecret(self.private_key_wif)
        except ValueError as e:
            print("Wallet cannot be created due to %s " % e.message)

    def create_new_wallet(self):
        if self.wallet_exists():
            raise ValueError('Wallet already exists!')
        # Create private key
        if self.password is None:
            super(PlainWallet, self).create_new_wallet()
        else:
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
