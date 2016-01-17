import boto3
import botocore
import configparser
import os
from bitcoinlib.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from bitcoinlib.signmessage import BitcoinMessage, VerifyMessage, SignMessage
import base58
import fileencrypt
import StringIO


section_name = 'NotaryWallet'
file_name = 'notarywallet.data'


class PlainWallet(object):
    """An encapsulated wallet for notary stuff.
    """
    def __init__(self):
        if not self.wallet_exists():
            self.create_new_wallet()
        self.private_key_hex = self.read_private_key()
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

    def wallet_exists(self):
        if os.path.exists(file_name) and os.path.isfile(file_name):
            return True
        else:
            return False

    def create_new_wallet(self):
        print ("Defaulting to PlainWallet")
        if self.wallet_exists():
            raise ValueError('Wallet already exists!')
        # Create private key
        private_key = os.urandom(32)
        private_hex = private_key.encode("hex")

        config = configparser.ConfigParser()
        config.add_section(section_name)
        config.set(section_name, 'private_key',  private_hex)

        with open(file_name, 'w') as configfile:
            config.write(configfile)

    def read_private_key(self):
        if self.wallet_exists():
            config = configparser.ConfigParser()
            config.read(file_name)
            if config.has_option(section_name, 'private_key'):
                private_hex = config.get(section_name, 'private_key')
                return private_hex
            else:
                raise ValueError('Private key does not exist!')
        else:
            raise ValueError('Wallet does not exist!')


class ServerWallet(PlainWallet):
    def __init__(self, key_id):
        super(PlainWallet, self).__init__()
        try:
            self.kms = boto3.client('kms')
        except botocore.exceptions.ClientError as e:
            self.kms = None
            print(e)

        self.key_id = key_id
        if not self.wallet_exists():
            self.create_new_wallet()
        self.private_key_hex = self.read_private_key()
        self.private_key_wif = base58.base58_check_encode(0x80, self.private_key_hex.decode("hex"))
        self.private_key = CBitcoinSecret(self.private_key_wif)

    def create_new_wallet(self):
        if self.wallet_exists():
            raise ValueError('Wallet already exists!')
        # Create private key
        if self.kms is None:
            super(ServerWallet, self).create_new_wallet()
        else:
            private_key = os.urandom(32)
            private_hex = private_key.encode("hex")
            encrypted_hex = self.encrypt_to_hex(private_hex)
            config = configparser.ConfigParser()
            config.add_section(section_name)
            config.set(section_name, 'private_key',  encrypted_hex)

            with open(file_name, 'w') as configfile:
                config.write(configfile)

    def read_private_key(self):
        if self.wallet_exists():
            config = configparser.ConfigParser()
            config.read(file_name)
            if config.has_option(section_name, 'private_key'):
                if self.kms is None:
                    return super(ServerWallet, self).read_private_key()
                else:
                    encrypted_hex = config.get (section_name, 'private_key')
                    private_hex = self.decrypt_from_hex(encrypted_hex)
                    return private_hex
            else:
                raise ValueError('Private key does not exist!')
        else:
            raise ValueError('Wallet does not exist!')

    def encrypt_to_hex(self, plaintext):
        encryption_context = {}

        try:
            token = self.kms.encrypt(KeyId=self.key_id, Plaintext=plaintext, EncryptionContext=encryption_context)
        except botocore.exceptions.ClientError as e:
            print(e)

        ciphertext = token['CiphertextBlob']
        hex = ciphertext.encode('hex')
        return hex

    def decrypt_from_hex(self, ciphertext):
        encryption_context = {}
        encoded_ciphertext = ciphertext.decode('hex')

        try:
            decrypted_token = self.kms.decrypt(CiphertextBlob=encoded_ciphertext, EncryptionContext=encryption_context)
        except botocore.exceptions.ClientError as e:
            print(e)

        plaintext = decrypted_token['Plaintext']
        return plaintext


class ClientWallet(PlainWallet):
    def __init__(self, password):
        super(PlainWallet, self).__init__()
        self.password = password
        if not self.wallet_exists():
            self.create_new_wallet()
        self.private_key_hex = self.read_private_key()
        self.private_key_wif = base58.base58_check_encode(0x80, self.private_key_hex.decode("hex"))
        self.private_key = CBitcoinSecret(self.private_key_wif)

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
            config.add_section(section_name)
            config.set(section_name, 'private_key',  private_hex)
            with open(file_name, 'w') as configfile:
                config.write(configfile)

            wallet_file = open(file_name, 'r')
            plain_text = wallet_file.read()

            fileencrypt.write_encrypted(self.password, file_name, plain_text)

    def read_private_key(self):
        if self.wallet_exists():
            if self.password is None:
                return super(PlainWallet, self).read_private_key()
            else:
                plain_text = fileencrypt.read_encrypted(self.password, file_name, string=True)
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
