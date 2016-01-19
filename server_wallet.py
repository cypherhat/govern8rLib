import configparser
import os
from bitcoinlib.wallet import CBitcoinSecret
import base58
from plain_wallet import PlainWallet
import boto3
import botocore


class ServerWallet(PlainWallet):
    def __init__(self, key_id):
        super(ServerWallet, self).__init__()
        self.key_id = key_id
        self.kms = None

    def instance(self):
        try:
            self.kms = boto3.client('kms', region_name='us-east-1')
        except botocore.exceptions.ClientError as e:
            print("Error contacting KMS %s " % e.message)
        if not self.wallet_exists():
            self.create_new_wallet()
        self.private_key_hex = self.read_private_key()
        self.private_key_wif = base58.base58_check_encode(0x80, self.private_key_hex.decode("hex"))
        self.private_key = CBitcoinSecret(self.private_key_wif)

    def create_new_wallet(self):
        # Create private key
        temp_private_key = os.urandom(32)
        temp_private_hex = temp_private_key.encode("hex")
        temp_encrypted_hex = self.encrypt_to_hex(temp_private_hex)
        config = configparser.ConfigParser()
        config.add_section(self.section_name)
        config.set(self.section_name, 'private_key',  temp_encrypted_hex)

        with open(self.file_name, 'w') as configfile:
            config.write(configfile)

    def read_private_key(self):
        if self.wallet_exists():
            config = configparser.ConfigParser()
            config.read(self.file_name)
            if config.has_option(self.section_name, 'private_key'):
                if self.kms is None:
                    raise ValueError('Key Management Service failed!')
                else:
                    encrypted_hex = config.get(self.section_name, 'private_key')
                    private_hex = self.decrypt_from_hex(encrypted_hex)
                    return private_hex
            else:
                raise ValueError('Private key does not exist!')
        else:
            raise ValueError('Wallet does not exist!')

    def encrypt_to_hex(self, plaintext):
        import botocore
        encryption_context = {}
        encrypted_hex = None
        try:
            token = self.kms.encrypt(KeyId=self.key_id, Plaintext=plaintext, EncryptionContext=encryption_context)
            ciphertext = token['CiphertextBlob']
            encrypted_hex = ciphertext.encode('hex')
        except botocore.exceptions.ClientError as e:
            print(e)

        if encrypted_hex is None:
            raise ValueError('Wallet does not exist!')
        return encrypted_hex

    def decrypt_from_hex(self, ciphertext):
        import botocore
        encryption_context = {}
        encoded_ciphertext = ciphertext.decode('hex')
        plaintext = None
        try:
            decrypted_token = self.kms.decrypt(CiphertextBlob=encoded_ciphertext, EncryptionContext=encryption_context)
            plaintext = decrypted_token['Plaintext']
        except botocore.exceptions.ClientError as e:
            print(e)

        if plaintext is None:
            raise ValueError('Wallet does not exist!')

        return plaintext
