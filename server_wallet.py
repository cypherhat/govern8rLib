
import os
from bitcoinlib.wallet import CBitcoinSecret
import base58
from plain_wallet import PlainWallet
import boto3
import botocore
from boto3.dynamodb.conditions import Key
import resource_factory


class ServerWallet(PlainWallet):
    def __init__(self, config, logger):
        super(ServerWallet, self).__init__()
        self.config = config
        self.key_id = config.get_key_id()
        self.logger = logger
        self.kms = None
        self.dynamodb = None
        self.wallet_table = None

    def instance(self):
        try:
            self.kms = boto3.client('kms', region_name='us-east-1')
            self.dynamodb = resource_factory.get_dynamodb(self.config)
        except botocore.exceptions.ClientError as e:
            self.logger.exception("Error creating server wallet %s " % e.message)
        if not self.wallet_exists():
            self.create_new_wallet()

        try:
            self.private_key_hex = self.read_private_key()
            self.private_key_wif = base58.base58_check_encode(0x80, self.private_key_hex.decode("hex"))
            self.private_key = CBitcoinSecret(self.private_key_wif)
        except ValueError as e:
            self.logger.exception("Problem with wallet %s " % e.message)

    def get_wallet(self):
        try:
            response = self.wallet_table.query(KeyConditionExpression=Key('key_id').eq(self.key_id))
        except botocore.exceptions.ClientError as e:
            self.logger.exception("Failed read account table %s" % e.response)

        if len(response['Items']) == 0:
            return self.create_wallet()
        else:
            return response['Items'][0]

    def create_key(self, encrypted_hex):
        wallet = {
            'key_id': self.key_id,
            'encrypted_hex': encrypted_hex
        }
        try:
            self.wallet_table.put_item(Item=wallet)
        except botocore.exceptions.ClientError as e:
            self.logger.exception("Failed to add to wallet table %s" % e.response)
        return wallet

    def create_wallet_table(self):
        try:
            self.wallet_table = self.dynamodb.create_table(
                TableName='Wallet',
                KeySchema=[
                    {
                        'AttributeName': 'key_id',
                        'KeyType': 'HASH'
                    }
                ],
                AttributeDefinitions=[
                    {
                        'AttributeName': 'key_id',
                        'AttributeType': 'S'
                    }
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 10,
                    'WriteCapacityUnits': 10
                }
            )
            self.logger.debug("Account Table is %s" % self.wallet_table.table_status)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ResourceInUseException':
                self.logger.exception("Houston, we have a problem: the Wallet Table exists.")

    def wallet_exists(self):
        try:
            self.wallet_table = self.dynamodb.Table('Wallet')
            self.logger.debug("Wallet Table is %s" % self.wallet_table.table_status)
            return True
        except botocore.exceptions.ClientError as e:
            self.logger.exception("Problem accessing wallet table %s " % e.response)
        return False

    def generate_encrypted_private_key(self):
        private_key = os.urandom(32)
        private_hex = private_key.encode("hex")
        encrypted_hex = self.encrypt_to_hex(private_hex)
        return encrypted_hex

    def create_wallet(self):
        encrypted_hex = self.generate_encrypted_private_key()
        return self.create_key(encrypted_hex)

    def create_new_wallet(self):
        # Create private key
        self.create_wallet_table()
        self.create_wallet()

    def read_private_key(self):
        if self.wallet_exists():
            if self.kms is None:
                raise ValueError('Key Management Service failed!')
            else:
                wallet = self.get_wallet()
                encrypted_hex = wallet['encrypted_hex']
                private_hex = self.decrypt_from_hex(encrypted_hex)
                return private_hex
        else:
            raise ValueError('Wallet does not exist!')

    def encrypt_to_hex(self, plaintext):
        encryption_context = {}
        encrypted_hex = None
        try:
            token = self.kms.encrypt(KeyId=self.key_id, Plaintext=plaintext, EncryptionContext=encryption_context)
            ciphertext = token['CiphertextBlob']
            encrypted_hex = ciphertext.encode('hex')
        except botocore.exceptions.ClientError as e:
            self.logger.exception("Error encrypting %s " % e.response)

        if encrypted_hex is None:
            raise ValueError('Wallet does not exist!')
        return encrypted_hex

    def decrypt_from_hex(self, ciphertext):
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
