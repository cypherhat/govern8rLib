import requests
import json
import hashfile
import wallet
from message import SecureMessage
from bitcoinlib.core.key import CPubKey
from bitcoinlib.wallet import P2PKHBitcoinAddress
from configuration import NotaryConfiguration
import log_handlers
import file_stream_encrypt


class Error(Exception):
    """Base class for exceptions in this module."""
    pass


class NotaryException(Error):
    """Exception raised for errors in the input.

    Attributes:
        error_code -- code
        error_message  -- explanation of the error
    """

    def __init__(self, error_code, error_message):
        self.error_code = error_code
        self.message = error_message


class NotaryServer(object):
    def __init__(self, config):
        self.config = config
        requests.packages.urllib3.disable_warnings()
        self.notary_url = self.get_notary_url()
        response = requests.get(self.notary_url + '/api/v1/pubkey', verify=self.config.get_ssl_verify_mode())
        data = response.json()
        self.other_party_public_key_hex = data['public_key']
        other_party_public_key_decoded = self.other_party_public_key_hex.decode("hex")
        self.other_party_public_key = CPubKey(other_party_public_key_decoded)
        self.other_party_address = P2PKHBitcoinAddress.from_pubkey(self.other_party_public_key)

    def get_address(self):
        return self.other_party_address

    def get_public_key_hex(self):
        return self.other_party_public_key_hex

    def get_notary_url(self):
        if self.config.is_remote_testing():
            return self.config.get_remote_server_url()
        else:
            return self.config.get_local_server_url()

    def get_account_url(self, address):
        return self.get_notary_url() + '/api/v1/account/' + address

    def get_challenge_url(self, address):
        return self.get_notary_url() + '/api/v1/challenge/' + address

    def get_notarization_url(self, address, document_hash):
        return self.get_notary_url() + '/api/v1/account/' + address + '/notarization/' + document_hash

    def get_notarization_status_url(self, address, document_hash):
        return self.get_notary_url() + '/api/v1/account/' + address + '/notarization/' + document_hash + '/status'

    def get_document_url(self, address, document_hash):
        return self.notary_url + '/api/v1/account/' + address + '/document/' + document_hash


class NotaryClient(object):
    def __init__(self, config_file, password):
        '''
           constructs needed objects
        Parameters
        ----------
        password  : takes the password of the wallet

        Returns
        -------

        '''

        self.config = NotaryConfiguration(config_file)
        self.logger = log_handlers.get_logger(self.config)
        self.ssl_verify_mode = self.config.get_ssl_verify_mode()
        self.wallet = wallet.create_wallet(self.config.get_wallet_type(), password, self.logger)
        self.secure_message = SecureMessage(self.wallet)
        self.notary_server = NotaryServer(self.config)
        self.address = str(self.wallet.get_bitcoin_address())

    def get_server_pubkey(self):
        return self.notary_server.get_public_key_hex()

    def get_payload(self, message):
        str_message = json.dumps(message)
        return self.secure_message.create_secure_payload(self.notary_server.get_public_key_hex(), str_message)

    def authenticate(self):
        challenge_url = self.notary_server.get_challenge_url(self.address)
        response = requests.get(challenge_url, verify=self.ssl_verify_mode)
        if response.status_code != 200:
            raise NotaryException(response.status_code, "Error getting authentication challenge!")
        payload = json.loads(response.content)
        if self.secure_message.verify_secure_payload(self.notary_server.get_address(), payload):
            message = self.secure_message.get_message_from_secure_payload(payload)
            payload = self.secure_message.create_secure_payload(self.notary_server.get_public_key_hex(), message)
            response = requests.put(challenge_url, data=payload, verify=self.ssl_verify_mode)
            if response.status_code != 200:
                raise NotaryException(response.status_code, "Error authenticating!")
            return requests.utils.dict_from_cookiejar(response.cookies)
        raise NotaryException(-1, "Error Verifying signature!")

    def register_user(self, email):
        '''
           first step in registering an user to our system.
        Parameters
        ----------
        email   : the email address of the user.

        Returns
        -------
              the http response status code.
        '''
        # prepare the input.

        payload = self.get_payload({'public_key': self.wallet.get_public_key_hex(), 'email': email})

        # send to server
        response = requests.put(self.notary_server.get_account_url(self.address), data=payload,
                                verify=self.ssl_verify_mode)
        if response.status_code != 200:
            raise NotaryException(response.status_code, "Error registering!")
        return response.status_code

    def get_file_encryption_wallet(self):
        try:
            account = self.get_account()
            file_encryption_wallet = wallet.create_wallet('MemoryWallet', account['file_encryption_key'])
            return file_encryption_wallet
        except NotaryException as e:
            raise NotaryException(e.error_code, "Error getting file encryption key!")

    def get_account(self):
        '''
        This method tells us many things:

        1. If a user has never been registered, then an exception with an error code of 404 will be raised
        2. If a user has registered but hasn't confirmed, then an exception with an error code of 403 will be raised
        3. If a user is registered and confirmed, account data will be returned. That data contains a file_encryption_key.

        Returns
        -------
              the account
        '''
        try:
            cookies = self.authenticate()
        except NotaryException as e:
            raise NotaryException(e.error_code, e.message)

        response = requests.get(self.notary_server.get_account_url(self.address),cookies=cookies,
                                verify=self.ssl_verify_mode)
        registration_status = response.status_code
        if registration_status == 200:
            payload = json.loads(response.content)
            if self.secure_message.verify_secure_payload(self.notary_server.get_address(), payload):
                message = self.secure_message.get_message_from_secure_payload(payload)
                return json.loads(message)
        raise NotaryException(registration_status, "Error Verifying signature!")

    def notarize_file(self, path_to_file, metadata):
        '''
        the main method to notarize a file.
        Parameters
        ----------
        path_to_file   : the fp to the file. ( Not file name). Need to support file name.
        metadata  : a JSON object containing metadata

        Returns
        -------
           returns the transaction hash and document hash.

        '''

        # hash the file and generate the document hashh

        try:
            cookies = self.authenticate()
        except NotaryException as e:
            raise NotaryException(e.error_code, e.message)

        document_hash = hashfile.hash_file(path_to_file)

        metadata['document_hash'] = document_hash
        # create a secure payload
        notarization_payload = self.get_payload(metadata)
        # Have to authenticate
        response = requests.put(self.notary_server.get_notarization_url(self.address, document_hash),
                                cookies=cookies, data=notarization_payload, verify=self.ssl_verify_mode)
        if response.status_code == 200:
            payload = json.loads(response.content)
            if self.secure_message.verify_secure_payload(self.notary_server.get_address(), payload):
                message = self.secure_message.get_message_from_secure_payload(payload)
                return json.loads(message)
        else:
            raise NotaryException(response.status_code, "Error notarizing!")

    def upload_file_encrypted(self, path_to_file):
        '''
        uploads a file to server encrypting along the way
        Parameters
        ----------
        path_to_file :  file full path name.

        Returns
        -------
         the http status from the server

        '''
        try:
            file_encryption_wallet = self.get_file_encryption_wallet()
            cookies = self.authenticate()
        except NotaryException as e:
            raise NotaryException(e.error_code, e.message)

        document_hash = hashfile.hash_file(path_to_file)

        try:
            file_stream_encrypt.encrypt_file(path_to_file,path_to_file+".encrypted", file_encryption_wallet.get_public_key())
            files = {'document_content': open(path_to_file+".encrypted", 'rb')}
            upload_response = requests.put(
                    self.notary_server.get_document_url(self.address, document_hash), cookies=cookies,
                    files=files, verify=False)
            return upload_response.status_code
        except requests.ConnectionError as e:
            raise NotaryException(upload_response.status_code, "Problem uploading file!")

    def upload_file(self, path_to_file):
        '''
        uploads a file to server
        Parameters
        ----------
        path_to_file : file full path name.

        Returns
        -------
         the http status from the server

        '''

        try:
            cookies = self.authenticate()
        except NotaryException as e:
            raise NotaryException(e.error_code, e.message)

        document_hash = hashfile.hash_file(path_to_file)

        try:
            files = {'document_content': open(path_to_file, 'rb')}
            upload_response = requests.put(
                    self.notary_server.get_document_url(self.address, document_hash), cookies=cookies,
                    files=files, verify=False)
            if upload_response.status_code != 200:
                raise NotaryException(upload_response.status_code, "Problem uploading file!")
            return upload_response.status_code
        except requests.ConnectionError as e:
            raise NotaryException(-1, e.message)
        except NotaryException as ne:
            raise NotaryException(ne.error_code, ne.message)

    def download_file(self, document_hash, storing_file_name):
        '''
        uploads a file to server
        Parameters
        ----------
        document_hash : hash of file.
        storing_file_name : file name to write to.

        Returns
        -------
         storing_file_name

        '''

        try:
            cookies = self.authenticate()
        except NotaryException as e:
            raise NotaryException(e.error_code, e.message)

        try:
            download_response = requests.get(self.notary_server.get_document_url(self.address, document_hash),
                                             cookies=cookies, allow_redirects=True, verify=False)
            if download_response.status_code != 200:
                raise NotaryException(download_response.status_code, "Problem downloading file!")
                # Need to add error handling
            ultimate_file_name = str(storing_file_name)
            with open(ultimate_file_name, 'wb') as f:
                for chunk in download_response.iter_content(chunk_size=1024):
                    if chunk:  # filter out keep-alive new chunks
                        f.write(chunk)
            return storing_file_name
        except requests.ConnectionError as e:
            raise NotaryException(-1, e.message)
        except NotaryException as ne:
            raise NotaryException(ne.error_code, ne.message)

    def download_file_decrypted(self, document_hash, storing_file_name):
        '''
        uploads a file to server
        Parameters
        ----------
        document_hash : hash of file.
        storing_file_name : file name to write to.

        Returns
        -------
         storing_file_name

        '''

        try:
            file_encryption_wallet = self.get_file_encryption_wallet()
            cookies = self.authenticate()
        except NotaryException as e:
            raise NotaryException(e.error_code, e.message)

        try:
            download_response = requests.get(self.notary_server.get_document_url(self.address, document_hash),
                                             cookies=cookies, allow_redirects=True, verify=False)
            if download_response.status_code != 200:
                raise NotaryException(download_response.status_code, "Problem downloading file!")
                # Need to add error handling
            ultimate_file_name = str(storing_file_name)
            with open(ultimate_file_name, 'wb') as f:
                for chunk in download_response.iter_content(chunk_size=1024):
                    if chunk:  # filter out keep-alive new chunks
                        f.write(chunk)

            file_stream_encrypt.decrypt_file(ultimate_file_name+".decrypted",  storing_file_name, file_encryption_wallet.get_private_key_wif())
            return storing_file_name
        except requests.ConnectionError as e:
            raise NotaryException(-1, e.message)
        except NotaryException as ne:
            raise NotaryException(ne.error_code, ne.message)

    def get_notarization_status(self, document_hash):
        '''
        This method returns the notary status
        Parameters
        ----------
        document_hash : the document hash value.

        Returns
        -------
             status value.
        '''
        try:
            cookies = self.authenticate()
        except NotaryException as e:
            raise NotaryException(e.error_code, e.message)

        response = requests.get(self.notary_server.get_notarization_status_url(self.address, document_hash),
                                cookies=cookies, verify=False)
        if response.status_code != 200 or response.content is None:
            raise NotaryException(response.status_code, "Error retrieving notarization status")
        else:
            payload = json.loads(response.content)
            if self.secure_message.verify_secure_payload(self.notary_server.get_address(), payload):
                message = self.secure_message.get_message_from_secure_payload(payload)
                return json.loads(message)
