import requests
import json
import hashfile
import wallet
from message import SecureMessage
from bitcoinlib.core.key import CPubKey
from bitcoinlib.wallet import P2PKHBitcoinAddress
from configuration import NotaryConfiguration
import log_handlers


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


class Notary(object):
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

    def get_payload(self, message):
        str_message = json.dumps(message)
        return self.secure_message.create_secure_payload(self.notary_server.get_public_key_hex(), str_message)

    def authenticate(self):
        challenge_url = self.notary_server.get_challenge_url(self.address)
        response = requests.get(challenge_url, verify=self.ssl_verify_mode)
        if response.status_code != 200:
            return None
        payload = json.loads(response.content)
        if self.secure_message.verify_secure_payload(self.notary_server.get_address(), payload):
            message = self.secure_message.get_message_from_secure_payload(payload)
            payload = self.secure_message.create_secure_payload(self.notary_server.get_public_key_hex(), message)
            response = requests.put(challenge_url, data=payload, verify=self.ssl_verify_mode)
            if response.status_code != 200:
                return None
            return requests.utils.dict_from_cookiejar(response.cookies)

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

        return response.status_code

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

        # hash the file and generate the document hash
        document_hash = hashfile.hash_file_fp(path_to_file)
        metadata['document_hash'] = document_hash
        # create a secure payload
        notarization_payload = self.get_payload(metadata)
        # Have to authenticate
        cookies = self.authenticate()
        if cookies is not None:
            response = requests.put(self.notary_server.get_notarization_url(self.address, document_hash),
                                cookies=cookies, data=notarization_payload, verify=self.ssl_verify_mode)
            if response.status_code == 200:
                payload = json.loads(response.content)
                if self.secure_message.verify_secure_payload(self.notary_server.get_address(), payload):
                    message = self.secure_message.get_message_from_secure_payload(payload)
                    return json.loads(message)

        return None

    def upload_file(self, path_to_file):
        '''
        uploads a file to server
        Parameters
        ----------
        path_to_file : give a file pointer,i.e. file pointer. Need change code support file full path name.

        Returns
        -------
         the http status from the server

        '''
        document_hash = hashfile.hash_file(path_to_file)
        cookies = self.authenticate()
        if cookies is not None:
            check_notarized = requests.get(self.notary_server.get_notarization_status_url(self.address, document_hash), cookies=cookies, verify=False)
            if check_notarized is not None:
                if check_notarized.status_code == 404:
                    return None
                elif check_notarized.status_code == 200:
                    try:
                        cookies = requests.utils.dict_from_cookiejar(check_notarized.cookies)
                        files = {'document_content': open(path_to_file, 'rb')}
                        upload_response = requests.put(self.notary_server.get_notarization_url(self.address, document_hash), cookies=cookies, files=files, verify=False)
                        return upload_response.status_code
                    except requests.ConnectionError as e:
                        print (e.message)
        return None

    def download_file(self, document_hash, storing_file_name):
        cookies = self.authenticate()
        if cookies is not None:
            download_response = requests.get(self.notary_server.get_notarization_url(self.address, document_hash), cookies=cookies, allow_redirects=True, verify=False)
            if download_response.status_code == 200:
                # Need to add error handling
                with open(storing_file_name, 'wb') as f:
                    for chunk in download_response.iter_content(chunk_size=1024):
                        if chunk:  # filter out keep-alive new chunks
                            f.write(chunk)
                return storing_file_name
        return None

    def notary_status(self, document_hash):
        '''
        This method returns the notary status
        Parameters
        ----------
        document_hash : the document hash value.

        Returns
        -------
             status value.
        '''
        cookies = self.authenticate()
        if cookies is not None:
            response = requests.get(self.notary_server.get_notarization_status_url(self.address, document_hash), cookies=cookies, verify=False)
            if response.status_code == 404:
                print ('No notarization!')
            elif response.content is not None:
                payload = json.loads(response.content)
                if self.secure_message.verify_secure_payload(self.notary_server.get_address(), payload):
                    message = self.secure_message.get_message_from_secure_payload(payload)
                    return message
        return None

