import requests
import json
import hashfile
import wallet
from message import SecureMessage
from bitcoinlib.core.key import CPubKey
from bitcoinlib.wallet import P2PKHBitcoinAddress
from configuration import NotaryConfiguration
import log_handlers


class Notary(object):
    def __init__(self, config_file):
        '''
           constructs needed objects
        Parameters
        ----------
        password  : takes the password of the wallet

        Returns
        -------

        '''

        self.config = NotaryConfiguration(config_file)
        self.ssl_verify_mode = self.config.get_ssl_verify_mode()
        logger = log_handlers.get_logger(self.config)
        logger.debug("-------------------------ENVIRONMENT--------------------------")
        logger.debug("Am I Local: %s " % self.config.is_local_host())

        requests.packages.urllib3.disable_warnings()
        self.notary_url = self.config.get_server_url()
        self.wallet = None

        self.secure_message = SecureMessage(self.wallet)
        response = requests.get(self.notary_url + '/api/v1/pubkey', verify=self.ssl_verify_mode)
        data = response.json()
        self.other_party_public_key_hex = data['public_key']
        other_party_public_key_decoded = self.other_party_public_key_hex.decode("hex")
        self.other_party_public_key = CPubKey(other_party_public_key_decoded)
        self.other_party_address = P2PKHBitcoinAddress.from_pubkey(self.other_party_public_key)
        self.govenr8r_token = 'UNAUTHENTICATED'
        self.cookies = None

    def check_wallet(self):
        '''
            It is a PRIVATE method to make sure wallet is there and loaded into the notary object already to do the things you want to do.
        :return:
        '''
        if wallet is None:
            self.logger.exception("Calling API without loading wallet.")
            raise ValueError('Client Wallet does not exist!')

    def create_wallet(self, password):
        '''
           Basically this method creates a wallet file locally on your disk.
        :param password:
        :return:
        '''
        self.wallet = wallet.create_wallet(self.config.get_wallet_type(), password, self.logger)

    def load_wallet(self, password):
        '''
         loading wallet should be done before using any of the API calls. if you do , it will raise exception.
        :param password:
        :return:
        '''
        self.wallet = wallet.load_wallet(self.config.get_wallet_type(), password, self.logger)

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
        # make sure wallet object is there.
        self.check_wallet()

        address = str(self.wallet.get_bitcoin_address())
        message = {'public_key': self.wallet.get_public_key_hex(), 'email': email}
        str_message = json.dumps(message)
        payload = self.secure_message.create_secure_payload(self.other_party_public_key_hex, str_message)

        # send to server
        response = requests.put(self.notary_url + '/api/v1/account/' + address, data=payload,
                                verify=self.ssl_verify_mode)

        # process the response
        if response.status_code != 200:
            return None
        print response.content
        payload = response.content
        print payload
        return response.status_code

    def rotate_the_cookie(self, response):
        '''
           utility to rotate the cookie.
           It is a PRIVATE method. don't use it as a API call.
        Parameters
        ----------
        response

        Returns
        -------

        '''
        if response.cookies is None:
            self.cookies = None
            self.govenr8r_token = 'UNAUTHENTICATED'
            return

        self.cookies = requests.utils.dict_from_cookiejar(response.cookies)
        if self.cookies is not None:
            self.govenr8r_token = 'UNAUTHENTICATED'
            return

        if 'govern8r_token' in self.cookies:
            self.govenr8r_token = self.cookies['govern8r_token']
        else:
            self.govenr8r_token = 'UNAUTHENTICATED'

    def login(self):
        '''
           the login procedure. I don't takes any parameters. it assumes the wallet was already
           created and  opened during the Notary object construction.
           The login procedure uses the private key to sign the challenge sent by the server.

        Returns
        -------
             basically true or false.

        '''
        # make sure wallet object is there.
        self.check_wallet()
        # call the server to get the challenge URL.
        self.govenr8r_token = 'UNAUTHENTICATED'
        address = str(self.wallet.get_bitcoin_address())
        response = requests.get(self.notary_url + '/api/v1/challenge/' + address, verify=self.ssl_verify_mode)

        # process the response
        if response.status_code != 200:
            return False
        payload = json.loads(response.content)
        if self.secure_message.verify_secure_payload(self.other_party_address, payload):
            message = self.secure_message.get_message_from_secure_payload(payload)
            # create another payload with the signed challenge message.
            payload = self.secure_message.create_secure_payload(self.other_party_public_key_hex, message)

            # call the server with secure payload
            response = requests.put(self.notary_url + '/api/v1/challenge/' + address, data=payload,
                                    verify=self.ssl_verify_mode)

            # process the response.
            if response.status_code != 200:
                return False
            self.rotate_the_cookie(response)
            return True
        else:
            self.govenr8r_token = 'UNAUTHENTICATED'
            return False

    def logout(self):
        '''
         basically it clears the cookie stored locally in memory.
        Returns
        -------

        '''

        self.govenr8r_token = 'UNAUTHENTICATED'
        self.cookies = None

    def confirm_registration(self, confirmation_url):
        '''
           Confirmation of the account is generally done out of band using email,etc.
            This code basically takes the url and call the server url as it is to confirm the account.
        Parameters
        ----------
        confirmation_url

        Returns
        -------

        '''
        # make sure wallet object is there.
        self.check_wallet()
        response = requests.get(confirmation_url, verify=self.ssl_verify_mode)
        return response.status_code

    def authenticated(self):
        '''
          basically checks for the token and if it is there it assumes the use login is done.
        Returns
        -------
             True or False.
        '''
        return self.govenr8r_token != 'UNAUTHENTICATED'

    def notarize_file(self, path_to_file, metadata_file):
        '''
        the main method to notarize a file.
        Parameters
        ----------
        path_to_file   : the fp to the file. ( Not file name). Need to support file name.
        metadata_file  : the fp to the file. ( Not file name). Need to support file name.

        Returns
        -------
           returns the transaction hash and document hash.

        '''
        # make sure wallet object is there.
        self.check_wallet()
        address = str(self.wallet.get_bitcoin_address())
        meta_data = json.loads(metadata_file.read())

        # hash the file and generate the document hash
        document_hash = hashfile.hash_file_fp(path_to_file)
        meta_data['document_hash'] = document_hash
        print json.dumps(meta_data)
        # create a secure payload
        notarization_payload = self.secure_message.create_secure_payload(self.other_party_public_key_hex,
                                                                         json.dumps(meta_data))

        # make the rest call.
        response = requests.put(self.notary_url + '/api/v1/account/' + address + '/notarization/' + document_hash,
                                cookies=self.cookies, data=notarization_payload, verify=self.ssl_verify_mode)

        # process the response
        if response.status_code != 200:
            return None
        # store the rotated cookie.
        self.rotate_the_cookie(response)

        # process the returned payload
        payload = json.loads(response.content)
        print "payload"
        print payload
        if self.secure_message.verify_secure_payload(self.other_party_address, payload):
            message = self.secure_message.get_message_from_secure_payload(payload)
            print message
            message = json.loads(message)
            return message

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
        # make sure wallet object is there.
        self.check_wallet()
        address = str(self.wallet.get_bitcoin_address())
        files = {'files': path_to_file}
        print repr(path_to_file.name)
        print repr(self.notary_url + '/api/v1/upload/' + address + '/name/' + path_to_file.name)

        # call the server
        response = requests.post(self.notary_url + '/api/v1/upload/' + address + '/name/' + path_to_file.name,
                                 cookies=self.cookies, files=files, verify=self.ssl_verify_mode)

        self.rotate_the_cookie(response)
        # process the response
        if response.status_code != 200:
            return None
        # cookies = requests.utils.dict_from_cookiejar(response.cookies)
        # self.govenr8r_token = cookies['govern8r_token']
        print response.status_code
        return response.status_code

    def download_file(self, document_hash, storing_file_name):
        self.check_wallet()
        address = str(self.wallet.get_bitcoin_address())
        response = requests.get(
            self.notary_url + '/api/v1/account/' + address + '/document/' + document_hash + '/status',
            cookies=self.cookies, verify=False)
        self.rotate_the_cookie(response)
        if response.content is not None:
            if response.status_code == 404:
                print ("Document not found!")
            elif response.status_code == 200:
                try:
                    files = {'document_content': open(storing_file_name, 'rb')}
                    r = requests.put(self.notary_url + '/api/v1/account/' + address + '/document/' + document_hash,
                                     cookies=self.cookies, files=files, verify=False)
                    print r.status_code
                except requests.ConnectionError as e:
                    print(e.message)

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
        # make sure wallet object is there.
        self.check_wallet()
        address = str(self.wallet.get_bitcoin_address())
        response = requests.get(
                self.notary_url + '/api/v1/account/' + address + '/notarization/' + document_hash + '/status',
                cookies=self.cookies, verify=self.ssl_verify_mode)

        self.rotate_the_cookie(response)
        if response.status_code != 200:
            print ('No notarization!')
            return None
        elif response.content is not None:
            payload = json.loads(response.content)
            if self.secure_message.verify_secure_payload(self.other_party_address, payload):
                message = self.secure_message.get_message_from_secure_payload(payload)
                print(message)
                return message
