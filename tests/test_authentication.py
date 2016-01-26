import requests
import json

from bitcoinlib.core.key import CPubKey
import wallet
from bitcoinlib.wallet import P2PKHBitcoinAddress
from message import SecureMessage
import configuration
import log_handlers

config = configuration.NotaryConfiguration('./notaryconfig.ini')

logger = log_handlers.get_logger(config)
logger.debug("-------------------------ENVIRONMENT--------------------------")
logger.debug("Am I Local: %s " % config.is_local_host())
if config.is_remote_testing():
    notary_url = config.get_remote_server_url()
else:
    notary_url = config.get_local_server_url()

requests.packages.urllib3.disable_warnings()

wallet = wallet.create_wallet(config.get_wallet_type(), config.get_key_id(),logger)
secure_message = SecureMessage(wallet)


## Test GET pubkey
pubkey_response = requests.get(notary_url+'/api/v1/pubkey', verify=False)
data = pubkey_response.json()
other_party_public_key_hex = data['public_key']
print data['public_key']
other_party_public_key_decoded = other_party_public_key_hex.decode("hex")
other_party_public_key = CPubKey(other_party_public_key_decoded)
other_party_address = P2PKHBitcoinAddress.from_pubkey(other_party_public_key)
address = str(wallet.get_bitcoin_address())

## Test GET challenge

response = requests.get(notary_url+'/api/v1/challenge/'+address, verify=False)
payload = json.loads(response.content)
if secure_message.verify_secure_payload(other_party_address, payload):
    message = secure_message.get_message_from_secure_payload(payload)
    print(message)

payload = secure_message.create_secure_payload(other_party_public_key_hex, message)
response = requests.put(notary_url+'/api/v1/challenge/'+address, data=payload, verify=False)
cookies = requests.utils.dict_from_cookiejar(response.cookies)
govern8r_token = cookies['govern8r_token']
print("Token from authentication: %s" % govern8r_token)
print("Status: %s" % response.status_code)

## Test Authentication against notarization service

# /govern8r/api/v1/account/<address>/notarization/<document_hash>

data=""

cookies = dict(govern8r_token=govern8r_token)
response = requests.get(notary_url+'/api/v1/account/'+address+'/test', cookies=cookies, data=data, verify=False)
govern8r_token = cookies['govern8r_token']
print("Token from first use: %s" % govern8r_token)

print(response.status_code)
## Test rotation
cookies = requests.utils.dict_from_cookiejar(response.cookies)
response = requests.get(notary_url+'/api/v1/account/'+address+'/test', cookies=cookies, data=data, verify=False)
print(response.status_code)
govern8r_token = cookies['govern8r_token']
print("Token from second use: %s" % govern8r_token)
