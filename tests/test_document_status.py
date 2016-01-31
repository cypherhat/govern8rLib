import requests
import json

from bitcoinlib.core.key import CPubKey
import wallet
from bitcoinlib.wallet import P2PKHBitcoinAddress
from message import SecureMessage
import hashfile
import configuration
import test_data

config = configuration.NotaryConfiguration('./notaryconfig.ini')
if config.is_remote_testing():
    notary_url = config.get_remote_server_url()
else:
    notary_url = config.get_local_server_url()

requests.packages.urllib3.disable_warnings()

wallet = wallet.create_wallet(config.get_wallet_type(), config.get_key_id())
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

response = requests.get(notary_url+'/api/v1/challenge/' + address, verify=False)
payload = json.loads(response.content)
if secure_message.verify_secure_payload(other_party_address, payload):
    message = secure_message.get_message_from_secure_payload(payload)
    print(message)

payload = secure_message.create_secure_payload(other_party_public_key_hex, message)
response = requests.put(notary_url+'/api/v1/challenge/' + address, data=payload, verify=False)
cookies = requests.utils.dict_from_cookiejar(response.cookies)

document_hash = hashfile.hash_file(test_data.notary_file_name)

response = requests.get(notary_url+'/api/v1/account/' + address + '/document/' + document_hash + '/status', cookies=cookies, verify=False)
if response.content is not None:
    if response.status_code == 404:
        print ("Document not found!")
    elif response.status_code == 200:
        str_content = response.content
        payload = json.loads(response.content)
        if secure_message.verify_secure_payload(other_party_address, payload):
            message = secure_message.get_message_from_secure_payload(payload)
            print(message)

