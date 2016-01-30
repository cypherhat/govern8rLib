import requests
import json
import wallet
from bitcoinlib.wallet import P2PKHBitcoinAddress
from message import SecureMessage
import configuration
import log_handlers

config = configuration.NotaryConfiguration('./notaryconfig.ini')
if config.is_remote_testing():
    notary_url = config.get_remote_server_url()
else:
    notary_url = config.get_local_server_url()


requests.packages.urllib3.disable_warnings()

logger = log_handlers.get_logger(config)
logger.debug("-------------------------ENVIRONMENT--------------------------")
logger.debug("Am I Local: %s " % config.is_local_host())

wallet = wallet.create_wallet(config.get_wallet_type(), config.get_key_id(), logger)
secure_message = SecureMessage(wallet)

## Test GET pubkey
req_pubkey = requests.get(notary_url+'/api/v1/pubkey', verify=config.get_ssl_verify_mode())
data = req_pubkey.json()
other_party_public_key = data['public_key']
print data['public_key']
address = str(wallet.get_bitcoin_address())

## Test POST account

print("\nWallet Public Key Hex %s" % wallet.get_public_key_hex())
print("\nWallet Public Key %s" % wallet.get_public_key())
addrfromhex = P2PKHBitcoinAddress.from_pubkey(wallet.get_public_key_hex().decode("hex"))
print("\nAddress From Hex %s" % addrfromhex)
email = 'jeff_ploughman@troweprice.com'

registration_message = {'public_key': wallet.get_public_key_hex(), 'email': email}

registration_payload = secure_message.create_secure_payload(other_party_public_key, json.dumps(registration_message))
response = requests.put(notary_url+'/api/v1/account/' + address, data=registration_payload, verify=config.get_ssl_verify_mode())
print(response.status_code)
