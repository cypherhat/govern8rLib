import requests
import wallet
import configuration

config = configuration.NotaryConfiguration('./notaryconfig.ini')
if config.is_remote_testing():
    notary_url = config.get_remote_server_url()
else:
    notary_url = config.get_local_server_url()

wallet = wallet.create_wallet(config.get_wallet_type(), config.get_key_id())
requests.packages.urllib3.disable_warnings()

print ("Testing against %s" % notary_url)
## Test GET pubkey
req_pubkey = requests.get(notary_url+'/api/v1/pubkey', verify=config.get_ssl_verify_mode())
data = req_pubkey.json()
other_party_public_key = data['public_key']
print data['public_key']