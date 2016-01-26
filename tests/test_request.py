import requests
import configuration

config = configuration.NotaryConfiguration('./notaryconfig.ini')
if config.is_remote_testing():
    notary_url = config.get_remote_server_url()
else:
    notary_url = config.get_local_server_url()


## Test GET pubkey
url = notary_url+'/api/v1/pubkey'
print ("URL test: %s " % url)
req_pubkey = requests.get(url)
data = req_pubkey.json()
print(data)
