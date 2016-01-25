import requests
import configuration

config = configuration.NotaryConfiguration('./notaryconfig.ini')
if config.is_remote_testing():
    notary_url = config.get_remote_server_url()
else:
    notary_url = config.get_local_server_url()

requests.packages.urllib3.disable_warnings()
response = requests.get(notary_url+'/api/v1/account/19sbnNShA5mQML6Xyia5HBrDEYycv7yTVa/b9ec8a84b7481e4e', verify=False)
print(response.status_code)