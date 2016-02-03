from notary_client import Notary

notary_client = Notary('./notaryconfig.ini', 'foobar')
cookies = notary_client.authenticate()
print(cookies)