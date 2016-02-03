from notary_client import NotaryClient, NotaryException

notary_client = NotaryClient('./notaryconfig.ini', 'foobar')
try:
    cookies = notary_client.authenticate()
    print(cookies)
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
