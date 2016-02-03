from notary_client import NotaryClient, NotaryException

try:
    notary_client = NotaryClient('./notaryconfig.ini', 'foobar')
    message = notary_client.get_account()
    print(message['email'])
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
