from notary_client import NotaryClient, NotaryException

try:
    notary_client = NotaryClient('./notaryconfig.ini', 'foobar')
    message = notary_client.get_notarizations()
    if len(message) > 0:
        for notarization in message:
            print(notarization)
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
