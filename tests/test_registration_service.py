import test_data
from notary_client import NotaryClient, NotaryException

try:
    notary_client = NotaryClient('./notaryconfig.ini', 'foobar')
    message = notary_client.register_user(test_data.email_address)
    print(message)
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
