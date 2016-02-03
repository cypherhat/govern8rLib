import test_data
from notary_client import NotaryClient, NotaryException

try:
    notary_client = NotaryClient('./notaryconfig.ini', 'foobar')
    message = notary_client.get_notarization_status(test_data.document_hash)
    print(message)
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
