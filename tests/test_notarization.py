import test_data
from notary_client import NotaryClient, NotaryException

try:
    notary_client = NotaryClient('./notaryconfig.ini', 'foobar')
    message = notary_client.notarize_file(test_data.notary_file_name, test_data.getMetaData())
    print(message)
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
