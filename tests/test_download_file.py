import test_data
from notary_client import NotaryClient, NotaryException

try:
    notary_client = NotaryClient('./notaryconfig.ini', 'foobar')
    message = notary_client.download_file(test_data.document_hash, test_data.storing_file_name)
    print(message)
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
