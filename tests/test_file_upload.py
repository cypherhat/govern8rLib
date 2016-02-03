import test_data
from notary_client import NotaryClient, NotaryException

try:
    notary_client = NotaryClient('./notaryconfig.ini', 'foobar')
    message = notary_client.upload_file(test_data.notary_file_name)
    print(message)
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
