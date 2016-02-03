import test_data
from notary_client import Notary

notary_client = Notary('./notaryconfig.ini', 'foobar')
message = notary_client.download_file(test_data.document_hash, test_data.storing_file_name)
print(message)