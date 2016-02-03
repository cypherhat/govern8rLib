import test_data
from notary_client import Notary

notary_client = Notary('./notaryconfig.ini', 'foobar')
message = notary_client.notary_status(test_data.document_hash)
print(message)
