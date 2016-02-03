import test_data
from notary_client import Notary

notary_client = Notary('./notaryconfig.ini', 'foobar')
message = notary_client.notarize_file(test_data.notary_file_name, test_data.getMetaData())
print(message)