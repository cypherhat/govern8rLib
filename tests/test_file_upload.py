import test_data
from notary_client import Notary

notary_client = Notary('./notaryconfig.ini', 'foobar')
message = notary_client.upload_file(test_data.notary_file_name)
print(message)