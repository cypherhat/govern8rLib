import notary
import os
import requests
import test_data
import json
import hashfile
from notary_client import NotaryException

requests.packages.urllib3.disable_warnings()

with open(test_data.notary_file_name, 'wb') as output:
    output.write(os.urandom(64).encode("hex"))

document_hash = hashfile.hash_file(test_data.notary_file_name)
login_result = False
try:
    notary.main_method(['register', '-password', 'test123', "-email", "raju_mariappan@troweprice.com"])
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
print (raw_input('Finish confirmation and click'))
try:
    login_result = notary.main_method(['login', '-password', 'test123'])
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)

if login_result:
    transaction_id = notary.main_method(
            ['notarize', '-file', test_data.notary_file_name, '-metadata', json.dumps(test_data.getMetaData()),
             '-password',
             'test123'])
    if transaction_id is not None:
        print notary.main_method(['uploadfile', '-file', test_data.notary_file_name, '-password', 'test123'])
        print transaction_id
        transaction_status = notary.main_method(
                ['notarystatus', "-document_hash", document_hash, '-password', 'test123'])
        print transaction_status

        print notary.main_method(
                ['downloadfile', "-document_hash", document_hash, '-file', test_data.storing_file_name, '-password',
                 'test123'])
else:
    print "There is not transaction id returned"


notary.main_method(['-h'])
