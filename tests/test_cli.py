import notary
import os
import requests

requests.packages.urllib3.disable_warnings()

with open('testnotarizecontent.txt', 'wb') as output:
    output.write(os.urandom(64).encode("hex"))

login_result = notary.main_method(['login', '-password', 'test123'])
if login_result:
    transaction_id = notary.main_method(
            ['notarize', '-file', 'testnotarizecontent.txt', '-metadata', 'tests/testmetadata.txt', '-password',
             'test123'])
    if transaction_id is not None:
        print notary.main_method(['uploadfile', '-file', 'testnotarizecontent.txt', '-password', 'test123'])
        transaction_status = notary.main_method(
                ['notarystatus', "-transaction_id", transaction_id, '-password', 'test123'])
        print transaction_status
    else:
        print "There is not transaction id returned"
else:
    print "Login failed"

notary.main_method(['-h'])
