import notary
import os
import requests

requests.packages.urllib3.disable_warnings()

print "deleting wallet file"
if os.path.isfile("notarywallet.data"):
     os.remove("notarywallet.data")
else:    ## Show an error ##
     print("Error: %s file not found" % "notarywallet.data")

with open('testnotarizecontent.txt', 'wb') as output:
        output.write(os.urandom(64).encode("hex"))


#Try to login withour registering.

print "Try to login without registering."
login_result = notary.mainMethod(['login', '-password', 'test123'])
print login_result


#Confirm without registering.
print "Confirm without registering"
confirm_result = notary.mainMethod(['confirm','-confirm_url', "https://127.0.0.1:5000/govern8r/api/v1/account/randomaddress/randomchallenge",'-password', 'test123'])
print confirm_result

#Notarize without registering.
print "Notarize without registering"
transaction_id = notary.mainMethod(['notarize', '-file', 'testnotarizecontent.txt','-metadata','testmetadata.txt','-password', 'test123'])
print transaction_id

# Get notarize status for a fake transid.
print "Get notarize status for a fake transid."
transaction_status=notary.mainMethod(['notarystatus', "-transaction_id","fake transaction id", '-password', 'test123'])
print transaction_status


