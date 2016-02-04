from notary_client import NotaryClient,NotaryException
import simplecrypt
from client_wallet import ClientWallet
import test_data

# create a wallet
notary_obj = NotaryClient(test_data.config_file_name, "test123")

#try to authenticate without anything.
print "try to authenticate without anything"
try:
    print notary_obj.authenticate()
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
# load wallet with wrong password


try:
    notary_obj = NotaryClient(test_data.config_file_name, "tessfsdft123")
except simplecrypt.DecryptionException as e:
    print e.message
# test wallet exists are not.
client_wallet_obj = ClientWallet("somepassword")
print "wallet exists"
print client_wallet_obj.wallet_exists()
#test wallet is registered or not.
#test wallet is confirmed or not.
#test register to server.
print "registering wallet"
try:
    print notary_obj.register_user(test_data.email_address)
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
print "try authentication without confirmation"
try:
    print notary_obj.authenticate()
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
print "getting register status"
try:
   print notary_obj.get_account()
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)

#test register to server agin.
print "testing register again"
try:
    print notary_obj.register_user(test_data.email_address)
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
print "getting register status"
try:
    print notary_obj.get_account()
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)

print (raw_input('Finish confirmation and click'))
print "getting register status"
try:
    print notary_obj.get_account()
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
#test to notarize before confirmation/registeration
print "notarizing file"
try:
    print notary_obj.notarize_file(test_data.notary_file_name,test_data.getMetaData())
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
#test document status.
print "notarize again to see behaviour"
try:
    print notary_obj.notarize_file(test_data.notary_file_name,test_data.getMetaData())
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
print "upload file"
try:
    print notary_obj.upload_file(test_data.notary_file_name)
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
print "notary_status"
try:
    print notary_obj.get_notarization_status(test_data.document_hash)
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)
print "download file"
try:
    print notary_obj.download_file(test_data.document_hash,test_data.storing_file_name)
except NotaryException as e:
    print("Code %s " % e.error_code)
    print(e.message)





