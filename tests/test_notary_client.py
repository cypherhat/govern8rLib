from notary_client import Notary
import simplecrypt
from client_wallet import ClientWallet
import test_data

# create a wallet
notary_obj = Notary(test_data.config_file_name, "test123")

# load wallet with wrong password
try:
    notary_obj = Notary(test_data.config_file_name, "tessfsdft123")
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
print notary_obj.register_user(test_data.email_address)
#test register to server agin.
print "testing register again"
print notary_obj.register_user(test_data.email_address)

print (raw_input('Finish confirmation and click'))

#test to notarize before confirmation/registeration
print "notarizing file"
print notary_obj.notarize_file(test_data.notary_file_name,test_data.getMetaData())
#test document status.
print "notarize again to see behaviour"
print notary_obj.notarize_file(test_data.notary_file_name,test_data.getMetaData())
print "upload file"
print notary_obj.upload_file(test_data.notary_file_name)
print "notary_status"
print notary_obj.notary_status(test_data.document_hash)
print "download file"
print notary_obj.download_file(test_data.document_hash,test_data.storing_file_name)





