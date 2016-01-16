from wallet import ServerWallet

keyId = 'arn:aws:kms:us-east-1:705237929316:key/b45597bc-3ea5-4f52-b3f0-7e57f2ec757e'

#server_wallet = ServerWallet(keyId)
#print("Wallet: Bitcoin Address %s " % server_wallet.get_bitcoin_address())
#print("Wallet: Private Key WIF %s " % server_wallet.get_private_key_wif())
#print("Wallet: Public Key Hex %s " % server_wallet.get_public_key_hex())

client_wallet = ServerWallet(keyId)
print("Wallet: Bitcoin Address %s " % client_wallet.get_bitcoin_address())
print("Wallet: Private Key WIF %s " % client_wallet.get_private_key_wif())
print("Wallet: Public Key Hex %s " % client_wallet.get_public_key_hex())
