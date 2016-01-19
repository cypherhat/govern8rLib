import wallet

keyId = 'arn:aws:kms:us-east-1:705237929316:key/b45597bc-3ea5-4f52-b3f0-7e57f2ec757e'

# wallet = wallet.create_wallet('PlainWallet', keyId)
wallet = wallet.create_wallet('ServerWallet', keyId)
# wallet = wallet.create_wallet('ClientWallet', keyId)
print("Wallet: Bitcoin Address %s " % wallet.get_bitcoin_address())
print("Wallet: Private Key WIF %s " % wallet.get_private_key_wif())
print("Wallet: Public Key Hex %s " % wallet.get_public_key_hex())
