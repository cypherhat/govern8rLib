import wallet
import configuration
import log_handlers


config = configuration.NotaryConfiguration('./notaryconfig.ini')
logger = log_handlers.get_logger(config)


# wallet = wallet.create_wallet('PlainWallet', keyId, logger=None)
wallet = wallet.create_wallet('ServerWallet', config, logger)
# wallet = wallet.create_wallet('ClientWallet', keyId, logger=None)
print("Wallet: Bitcoin Address %s " % wallet.get_bitcoin_address())
print("Wallet: Private Key WIF %s " % wallet.get_private_key_wif())
print("Wallet: Public Key Hex %s " % wallet.get_public_key_hex())
