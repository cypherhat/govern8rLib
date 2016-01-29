from server_wallet import ServerWallet
from client_wallet import ClientWallet
from plain_wallet import PlainWallet


def create_wallet(wallet_type, key, logger):
    if wallet_type == 'ServerWallet':
        wallet = ServerWallet(key, logger)
    elif wallet_type == 'ClientWallet':
        wallet = ClientWallet(key)
    else:
        wallet = PlainWallet()
    wallet.instance()
    return wallet


def load_wallet(wallet_type, key, logger):
    if wallet_type == 'ServerWallet':
        wallet = ServerWallet(key, logger)
    elif wallet_type == 'ClientWallet':
        wallet = ClientWallet(key)
    else:
        wallet = PlainWallet()
    return wallet
