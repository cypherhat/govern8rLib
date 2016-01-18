from server_wallet import ServerWallet
from client_wallet import ClientWallet
from plain_wallet import PlainWallet


def create_wallet(wallet_type, key):
    if wallet_type == 'ServerWallet':
        return ServerWallet(key)
    elif wallet_type == 'ClientWallet':
        return ClientWallet(key)
    else:
        return PlainWallet()
