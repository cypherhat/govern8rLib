import encrypt
import wallet
from base58 import base58_check_encode
import os
from bitcoinlib.wallet import CBitcoinSecret, P2PKHBitcoinAddress
import requests
requests.packages.urllib3.disable_warnings()

def privateKeyToWif(key_hex):
    return base58_check_encode(0x80, key_hex.decode('hex'))

wallet = wallet.create_wallet(config.get_wallet_type(), config.get_key_id())

print("\nWallet Private Key %s" % wallet.get_private_key())
print("\nWallet Public Key %s" % wallet.get_public_key())
print("\nWallet Public Key Hex %s" % wallet.get_public_key_hex())
print("\nWallet Private Key WIF %s" % wallet.get_private_key_wif())
str = wallet.get_bitcoin_address()
print("\nWallet Address %s" % wallet.get_bitcoin_address())

pubkeyhex = wallet.get_public_key_hex()
pubkey = wallet.get_public_key()

addrfrom = P2PKHBitcoinAddress.from_pubkey(pubkey)
addrfromhex = P2PKHBitcoinAddress.from_pubkey(pubkeyhex.decode("hex"))
print("\nAddress From %s" % addrfrom)
print("\nAddress From Hex %s" % addrfromhex)

message = "bitid://localhost:5000/callback?x=30f56bc022dde976&u=1"

print("\nClear: %s" % message)
encrypted = encrypt.encrypt(wallet.get_public_key(), message)
print("\nEncrypted: %s" % encrypted)

decrypted = encrypt.decrypt(wallet.get_private_key_wif(), encrypted)
print("\nDecrypted: %s" % decrypted)

signature = wallet.sign(message)

print("\nSignature: %s" % signature)
print("\nVerified: %s" % wallet.verify(message, signature))

test1_raw_hex = '3e52050b58e1765ca9abfce576aa0efc27eaa4dd11a4051affabd050e6b92324'
test1_private_key_wif = privateKeyToWif(test1_raw_hex)
test1_key = CBitcoinSecret(test1_private_key_wif)
test1_pub = test1_key.pub

test2_private_key_wif = wallet.get_private_key_wif()
test2_key = wallet.get_private_key()
test2_pub = test2_key.pub

message = "foobar"
print("\nClear: %s" % message)
encrypted = encrypt.encrypt(test1_pub, message)
print("\nEncrypted1: %s" % encrypted)

decrypted = encrypt.decrypt(test1_private_key_wif, encrypted)
print("\nDecrypted1: %s" % decrypted)
