import file_stream_encrypt
import wallet
from bitcoinlib.core.key import CPubKey
import requests

requests.packages.urllib3.disable_warnings()

file_name = "/Users/tssbi08/Downloads/jdk-8u65-macosx-x64.dmg"
encrypted_file = "/Users/tssbi08/Downloads/encrypt_jdk-8u65-macosx-x64.dmg"
decrypted_file = "/Users/tssbi08/Downloads/decrypt-8u65-macosx-x64.dmg"

wallet = wallet.PlainWallet()
public_key = CPubKey(wallet.get_public_key_hex().decode("hex"))


file_stream_encrypt.encrypt_file(file_name,encrypted_file,public_key)
file_stream_encrypt.decrypt_file(encrypted_file,decrypted_file,wallet.get_private_key_wif())