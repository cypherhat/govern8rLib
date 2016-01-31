from hashlib import md5
from Crypto.Cipher import AES
from Crypto import Random
import uuid
import bitcoin_asymmetric_encrypt

def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = ''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt_file(in_file_name, out_file_name, public_key, key_length=32):
    password = str(uuid.uuid4())
    print password
    encrypted_password = bitcoin_asymmetric_encrypt.encrypt(public_key,password)
    print encrypted_password
    with open(in_file_name, 'rb') as in_file, open(out_file_name, 'wb') as out_file:
        encrypt(in_file, out_file, password,encrypted_password)

def encrypt(in_file, out_file, password, encrypted_password, key_length=32):
    bs = AES.block_size
    salt = Random.new().read(bs - len('Salted__'))
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    out_file.write('Salted__' + salt)
    epass_length = str(len(encrypted_password))
    print epass_length
    out_file.write('Length__'+epass_length)
    out_file.write('Key__'+encrypted_password)
    finished = False
    while not finished:
        chunk = in_file.read(1024 * bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += padding_length * chr(padding_length)
            finished = True
        out_file.write(cipher.encrypt(chunk))


def decrypt_file(in_file_name, out_file_name, private_key, key_length=32):
    with open(in_file_name, 'rb') as in_file, open(out_file_name, 'wb') as out_file:
        decrypt(in_file, out_file, private_key)


def decrypt(in_file, out_file, private_key, key_length=32):
    bs = AES.block_size
    salt = in_file.read(bs)[len('Salted__'):]
    pass_key_length = int(in_file.read(11)[len('Length__'):])
    print pass_key_length
    encrypted_password = in_file.read(5+pass_key_length)[len('Key__'):]
    print encrypted_password
    password = bitcoin_asymmetric_encrypt.decrypt(private_key,encrypted_password)
    print password

    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = ord(chunk[-1])
            chunk = chunk[:-padding_length]
            finished = True
        out_file.write(chunk)




def test_encryption():
    zipfilename = "/Users/raju/Downloads/jdk-8u65-macosx-x64.dmg"
    newzipfilename = "/Users/raju/Downloads/newjdk-8u65-macosx-x64.dmg"
    outfilename = "/Users/raju/Downloads/encrypt-8u65-macosx-x64.dmg"
    with open(zipfilename, 'rb') as in_file, open(outfilename, 'wb') as out_file:
        encrypt(in_file, out_file, "TestStreamEncrypt")

    with open(outfilename, 'rb') as in_file, open(newzipfilename, 'wb') as out_file:
        decrypt(in_file, out_file, "TestStreamEncrypt")