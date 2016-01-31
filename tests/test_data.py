import hashfile
import os
def getMetaData():
    meta_data= {
    'title': 'Stillwater Shame',
    'creator': 'Ploughman, J.J.',
    'subject': 'Rock Music',
    'description': 'A song about lying politicians',
    'publisher': 'J.J. Ploughman',
    'contributor': 'J.J. Ploughman',
    'date': '2001-08-03T03:00:00.000000',
    'type': 'Music',
    'format': 'm4a',
    'source': 'Green Beans Album',
    'language': 'en',
    'relation': 'Unknown',
    'coverage': 'Unknown',
    'rights': 'Unknown'
    }
    return meta_data

config_file_name="notaryconfig.ini"
email_address="rajumail@gmail.com"
notary_file_name='/Users/raju/govern8r/IP/README.txt'
with open(notary_file_name, 'wb') as output:
    output.write(os.urandom(64).encode("hex"))

document_hash = hashfile.hash_file(notary_file_name)
storing_file_name='/Users/raju/govern8r/IP/downloadedfile.txt'

