import hashfile
import requests


def getMetaData():
    meta_data= {
    'title': 'My favorite beaver',
    'creator': 'Ploughman, J.J.',
    'subject': 'TV show',
    'description': 'A show about a blake... that you hate the best...',
    'publisher': 'J.J. Ploughman',
    'contributor': 'J.J. Ploughman',
    'date': '2001-08-03T03:00:00.000000',
    'type': 'Video',
    'format': 'mpeg',
    'source': 'CBS',
    'language': 'en',
    'relation': 'Unknown',
    'coverage': 'Unknown',
    'rights': 'Unknown'
    }
    return meta_data

config_file_name="notaryconfig.ini"
email_address="jeff_ploughman@troweprice.com"
notary_file_name='/Users/tssbi08/govern8r/IP/README.txt'
# with open(notary_file_name, 'wb') as output:
#     output.write(os.urandom(64).encode("hex"))

document_hash = hashfile.hash_file(notary_file_name)
storing_file_name='/Users/tssbi08/govern8r/IP/downloadedfile.txt'

