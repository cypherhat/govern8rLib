import blockchain
from blockcypher import get_transaction_details
import requests
requests.packages.urllib3.disable_warnings()

#transcation_id=blockchain.embed("6cbe5d6c75bcabcd","e9eff5e2e97724ced567742d851b1053","btc-testnet")
#transcation_id='02571d93e64340af193658b5b2b44cda7cc8660cac5dbb746d1d2765eca9f915'
transcation_id='c640f0454cb1926ee82bf214ebe47f4bc12a197ed7104ef27c548aa7efb1224c'
status_value=get_transaction_details(transcation_id,coin_symbol="btc-testnet")
print status_value['confirmed']