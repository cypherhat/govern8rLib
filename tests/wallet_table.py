from __future__ import print_function # Python 2/3 compatibility
import botocore
import configuration
import resource_factory

config = configuration.NotaryConfiguration('../notaryconfig.ini')

try:
    dynamodb = resource_factory.get_dynamodb(config)
    wallet_table = dynamodb.Table('Wallet')
    wallet_table.delete()
    # wallet_table = dynamodb.create_table(
    #     TableName='Wallet',
    #     KeySchema=[
    #         {
    #             'AttributeName': 'key_id',
    #             'KeyType': 'HASH'
    #         }
    #     ],
    #     AttributeDefinitions=[
    #         {
    #             'AttributeName': 'key_id',
    #             'AttributeType': 'S'
    #         }
    #     ],
    #     ProvisionedThroughput={
    #         'ReadCapacityUnits': 10,
    #         'WriteCapacityUnits': 10
    #     }
    # )
    print("Wallet Table status: %s " % wallet_table.table_status)
except botocore.exceptions.ClientError as e:
    print(e.response['Error']['Code'])
