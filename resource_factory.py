import boto3
import botocore.exceptions


def get_dynamodb(config):
    if config.is_local_host():
        try:
            resource = boto3.resource('dynamodb', region_name=config.get_aws_region(), endpoint_url=config.get_local_db_url())
            return resource
        except botocore.exceptions.ClientError as e:
            print ("Problem accessing dynamodb locally  %s " % e.message)
    else:
        try:
            resource = boto3.resource('dynamodb', region_name=config.get_aws_region())
            return resource
        except botocore.exceptions.ClientError as e:
            print ("Problem accessing dynamodb remotely %s " % e.message)

