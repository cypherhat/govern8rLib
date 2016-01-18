import boto3


def get_dynamodb(config):
    if config.is_local_host():
        return boto3.resource('dynamodb', region_name=config.get_aws_region(), endpoint_url=config.get_local_db_url())
    else:
        boto3.resource('dynamodb', region_name=config.get_aws_region())
