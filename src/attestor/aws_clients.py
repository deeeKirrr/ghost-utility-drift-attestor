import boto3


def client(service: str, region: str):
    return boto3.client(service, region_name=region)
