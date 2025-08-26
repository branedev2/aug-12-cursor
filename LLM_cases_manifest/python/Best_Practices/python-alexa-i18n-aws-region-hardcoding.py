import boto3
import os
from botocore.config import Config
import json
from aws_lambda_powertools import Logger
from aws_lambda_powertools.utilities.parameters import get_parameter
import requests
from typing import Dict, Any

# True Positive Examples (Vulnerable Code)

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_1():
    # Creating an S3 client with hardcoded region
    # ruleid: python-alexa-i18n-aws-region-hardcoding
    s3_client = boto3.client('s3', region_name='us-west-2')
    response = s3_client.list_buckets()
    return response


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_2():
    # Creating a DynamoDB resource with hardcoded region
    # ruleid: python-alexa-i18n-aws-region-hardcoding
    dynamodb = boto3.resource('dynamodb', region_name='eu-west-1')
    table = dynamodb.Table('Users')
    response = table.scan()
    return response['Items']


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_3():
    # Creating a Lambda client with hardcoded region in a config object
    config = Config(
        # ruleid: python-alexa-i18n-aws-region-hardcoding
        region_name='ap-northeast-1',
        signature_version='v4',
        retries={
            'max_attempts': 10,
            'mode': 'standard'
        }
    )
    lambda_client = boto3.client('lambda', config=config)
    return lambda_client.list_functions()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_4():
    # Creating an SQS client with hardcoded region in a dictionary
    client_config = {
        # ruleid: python-alexa-i18n-aws-region-hardcoding
        'region_name': 'us-east-1',
        'api_version': '2012-11-05'
    }
    sqs = boto3.client('sqs', **client_config)
    return sqs.list_queues()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_5():
    # Creating multiple AWS clients with the same hardcoded region
    # ruleid: python-alexa-i18n-aws-region-hardcoding
    region = 'ca-central-1'
    s3 = boto3.client('s3', region_name=region)
    dynamodb = boto3.resource('dynamodb', region_name=region)
    
    buckets = s3.list_buckets()
    tables = list(dynamodb.tables.all())
    return buckets, tables


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_6():
    # Using a hardcoded region in a session
    # ruleid: python-alexa-i18n-aws-region-hardcoding
    session = boto3.Session(region_name='sa-east-1')
    ec2 = session.client('ec2')
    return ec2.describe_instances()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_7():
    # Using hardcoded region with conditional logic
    env = os.environ.get('ENVIRONMENT', 'dev')
    
    if env == 'dev':
        # ruleid: python-alexa-i18n-aws-region-hardcoding
        region = 'us-west-2'
    else:
        # ruleid: python-alexa-i18n-aws-region-hardcoding
        region = 'us-east-1'
        
    sns = boto3.client('sns', region_name=region)
    return sns.list_topics()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_8():
    # Using hardcoded region in a function that creates AWS clients
    def get_aws_client(service):
        # ruleid: python-alexa-i18n-aws-region-hardcoding
        return boto3.client(service, region_name='eu-central-1')
    
    s3 = get_aws_client('s3')
    return s3.list_buckets()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_9():
    # Using hardcoded region with string formatting
    service = 'cloudwatch'
    # ruleid: python-alexa-i18n-aws-region-hardcoding
    region = f"us-west-{1}"
    client = boto3.client(service, region_name=region)
    return client.list_metrics()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_10():
    # Using hardcoded region with a class
    class AWSHandler:
        def __init__(self):
            # ruleid: python-alexa-i18n-aws-region-hardcoding
            self.region = 'ap-southeast-2'
            self.s3 = boto3.client('s3', region_name=self.region)
        
        def list_buckets(self):
            return self.s3.list_buckets()
    
    handler = AWSHandler()
    return handler.list_buckets()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_11():
    # Using hardcoded region with multiple services in a function
    def process_data():
        # ruleid: python-alexa-i18n-aws-region-hardcoding
        region = 'eu-west-2'
        s3 = boto3.client('s3', region_name=region)
        dynamodb = boto3.resource('dynamodb', region_name=region)
        
        buckets = s3.list_buckets()
        table = dynamodb.Table('DataTable')
        items = table.scan()
        
        return buckets, items
    
    return process_data()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_12():
    # Using hardcoded region with a try-except block
    try:
        # ruleid: python-alexa-i18n-aws-region-hardcoding
        client = boto3.client('lambda', region_name='ap-south-1')
        response = client.list_functions()
        return response
    except Exception as e:
        # Fallback to another region if the first fails
        # ruleid: python-alexa-i18n-aws-region-hardcoding
        client = boto3.client('lambda', region_name='us-east-1')
        response = client.list_functions()
        return response


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_13():
    # Using hardcoded region with a dictionary of regions
    regions = {
        'primary': 'us-east-2',
        'secondary': 'us-west-1',
        'backup': 'eu-west-1'
    }
    
    # ruleid: python-alexa-i18n-aws-region-hardcoding
    client = boto3.client('sts', region_name=regions['primary'])
    return client.get_caller_identity()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_14():
    # Using hardcoded region with AWS SDK for specific services
    # ruleid: python-alexa-i18n-aws-region-hardcoding
    ssm = boto3.client('ssm', region_name='us-west-2')
    parameter = ssm.get_parameter(Name='/app/config', WithDecryption=True)
    
    # Use the parameter to configure another service
    config = json.loads(parameter['Parameter']['Value'])
    # ruleid: python-alexa-i18n-aws-region-hardcoding
    s3 = boto3.client('s3', region_name='us-west-2')
    
    return s3.list_objects(Bucket=config['bucket_name'])


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_15():
    # Using hardcoded region with a complex configuration
    # ruleid: python-alexa-i18n-aws-region-hardcoding
    session = boto3.Session(
        region_name='eu-north-1',
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_KEY')
    )
    
    kinesis = session.client('kinesis')
    return kinesis.list_streams()


# True Negative Examples (Safe Code)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_1():
    # Using environment variable for region
    # ok: python-alexa-i18n-aws-region-hardcoding
    s3_client = boto3.client('s3', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
    response = s3_client.list_buckets()
    return response


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_2():
    # Using AWS_DEFAULT_REGION environment variable implicitly
    # ok: python-alexa-i18n-aws-region-hardcoding
    dynamodb = boto3.resource('dynamodb')  # Uses AWS_DEFAULT_REGION env var
    table = dynamodb.Table('Users')
    response = table.scan()
    return response['Items']


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_3():
    # Using a configuration parameter from SSM Parameter Store
    # ok: python-alexa-i18n-aws-region-hardcoding
    region = get_parameter('/app/aws_region', transform='json')
    lambda_client = boto3.client('lambda', region_name=region)
    return lambda_client.list_functions()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_4():
    # Using EC2 metadata to determine region
    def get_region_from_metadata():
        try:
            response = requests.get('http://169.254.169.254/latest/meta-data/placement/region', timeout=1)
            return response.text
        except:
            return os.environ.get('AWS_REGION', 'us-east-1')
    
    # ok: python-alexa-i18n-aws-region-hardcoding
    region = get_region_from_metadata()
    sqs = boto3.client('sqs', region_name=region)
    return sqs.list_queues()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_5():
    # Using a configuration file to determine region
    def get_config():
        with open('config.json', 'r') as f:
            return json.load(f)
    
    config = get_config()
    # ok: python-alexa-i18n-aws-region-hardcoding
    s3 = boto3.client('s3', region_name=config.get('aws_region'))
    dynamodb = boto3.resource('dynamodb', region_name=config.get('aws_region'))
    
    buckets = s3.list_buckets()
    tables = list(dynamodb.tables.all())
    return buckets, tables


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_6():
    # Using a session with region from environment
    # ok: python-alexa-i18n-aws-region-hardcoding
    session = boto3.Session()  # Uses AWS_DEFAULT_REGION env var
    ec2 = session.client('ec2')
    return ec2.describe_instances()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_7():
    # Using conditional logic with environment variables
    env = os.environ.get('ENVIRONMENT', 'dev')
    
    if env == 'dev':
        # ok: python-alexa-i18n-aws-region-hardcoding
        region = os.environ.get('DEV_AWS_REGION')
    else:
        # ok: python-alexa-i18n-aws-region-hardcoding
        region = os.environ.get('PROD_AWS_REGION')
        
    sns = boto3.client('sns', region_name=region)
    return sns.list_topics()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_8():
    # Using a function that creates AWS clients with dynamic region
    def get_aws_client(service):
        # ok: python-alexa-i18n-aws-region-hardcoding
        return boto3.client(service, region_name=os.environ.get('AWS_REGION'))
    
    s3 = get_aws_client('s3')
    return s3.list_buckets()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_9():
    # Using region from a parameter store
    logger = Logger()
    
    def get_region():
        try:
            # ok: python-alexa-i18n-aws-region-hardcoding
            return get_parameter('/config/aws_region')
        except Exception as e:
            logger.error(f"Failed to get region from parameter store: {e}")
            return os.environ.get('AWS_REGION', 'us-east-1')
    
    client = boto3.client('cloudwatch', region_name=get_region())
    return client.list_metrics()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_10():
    # Using dynamic region with a class
    class AWSHandler:
        def __init__(self):
            # ok: python-alexa-i18n-aws-region-hardcoding
            self.region = os.environ.get('AWS_REGION')
            self.s3 = boto3.client('s3', region_name=self.region)
        
        def list_buckets(self):
            return self.s3.list_buckets()
    
    handler = AWSHandler()
    return handler.list_buckets()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_11():
    # Using dynamic region with multiple services in a function
    def process_data():
        # ok: python-alexa-i18n-aws-region-hardcoding
        region = boto3.Session().region_name  # Uses default region from config or env
        s3 = boto3.client('s3', region_name=region)
        dynamodb = boto3.resource('dynamodb', region_name=region)
        
        buckets = s3.list_buckets()
        table = dynamodb.Table('DataTable')
        items = table.scan()
        
        return buckets, items
    
    return process_data()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_12():
    # Using dynamic region with a try-except block
    try:
        # ok: python-alexa-i18n-aws-region-hardcoding
        primary_region = os.environ.get('PRIMARY_REGION')
        client = boto3.client('lambda', region_name=primary_region)
        response = client.list_functions()
        return response
    except Exception as e:
        # Fallback to another region if the first fails
        # ok: python-alexa-i18n-aws-region-hardcoding
        fallback_region = os.environ.get('FALLBACK_REGION')
        client = boto3.client('lambda', region_name=fallback_region)
        response = client.list_functions()
        return response


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_13():
    # Using dynamic region with a dictionary of regions from configuration
    def get_regions_config():
        # This could be from a database, API, or config file
        return {
            'primary': os.environ.get('PRIMARY_REGION'),
            'secondary': os.environ.get('SECONDARY_REGION'),
            'backup': os.environ.get('BACKUP_REGION')
        }
    
    regions = get_regions_config()
    # ok: python-alexa-i18n-aws-region-hardcoding
    client = boto3.client('sts', region_name=regions['primary'])
    return client.get_caller_identity()


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_14():
    # Using dynamic region with AWS SDK for specific services
    def get_ssm_parameter(param_name):
        # ok: python-alexa-i18n-aws-region-hardcoding
        ssm = boto3.client('ssm', region_name=os.environ.get('AWS_REGION'))
        parameter = ssm.get_parameter(Name=param_name, WithDecryption=True)
        return parameter['Parameter']['Value']
    
    # Use the parameter to configure another service
    config = json.loads(get_ssm_parameter('/app/config'))
    # ok: python-alexa-i18n-aws-region-hardcoding
    s3 = boto3.client('s3', region_name=config.get('region'))
    
    return s3.list_objects(Bucket=config['bucket_name'])


# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_15():
    # Using dynamic region with a complex configuration
    def get_session_config() -> Dict[str, Any]:
        return {
            'region_name': os.environ.get('AWS_REGION'),
            'aws_access_key_id': os.environ.get('AWS_ACCESS_KEY'),
            'aws_secret_access_key': os.environ.get('AWS_SECRET_KEY')
        }
    
    # ok: python-alexa-i18n-aws-region-hardcoding
    session = boto3.Session(**get_session_config())
    kinesis = session.client('kinesis')
    return kinesis.list_streams()
# {/fact}