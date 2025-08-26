# Test cases for py-deprecated-get-configuration rule
import boto3
import os
import json
from botocore.config import Config
from aws_appconfig_agent import AppConfigAgent

# True Positive Cases (Vulnerable/Insecure Code)

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_1():
    """Using the deprecated GetConfiguration API directly with boto3 client"""
    appconfig_client = boto3.client('appconfig')
    
    # ruleid: py-deprecated-get-configuration
    response = appconfig_client.get_configuration(
        Application='MyApp',
        Environment='Production',
        Configuration='MyConfig',
        ClientId='MyClientId'
    )
    
    config_data = json.loads(response['Content'].read().decode('utf-8'))
    return config_data

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_2():
    """Using the deprecated GetConfiguration API with error handling"""
    try:
        client = boto3.client('appconfig')
        # ruleid: py-deprecated-get-configuration
        result = client.get_configuration(
            Application='MyApplication',
            Environment='Development',
            Configuration='FeatureFlags',
            ClientId='client-123'
        )
        return result['Content'].read()
    except Exception as e:
        print(f"Error retrieving configuration: {e}")
        return None

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_3():
    """Using the deprecated GetConfiguration API with configuration version"""
    appconfig = boto3.client('appconfig', region_name='us-west-2')
    
    # ruleid: py-deprecated-get-configuration
    config = appconfig.get_configuration(
        Application='ServiceApp',
        Environment='Staging',
        Configuration='DatabaseSettings',
        ClientId='service-backend',
        ClientConfigurationVersion='1.0.0'
    )
    
    return json.loads(config['Content'].read().decode('utf-8'))

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_4():
    """Using the deprecated GetConfiguration API in a function that processes configurations"""
    def process_app_config():
        client = boto3.client('appconfig')
        app_id = 'app123'
        env_id = 'env456'
        config_id = 'conf789'
        
        # ruleid: py-deprecated-get-configuration
        response = client.get_configuration(
            Application=app_id,
            Environment=env_id,
            Configuration=config_id,
            ClientId='processor-service'
        )
        
        return json.loads(response['Content'].read().decode())
    
    return process_app_config()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_5():
    """Using the deprecated GetConfiguration API with custom retry configuration"""
    retry_config = Config(
        retries={
            'max_attempts': 5,
            'mode': 'standard'
        }
    )
    
    client = boto3.client('appconfig', config=retry_config)
    
    # ruleid: py-deprecated-get-configuration
    result = client.get_configuration(
        Application='PaymentService',
        Environment='Production',
        Configuration='PaymentGateways',
        ClientId='payment-processor'
    )
    
    return result['Content']

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_6():
    """Using the deprecated GetConfiguration API with variables for parameters"""
    app_name = 'UserService'
    env_name = 'Production'
    config_name = 'UserPreferences'
    client_id = 'user-service-' + str(os.getpid())
    
    appconfig = boto3.client('appconfig')
    
    # ruleid: py-deprecated-get-configuration
    response = appconfig.get_configuration(
        Application=app_name,
        Environment=env_name,
        Configuration=config_name,
        ClientId=client_id
    )
    
    return response

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_7():
    """Using the deprecated GetConfiguration API in a class method"""
    class ConfigManager:
        def __init__(self):
            self.client = boto3.client('appconfig')
            self.app = 'MyApp'
            self.env = 'Test'
            
        def get_app_config(self, config_name):
            # ruleid: py-deprecated-get-configuration
            response = self.client.get_configuration(
                Application=self.app,
                Environment=self.env,
                Configuration=config_name,
                ClientId='config-manager'
            )
            return response['Content']
    
    manager = ConfigManager()
    return manager.get_app_config('ApiSettings')

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_8():
    """Using the deprecated GetConfiguration API with session"""
    session = boto3.Session(region_name='us-east-1')
    client = session.client('appconfig')
    
    # ruleid: py-deprecated-get-configuration
    config_response = client.get_configuration(
        Application='NotificationService',
        Environment='Production',
        Configuration='EmailTemplates',
        ClientId='notification-service'
    )
    
    return config_response

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_9():
    """Using the deprecated GetConfiguration API with conditional logic"""
    client = boto3.client('appconfig')
    app_id = 'LoggingService'
    env_id = 'Production'
    
    if os.environ.get('DEBUG_MODE') == 'true':
        config_id = 'DebugConfig'
    else:
        config_id = 'ReleaseConfig'
    
    # ruleid: py-deprecated-get-configuration
    result = client.get_configuration(
        Application=app_id,
        Environment=env_id,
        Configuration=config_id,
        ClientId='logging-service'
    )
    
    return json.loads(result['Content'].read().decode('utf-8'))

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_10():
    """Using the deprecated GetConfiguration API in a loop for multiple configs"""
    client = boto3.client('appconfig')
    app = 'MultiConfigApp'
    env = 'Staging'
    configs = ['Config1', 'Config2', 'Config3']
    results = {}
    
    for config in configs:
        # ruleid: py-deprecated-get-configuration
        response = client.get_configuration(
            Application=app,
            Environment=env,
            Configuration=config,
            ClientId='multi-config-fetcher'
        )
        results[config] = json.loads(response['Content'].read().decode())
    
    return results

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_11():
    """Using the deprecated GetConfiguration API with async wrapper"""
    import asyncio
    
    async def fetch_config():
        client = boto3.client('appconfig')
        
        # ruleid: py-deprecated-get-configuration
        response = client.get_configuration(
            Application='AsyncApp',
            Environment='Production',
            Configuration='AsyncConfig',
            ClientId='async-client'
        )
        
        return json.loads(response['Content'].read().decode())
    
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(fetch_config())

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_12():
    """Using the deprecated GetConfiguration API with custom client configuration"""
    client = boto3.client(
        'appconfig',
        region_name='eu-west-1',
        endpoint_url='https://appconfig.eu-west-1.amazonaws.com'
    )
    
    # ruleid: py-deprecated-get-configuration
    config = client.get_configuration(
        Application='EuropeanService',
        Environment='Production',
        Configuration='RegionalSettings',
        ClientId='eu-service-client'
    )
    
    return config

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_13():
    """Using the deprecated GetConfiguration API with error handling and fallback"""
    client = boto3.client('appconfig')
    
    try:
        # ruleid: py-deprecated-get-configuration
        response = client.get_configuration(
            Application='CriticalService',
            Environment='Production',
            Configuration='OperationalSettings',
            ClientId='critical-service'
        )
        return json.loads(response['Content'].read().decode())
    except Exception:
        # Fallback to default configuration
        return {"default": "settings"}

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_14():
    """Using the deprecated GetConfiguration API with custom boto3 session"""
    session = boto3.Session(
        profile_name='development',
        region_name='us-west-2'
    )
    client = session.client('appconfig')
    
    # ruleid: py-deprecated-get-configuration
    result = client.get_configuration(
        Application='DevApp',
        Environment='Development',
        Configuration='LocalSettings',
        ClientId='dev-environment'
    )
    
    return result

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_15():
    """Using the deprecated GetConfiguration API with dynamic client ID generation"""
    import uuid
    
    client = boto3.client('appconfig')
    client_id = f"dynamic-client-{uuid.uuid4()}"
    
    # ruleid: py-deprecated-get-configuration
    config_data = client.get_configuration(
        Application='DynamicService',
        Environment='Production',
        Configuration='RuntimeConfig',
        ClientId=client_id
    )
    
    return config_data

# True Negative Cases (Safe/Secure Code)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_1():
    """Using the recommended AWS AppConfig Agent and GetLatestConfiguration API"""
    # ok: py-deprecated-get-configuration
    agent = AppConfigAgent()
    config_data = agent.get_latest_configuration()
    
    if config_data:
        return json.loads(config_data.decode('utf-8'))
    return {}

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_2():
    """Using the AWS AppConfig Agent with proper initialization and retrieval"""
    # ok: py-deprecated-get-configuration
    agent = AppConfigAgent(
        app_id='MyApp',
        env_id='Production',
        config_id='MyConfig'
    )
    
    config = agent.get_latest_configuration()
    return json.loads(config.decode('utf-8')) if config else {}

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_3():
    """Using AWS AppConfig Agent with error handling"""
    try:
        # ok: py-deprecated-get-configuration
        agent = AppConfigAgent(
            app_id='MyApplication',
            env_id='Development',
            config_id='FeatureFlags'
        )
        config_data = agent.get_latest_configuration()
        return json.loads(config_data.decode('utf-8'))
    except Exception as e:
        print(f"Error retrieving configuration: {e}")
        return None

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_4():
    """Using AWS AppConfig Agent in a function that processes configurations"""
    def process_app_config():
        # ok: py-deprecated-get-configuration
        agent = AppConfigAgent(
            app_id='app123',
            env_id='env456',
            config_id='conf789'
        )
        
        config_data = agent.get_latest_configuration()
        return json.loads(config_data.decode('utf-8')) if config_data else {}
    
    return process_app_config()

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_5():
    """Using AWS AppConfig Agent with custom configuration"""
    # ok: py-deprecated-get-configuration
    agent = AppConfigAgent(
        app_id='PaymentService',
        env_id='Production',
        config_id='PaymentGateways',
        environment_variables={
            'AWS_APPCONFIG_EXTENSION_POLL_INTERVAL_SECONDS': '30',
            'AWS_APPCONFIG_EXTENSION_POLL_TIMEOUT_MILLIS': '3000'
        }
    )
    
    config_data = agent.get_latest_configuration()
    return json.loads(config_data.decode('utf-8')) if config_data else {}

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_6():
    """Using AWS AppConfig Agent with variables for parameters"""
    app_name = 'UserService'
    env_name = 'Production'
    config_name = 'UserPreferences'
    
    # ok: py-deprecated-get-configuration
    agent = AppConfigAgent(
        app_id=app_name,
        env_id=env_name,
        config_id=config_name
    )
    
    config_data = agent.get_latest_configuration()
    return json.loads(config_data.decode('utf-8')) if config_data else {}

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_7():
    """Using AWS AppConfig Agent in a class method"""
    class ConfigManager:
        def __init__(self):
            self.app = 'MyApp'
            self.env = 'Test'
            
        def get_app_config(self, config_name):
            # ok: py-deprecated-get-configuration
            agent = AppConfigAgent(
                app_id=self.app,
                env_id=self.env,
                config_id=config_name
            )
            config_data = agent.get_latest_configuration()
            return json.loads(config_data.decode('utf-8')) if config_data else {}
    
    manager = ConfigManager()
    return manager.get_app_config('ApiSettings')

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_8():
    """Using AWS AppConfig Agent with region specification"""
    # ok: py-deprecated-get-configuration
    agent = AppConfigAgent(
        app_id='NotificationService',
        env_id='Production',
        config_id='EmailTemplates',
        environment_variables={
            'AWS_REGION': 'us-east-1'
        }
    )
    
    config_data = agent.get_latest_configuration()
    return json.loads(config_data.decode('utf-8')) if config_data else {}

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_9():
    """Using AWS AppConfig Agent with conditional logic"""
    app_id = 'LoggingService'
    env_id = 'Production'
    
    if os.environ.get('DEBUG_MODE') == 'true':
        config_id = 'DebugConfig'
    else:
        config_id = 'ReleaseConfig'
    
    # ok: py-deprecated-get-configuration
    agent = AppConfigAgent(
        app_id=app_id,
        env_id=env_id,
        config_id=config_id
    )
    
    config_data = agent.get_latest_configuration()
    return json.loads(config_data.decode('utf-8')) if config_data else {}

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_10():
    """Using AWS AppConfig Agent in a loop for multiple configs"""
    app = 'MultiConfigApp'
    env = 'Staging'
    configs = ['Config1', 'Config2', 'Config3']
    results = {}
    
    for config in configs:
        # ok: py-deprecated-get-configuration
        agent = AppConfigAgent(
            app_id=app,
            env_id=env,
            config_id=config
        )
        config_data = agent.get_latest_configuration()
        results[config] = json.loads(config_data.decode('utf-8')) if config_data else {}
    
    return results

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_11():
    """Using AWS AppConfig Agent with async wrapper"""
    import asyncio
    
    async def fetch_config():
        # ok: py-deprecated-get-configuration
        agent = AppConfigAgent(
            app_id='AsyncApp',
            env_id='Production',
            config_id='AsyncConfig'
        )
        
        config_data = agent.get_latest_configuration()
        return json.loads(config_data.decode('utf-8')) if config_data else {}
    
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(fetch_config())

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_12():
    """Using AWS AppConfig Agent with custom configuration"""
    # ok: py-deprecated-get-configuration
    agent = AppConfigAgent(
        app_id='EuropeanService',
        env_id='Production',
        config_id='RegionalSettings',
        environment_variables={
            'AWS_REGION': 'eu-west-1'
        }
    )
    
    config_data = agent.get_latest_configuration()
    return json.loads(config_data.decode('utf-8')) if config_data else {}

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_13():
    """Using AWS AppConfig Agent with error handling and fallback"""
    try:
        # ok: py-deprecated-get-configuration
        agent = AppConfigAgent(
            app_id='CriticalService',
            env_id='Production',
            config_id='OperationalSettings'
        )
        config_data = agent.get_latest_configuration()
        return json.loads(config_data.decode('utf-8')) if config_data else {}
    except Exception:
        # Fallback to default configuration
        return {"default": "settings"}

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_14():
    """Using AWS AppConfig Agent with custom profile"""
    os.environ['AWS_PROFILE'] = 'development'
    os.environ['AWS_REGION'] = 'us-west-2'
    
    # ok: py-deprecated-get-configuration
    agent = AppConfigAgent(
        app_id='DevApp',
        env_id='Development',
        config_id='LocalSettings'
    )
    
    config_data = agent.get_latest_configuration()
    return json.loads(config_data.decode('utf-8')) if config_data else {}

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_15():
    """Using AWS Systems Manager Parameter Store instead of AppConfig"""
    # ok: py-deprecated-get-configuration
    ssm_client = boto3.client('ssm')
    response = ssm_client.get_parameter(
        Name='/app/config/settings',
        WithDecryption=True
    )
    
    return json.loads(response['Parameter']['Value'])
# {/fact}