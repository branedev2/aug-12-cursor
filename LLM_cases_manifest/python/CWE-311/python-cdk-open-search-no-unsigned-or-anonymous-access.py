import aws_cdk as cdk
from aws_cdk import (
    aws_opensearchservice as opensearch,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy,
)
from constructs import Construct
import os

# True Positive Examples (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating an OpenSearch domain with anonymous access enabled
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "master_nodes": 3,
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        fine_grained_access_control=opensearch.AdvancedSecurityOptions(
            master_user_name="admin",
            master_user_password=cdk.SecretValue.plain_text("Password123!"),
        ),
        enforce_https=True,
        node_to_node_encryption=True,
        encryption_at_rest={
            "enabled": True,
        },
        anonymous_access_enabled=True  # Allowing anonymous access
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating an OpenSearch domain with unsigned requests allowed
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        unsigned_basic_auth=True  # Allowing unsigned requests
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating an OpenSearch domain with both anonymous access and unsigned basic auth
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        anonymous_access_enabled=True,
        unsigned_basic_auth=True
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating an OpenSearch domain with anonymous access in a complex configuration
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 3,
            "master_nodes": 3,
        },
        ebs={
            "volume_size": 20,
            "volume_type": cdk.aws_ec2.EbsDeviceVolumeType.GP2,
        },
        zone_awareness={
            "enabled": True,
            "availability_zone_count": 3,
        },
        logging={
            "slow_search_log_enabled": True,
            "app_log_enabled": True,
        },
        fine_grained_access_control=opensearch.AdvancedSecurityOptions(
            master_user_name="admin",
            master_user_password=cdk.SecretValue.plain_text("StrongPassword123!"),
        ),
        anonymous_access_enabled=True  # Allowing anonymous access
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating an OpenSearch domain with unsigned basic auth in a complex configuration
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 3,
        },
        ebs={
            "volume_size": 20,
        },
        encryption_at_rest={
            "enabled": True,
        },
        node_to_node_encryption=True,
        enforce_https=True,
        unsigned_basic_auth=True  # Allowing unsigned basic auth
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Using L1 construct with anonymous access
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = cdk.aws_opensearchservice.CfnDomain(scope, "MyDomain",
        engine_version="OpenSearch_1.0",
        cluster_config={
            "instance_count": 2,
            "instance_type": "t3.small.search",
        },
        ebs_options={
            "ebs_enabled": True,
            "volume_size": 10,
        },
        advanced_security_options={
            "enabled": True,
            "anonymous_auth_enabled": True,  # Allowing anonymous access
            "master_user_options": {
                "master_user_name": "admin",
                "master_user_password": "Password123!",
            },
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Using domain props with anonymous access
    domain_props = {
        "version": opensearch.EngineVersion.OPENSEARCH_1_0,
        "capacity": {
            "data_nodes": 2,
        },
        "ebs": {
            "volume_size": 10,
        },
        "anonymous_access_enabled": True  # Allowing anonymous access
    }
    
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain", **domain_props)
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Using domain props with unsigned basic auth
    domain_props = {
        "version": opensearch.EngineVersion.OPENSEARCH_1_0,
        "capacity": {
            "data_nodes": 2,
        },
        "ebs": {
            "volume_size": 10,
        },
        "unsigned_basic_auth": True  # Allowing unsigned basic auth
    }
    
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain", **domain_props)
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating domain with conditional anonymous access (still vulnerable)
    enable_anonymous = True
    
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        anonymous_access_enabled=enable_anonymous
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating domain with conditional unsigned basic auth (still vulnerable)
    allow_unsigned = True
    
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        unsigned_basic_auth=allow_unsigned
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating domain with environment variable for anonymous access (still vulnerable if True)
    enable_anonymous = os.environ.get("ENABLE_ANONYMOUS", "True") == "True"
    
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        anonymous_access_enabled=enable_anonymous
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating domain with environment variable for unsigned basic auth (still vulnerable if True)
    allow_unsigned = os.environ.get("ALLOW_UNSIGNED", "True") == "True"
    
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        unsigned_basic_auth=allow_unsigned
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating domain with explicit True for anonymous access
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        anonymous_access_enabled=True if 1 == 1 else False
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating domain with explicit True for unsigned basic auth
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        unsigned_basic_auth=True if 1 == 1 else False
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating domain with both insecure settings through variables
    enable_anonymous = True
    allow_unsigned = True
    
    # ruleid: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        anonymous_access_enabled=enable_anonymous,
        unsigned_basic_auth=allow_unsigned
    )
    return domain

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating an OpenSearch domain with anonymous access explicitly disabled
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        anonymous_access_enabled=False
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating an OpenSearch domain with unsigned basic auth explicitly disabled
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        unsigned_basic_auth=False
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating an OpenSearch domain with both anonymous access and unsigned basic auth explicitly disabled
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        anonymous_access_enabled=False,
        unsigned_basic_auth=False
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating an OpenSearch domain without specifying anonymous access or unsigned basic auth (defaults to secure)
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating an OpenSearch domain with secure configuration in a complex setup
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 3,
            "master_nodes": 3,
        },
        ebs={
            "volume_size": 20,
            "volume_type": cdk.aws_ec2.EbsDeviceVolumeType.GP2,
        },
        zone_awareness={
            "enabled": True,
            "availability_zone_count": 3,
        },
        logging={
            "slow_search_log_enabled": True,
            "app_log_enabled": True,
        },
        fine_grained_access_control=opensearch.AdvancedSecurityOptions(
            master_user_name="admin",
            master_user_password=cdk.SecretValue.secret_value("StrongPassword123!"),
        ),
        encryption_at_rest={
            "enabled": True,
        },
        node_to_node_encryption=True,
        enforce_https=True
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Using L1 construct with anonymous access explicitly disabled
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = cdk.aws_opensearchservice.CfnDomain(scope, "MyDomain",
        engine_version="OpenSearch_1.0",
        cluster_config={
            "instance_count": 2,
            "instance_type": "t3.small.search",
        },
        ebs_options={
            "ebs_enabled": True,
            "volume_size": 10,
        },
        advanced_security_options={
            "enabled": True,
            "anonymous_auth_enabled": False,
            "master_user_options": {
                "master_user_name": "admin",
                "master_user_password": "Password123!",
            },
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Using domain props with secure settings
    domain_props = {
        "version": opensearch.EngineVersion.OPENSEARCH_1_0,
        "capacity": {
            "data_nodes": 2,
        },
        "ebs": {
            "volume_size": 10,
        },
        "anonymous_access_enabled": False,
        "unsigned_basic_auth": False
    }
    
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain", **domain_props)
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Using domain props without specifying insecure settings
    domain_props = {
        "version": opensearch.EngineVersion.OPENSEARCH_1_0,
        "capacity": {
            "data_nodes": 2,
        },
        "ebs": {
            "volume_size": 10,
        }
    }
    
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain", **domain_props)
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating domain with conditional anonymous access set to False
    enable_anonymous = False
    
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        anonymous_access_enabled=enable_anonymous
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating domain with conditional unsigned basic auth set to False
    allow_unsigned = False
    
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        unsigned_basic_auth=allow_unsigned
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating domain with environment variable for anonymous access (secure if False)
    enable_anonymous = os.environ.get("ENABLE_ANONYMOUS", "False") == "True"
    
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        anonymous_access_enabled=enable_anonymous
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating domain with environment variable for unsigned basic auth (secure if False)
    allow_unsigned = os.environ.get("ALLOW_UNSIGNED", "False") == "True"
    
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        unsigned_basic_auth=allow_unsigned
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating domain with explicit False for anonymous access
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        anonymous_access_enabled=False if 1 == 1 else True
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating domain with explicit False for unsigned basic auth
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        unsigned_basic_auth=False if 1 == 1 else True
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating domain with both secure settings through variables
    enable_anonymous = False
    allow_unsigned = False
    
    # ok: python-cdk-open-search-no-unsigned-or-anonymous-access
    domain = opensearch.Domain(scope, "MyDomain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
        },
        ebs={
            "volume_size": 10,
        },
        anonymous_access_enabled=enable_anonymous,
        unsigned_basic_auth=allow_unsigned
    )
    return domain
# {/fact}