import aws_cdk as cdk
from aws_cdk import (
    aws_opensearchservice as opensearch,
    Stack,
    CfnOutput,
    RemovalPolicy,
    Duration,
)
from constructs import Construct
import os

# True Positives (Vulnerable Code Examples)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating OpenSearch domain without dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3
        },
        ebs={
            "volume_size": 10,
            "volume_type": cdk.aws_ec2.EbsDeviceVolumeType.GP2
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating OpenSearch domain with explicit disabled dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 5,
            "master_nodes": 0  # Explicitly setting to 0 (no dedicated master nodes)
        },
        ebs={
            "volume_size": 20
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating OpenSearch domain with default settings (no dedicated master nodes)
    # ruleid: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_2,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="r5.large.search",
            data_nodes=3
        )
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating OpenSearch domain with multiple data nodes but no dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.ELASTICSEARCH_7_10,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="r5.large.search",
            data_nodes=10
        ),
        ebs=opensearch.EbsOptions(
            volume_size=100,
            volume_type=cdk.aws_ec2.EbsDeviceVolumeType.GP3
        ),
        zone_awareness={
            "enabled": True,
            "availability_zone_count": 3
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating OpenSearch domain with high availability but no dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_3,
        capacity={
            "data_node_instance_type": "r5.2xlarge.search",
            "data_nodes": 6
        },
        ebs={
            "volume_size": 200
        },
        zone_awareness={
            "enabled": True
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating OpenSearch domain with encryption but no dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 4
        },
        ebs={
            "volume_size": 20
        },
        encryption_at_rest={
            "enabled": True
        },
        node_to_node_encryption=True
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating OpenSearch domain with custom endpoint but no dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        custom_endpoint={
            "domain_name": "search.example.com"
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating OpenSearch domain with fine-grained access control but no dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        fine_grained_access_control={
            "master_user_name": "admin",
            "master_user_password": cdk.SecretValue.secrets_manager("opensearch/master-password")
        },
        enforce_https=True,
        node_to_node_encryption=True,
        encryption_at_rest={
            "enabled": True
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating OpenSearch domain with UltraWarm storage but no dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3,
            "warm_nodes": 2,
            "warm_instance_type": "ultrawarm1.medium.search"
        },
        ebs={
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating OpenSearch domain with advanced options but no dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        advanced_options={
            "rest.action.multi.allow_explicit_index": "true",
            "indices.fielddata.cache.size": "40"
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating OpenSearch domain with logging but no dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        logging={
            "slow_search_log_enabled": True,
            "app_log_enabled": True,
            "slow_index_log_enabled": True
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating OpenSearch domain with cognito authentication but no dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    user_pool = cdk.aws_cognito.UserPool(scope, "UserPool")
    identity_pool = cdk.aws_cognito.CfnIdentityPool(scope, "IdentityPool",
        allow_unauthenticated_identities=False
    )
    
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        cognito_dashboards_auth=opensearch.CognitoOptions(
            identity_pool_id=identity_pool.ref,
            user_pool_id=user_pool.user_pool_id
        )
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC access but no dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    vpc = cdk.aws_ec2.Vpc(scope, "VPC")
    security_group = cdk.aws_ec2.SecurityGroup(scope, "SecurityGroup", vpc=vpc)
    
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[cdk.aws_ec2.SubnetSelection(subnet_type=cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        security_groups=[security_group]
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating OpenSearch domain with automated snapshot configuration but no dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        automated_snapshot_start_hour=3
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating OpenSearch domain with custom CloudWatch logs but no dedicated master nodes
    # ruleid: python-cdk-open-search-dedicated-master-node
    log_group = cdk.aws_logs.LogGroup(scope, "LogGroup")
    
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        logging={
            "app_log_enabled": True,
            "app_log_group": log_group
        }
    )
    return domain

# True Negatives (Secure Code Examples)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes
    # ok: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3
        },
        ebs={
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes using CapacityConfig
    # ok: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="r5.large.search",
            data_nodes=3,
            master_node_instance_type="r5.large.search",
            master_nodes=3
        ),
        ebs={
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating OpenSearch domain with minimum recommended dedicated master nodes (3)
    # ok: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_2,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 5,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3  # Recommended minimum for high availability
        },
        ebs={
            "volume_size": 20
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes and encryption
    # ok: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        encryption_at_rest={
            "enabled": True
        },
        node_to_node_encryption=True
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes and zone awareness
    # ok: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 6,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        zone_awareness={
            "enabled": True,
            "availability_zone_count": 3
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating OpenSearch domain with larger dedicated master nodes for high traffic
    # ok: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.2xlarge.search",
            "data_nodes": 10,
            "master_node_instance_type": "r5.xlarge.search",  # Larger instance for master nodes
            "master_nodes": 5  # More master nodes for higher reliability
        },
        ebs={
            "volume_size": 100
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes and fine-grained access control
    # ok: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        fine_grained_access_control={
            "master_user_name": "admin",
            "master_user_password": cdk.SecretValue.secrets_manager("opensearch/master-password")
        },
        enforce_https=True,
        node_to_node_encryption=True,
        encryption_at_rest={
            "enabled": True
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes and UltraWarm storage
    # ok: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3,
            "warm_nodes": 2,
            "warm_instance_type": "ultrawarm1.medium.search"
        },
        ebs={
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes and advanced options
    # ok: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        advanced_options={
            "rest.action.multi.allow_explicit_index": "true",
            "indices.fielddata.cache.size": "40"
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes and logging
    # ok: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        logging={
            "slow_search_log_enabled": True,
            "app_log_enabled": True,
            "slow_index_log_enabled": True
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes and cognito authentication
    # ok: python-cdk-open-search-dedicated-master-node
    user_pool = cdk.aws_cognito.UserPool(scope, "UserPool")
    identity_pool = cdk.aws_cognito.CfnIdentityPool(scope, "IdentityPool",
        allow_unauthenticated_identities=False
    )
    
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        cognito_dashboards_auth=opensearch.CognitoOptions(
            identity_pool_id=identity_pool.ref,
            user_pool_id=user_pool.user_pool_id
        )
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes and VPC access
    # ok: python-cdk-open-search-dedicated-master-node
    vpc = cdk.aws_ec2.Vpc(scope, "VPC")
    security_group = cdk.aws_ec2.SecurityGroup(scope, "SecurityGroup", vpc=vpc)
    
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[cdk.aws_ec2.SubnetSelection(subnet_type=cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        security_groups=[security_group]
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes and automated snapshot configuration
    # ok: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        automated_snapshot_start_hour=3
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes and custom CloudWatch logs
    # ok: python-cdk-open-search-dedicated-master-node
    log_group = cdk.aws_logs.LogGroup(scope, "LogGroup")
    
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        logging={
            "app_log_enabled": True,
            "app_log_group": log_group
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating OpenSearch domain with dedicated master nodes and custom endpoint
    # ok: python-cdk-open-search-dedicated-master-node
    domain = opensearch.Domain(scope, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_node_instance_type": "r5.large.search",
            "data_nodes": 3,
            "master_node_instance_type": "r5.large.search",
            "master_nodes": 3
        },
        ebs={
            "volume_size": 10
        },
        custom_endpoint={
            "domain_name": "search.example.com"
        }
    )
    return domain

# Example stack implementation
# {/fact}

class OpenSearchStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Example usage
        bad_domain = bad_case_1(self, "BadDomain")
        good_domain = good_case_1(self, "GoodDomain")