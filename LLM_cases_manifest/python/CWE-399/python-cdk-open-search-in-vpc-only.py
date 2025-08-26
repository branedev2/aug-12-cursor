import aws_cdk as cdk
from aws_cdk import (
    aws_opensearchservice as opensearch,
    aws_ec2 as ec2,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy
)
from constructs import Construct

# True Positives (Vulnerable Cases)

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating OpenSearch domain without VPC configuration
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain1",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "master_nodes": 3,
            "data_nodes": 2
        },
        ebs={
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating OpenSearch domain with explicit public access
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain2",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "master_nodes": 3,
            "data_nodes": 2
        },
        ebs={
            "volume_size": 10
        },
        enforce_https=True,
        node_to_node_encryption=True,
        encryption_at_rest={
            "enabled": True
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating OpenSearch domain with advanced options but no VPC
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain3",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "master_nodes": 5,
            "data_nodes": 10,
            "master_node_instance_type": "r5.large.search",
            "data_node_instance_type": "r5.large.search"
        },
        ebs={
            "volume_size": 20,
            "volume_type": ec2.EbsDeviceVolumeType.GP2
        },
        fine_grained_access_control={
            "master_user_name": "admin",
            "master_user_password": cdk.SecretValue.secrets_manager("opensearch/masteruser")
        },
        logging={
            "slow_search_log_enabled": True,
            "app_log_enabled": True,
            "slow_index_log_enabled": True
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating OpenSearch domain with custom endpoint but no VPC
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain4",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        custom_endpoint={
            "domain_name": "search.example.com",
            "certificate": None  # Would typically provide a certificate here
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating OpenSearch domain with access policies but no VPC
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain5",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        access_policies={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": "es:*",
                    "Resource": "*"
                }
            ]
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating OpenSearch domain with advanced security options but no VPC
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain6",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2
        },
        ebs={
            "volume_size": 10
        },
        enforce_https=True,
        encryption_at_rest={
            "enabled": True
        },
        node_to_node_encryption=True,
        advanced_security_options={
            "enabled": True,
            "internal_user_database_enabled": True,
            "master_user_name": "admin",
            "master_user_password": cdk.SecretValue.secrets_manager("opensearch/masteruser")
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating OpenSearch domain with cognito authentication but no VPC
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain7",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        cognito_dashboards_auth={
            "identity_pool_id": "us-east-1:12345678-1234-1234-1234-123456789012",
            "user_pool_id": "us-east-1_abcdefghi",
            "role": None  # Would typically provide an IAM role here
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating OpenSearch domain with explicit vpc_options set to None
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain8",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        vpc_options=None
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating OpenSearch domain with zone awareness but no VPC
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain9",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2
        },
        ebs={
            "volume_size": 10
        },
        zone_awareness={
            "enabled": True,
            "availability_zone_count": 2
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating OpenSearch domain with domain name but no VPC
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain10",
        domain_name="custom-domain-name",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating OpenSearch domain with removal policy but no VPC
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain11",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        removal_policy=RemovalPolicy.SNAPSHOT
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating OpenSearch domain with automated snapshot but no VPC
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain12",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        automated_snapshot_start_hour=2
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating OpenSearch domain with UltraWarm storage but no VPC
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain13",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
            "warm_nodes": 2,
            "warm_instance_type": "ultrawarm1.medium.search"
        },
        ebs={
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating OpenSearch domain with CfnDomain (L1 construct) but no VPC
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.CfnDomain(scope, "BadDomain14",
        engine_version="OpenSearch_1.0",
        cluster_config={
            "instance_count": 1,
            "instance_type": "t3.small.search"
        },
        ebs_options={
            "ebs_enabled": True,
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating OpenSearch domain with empty security options but no VPC
    # ruleid: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "BadDomain15",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        enforce_https=True,
        tls_security_policy=opensearch.TLSSecurityPolicy.TLS_1_2
    )
    return domain

# True Negatives (Secure Cases)

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC configuration
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain1",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and security groups
    vpc = ec2.Vpc(scope, "VPC")
    security_group = ec2.SecurityGroup(scope, "OpenSearchSG", vpc=vpc)
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain2",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        security_groups=[security_group]
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and advanced options
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain3",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "master_nodes": 3,
            "data_nodes": 10,
            "master_node_instance_type": "r5.large.search",
            "data_node_instance_type": "r5.large.search"
        },
        ebs={
            "volume_size": 20,
            "volume_type": ec2.EbsDeviceVolumeType.GP2
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        fine_grained_access_control={
            "master_user_name": "admin",
            "master_user_password": cdk.SecretValue.secrets_manager("opensearch/masteruser")
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and zone awareness
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain4",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        zone_awareness={
            "enabled": True,
            "availability_zone_count": 2
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and custom endpoint
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain5",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        custom_endpoint={
            "domain_name": "search.example.com",
            "certificate": None  # Would typically provide a certificate here
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and access policies
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain6",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        access_policies={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "*"
                    },
                    "Action": "es:*",
                    "Resource": "*"
                }
            ]
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and advanced security options
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain7",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        enforce_https=True,
        encryption_at_rest={
            "enabled": True
        },
        node_to_node_encryption=True,
        advanced_security_options={
            "enabled": True,
            "internal_user_database_enabled": True,
            "master_user_name": "admin",
            "master_user_password": cdk.SecretValue.secrets_manager("opensearch/masteruser")
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and cognito authentication
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain8",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        cognito_dashboards_auth={
            "identity_pool_id": "us-east-1:12345678-1234-1234-1234-123456789012",
            "user_pool_id": "us-east-1_abcdefghi",
            "role": None  # Would typically provide an IAM role here
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and explicit vpc_options
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain9",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        vpc_options={
            "vpc": vpc,
            "subnets": [ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and domain name
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain10",
        domain_name="custom-domain-name",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and removal policy
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain11",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        removal_policy=RemovalPolicy.SNAPSHOT
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and automated snapshot
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain12",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        automated_snapshot_start_hour=2
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and UltraWarm storage
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain13",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
            "warm_nodes": 2,
            "warm_instance_type": "ultrawarm1.medium.search"
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating OpenSearch domain with CfnDomain (L1 construct) and VPC
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.CfnDomain(scope, "GoodDomain14",
        engine_version="OpenSearch_1.0",
        cluster_config={
            "instance_count": 1,
            "instance_type": "t3.small.search"
        },
        ebs_options={
            "ebs_enabled": True,
            "volume_size": 10
        },
        vpc_options={
            "subnet_ids": [vpc.private_subnets[0].subnet_id]
        }
    )
    return domain

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating OpenSearch domain with VPC and TLS security policy
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-open-search-in-vpc-only
    domain = opensearch.Domain(scope, "GoodDomain15",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        enforce_https=True,
        tls_security_policy=opensearch.TLSSecurityPolicy.TLS_1_2
    )
    return domain
# {/fact}