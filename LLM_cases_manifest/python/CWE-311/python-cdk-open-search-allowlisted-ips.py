import aws_cdk as cdk
from aws_cdk import (
    aws_opensearchservice as opensearch,
    aws_ec2 as ec2,
    Stack,
    CfnOutput,
    RemovalPolicy,
)
from constructs import Construct
import ipaddress

# True Positive Examples (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(self):
    # Creating OpenSearch domain without any access policies or IP restrictions
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "master_nodes": 3,
            "data_nodes": 2
        },
        ebs={
            "volume_size": 10
        },
        node_to_node_encryption=True,
        encryption_at_rest={
            "enabled": True
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(self):
    # Creating OpenSearch domain with only encryption but no access policies
    vpc = ec2.Vpc(self, "VPC")
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        vpc=vpc,
        encryption_at_rest={
            "enabled": True
        },
        node_to_node_encryption=True,
        enforce_https=True
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(self):
    # Creating OpenSearch domain with public access but no IP restrictions
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        removal_policy=RemovalPolicy.DESTROY
    )
    CfnOutput(self, "DomainEndpoint", value=domain.domain_endpoint)
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(self):
    # Creating OpenSearch domain with custom endpoint but no IP restrictions
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2
        },
        ebs={
            "volume_size": 20
        },
        custom_endpoint={
            "domain_name": "search.example.com",
            "certificate": None
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(self):
    # Creating OpenSearch domain with fine-grained access control but no IP restrictions
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        fine_grained_access_control={
            "master_user_name": "admin",
            "master_user_password": cdk.SecretValue.secrets_manager("opensearch/masteruser")
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
def bad_case_6(self):
    # Creating OpenSearch domain with advanced options but no IP restrictions
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        advanced_options={
            "rest.action.multi.allow_explicit_index": "true",
            "indices.fielddata.cache.size": "25",
            "indices.query.bool.max_clause_count": "1024"
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(self):
    # Creating OpenSearch domain with logging but no IP restrictions
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
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
def bad_case_8(self):
    # Creating OpenSearch domain with UltraWarm but no IP restrictions
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
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

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(self):
    # Creating OpenSearch domain with zone awareness but no IP restrictions
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
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

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(self):
    # Creating OpenSearch domain with cognito authentication but no IP restrictions
    vpc = ec2.Vpc(self, "VPC")
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        vpc=vpc,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        cognito_dashboards_auth={
            "identity_pool_id": "us-east-1:12345678-1234-1234-1234-123456789012",
            "user_pool_id": "us-east-1_abcdefghi",
            "role": None
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(self):
    # Creating OpenSearch domain with specific instance type but no IP restrictions
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 2,
            "data_node_instance_type": "r5.large.search"
        },
        ebs={
            "volume_size": 20,
            "volume_type": ec2.EbsDeviceVolumeType.GP2
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(self):
    # Creating OpenSearch domain with automated snapshot but no IP restrictions
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
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

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(self):
    # Creating OpenSearch domain with empty access policies
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        access_policies={}
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(self):
    # Creating OpenSearch domain with older Elasticsearch version and no IP restrictions
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.ELASTICSEARCH_7_10,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(self):
    # Creating OpenSearch domain with custom KMS key but no IP restrictions
    # ruleid: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        },
        encryption_at_rest={
            "enabled": True,
            "kms_key": None  # Would be a KMS key in real code
        }
    )
    return domain

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(self):
    # Creating OpenSearch domain with IP-based access policies
    vpc = ec2.Vpc(self, "VPC")
    security_group = ec2.SecurityGroup(self, "SecurityGroup", vpc=vpc)
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        vpc=vpc,
        security_groups=[security_group],
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(self):
    # Creating OpenSearch domain with explicit IP allowlist
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
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
                    "Principal": {"AWS": "*"},
                    "Action": "es:*",
                    "Resource": "*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": [
                                "192.168.0.1/32",
                                "10.0.0.0/24"
                            ]
                        }
                    }
                }
            ]
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(self):
    # Creating OpenSearch domain in VPC with specific subnet and security group
    vpc = ec2.Vpc(self, "VPC")
    security_group = ec2.SecurityGroup(self, "SecurityGroup", vpc=vpc)
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        security_groups=[security_group],
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(self):
    # Creating OpenSearch domain with IP-based access policy using CIDR notation
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
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
                    "Principal": {"AWS": "*"},
                    "Action": "es:ESHttp*",
                    "Resource": "*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": ["172.16.0.0/16"]
                        }
                    }
                }
            ]
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(self):
    # Creating OpenSearch domain with IP-based access policy and specific actions
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
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
                    "Principal": {"AWS": "*"},
                    "Action": ["es:ESHttpGet", "es:ESHttpPut"],
                    "Resource": "*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": ["192.168.1.0/24", "192.168.2.0/24"]
                        }
                    }
                }
            ]
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(self):
    # Creating OpenSearch domain with VPC and security groups with specific rules
    vpc = ec2.Vpc(self, "VPC")
    security_group = ec2.SecurityGroup(self, "SecurityGroup", vpc=vpc)
    security_group.add_ingress_rule(
        ec2.Peer.ipv4("10.0.0.0/16"),
        ec2.Port.tcp(443),
        "Allow HTTPS from internal network"
    )
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        vpc=vpc,
        security_groups=[security_group],
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(self):
    # Creating OpenSearch domain with IP-based access policy and IAM principal
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
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
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/admin"},
                    "Action": "es:*",
                    "Resource": "*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": ["203.0.113.0/24"]
                        }
                    }
                }
            ]
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(self):
    # Creating OpenSearch domain with VPC and multiple security groups
    vpc = ec2.Vpc(self, "VPC")
    security_group1 = ec2.SecurityGroup(self, "SecurityGroup1", vpc=vpc)
    security_group2 = ec2.SecurityGroup(self, "SecurityGroup2", vpc=vpc)
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        vpc=vpc,
        security_groups=[security_group1, security_group2],
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(self):
    # Creating OpenSearch domain with IP-based access policy and specific resource
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        }
    )
    
    domain.add_access_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "es:*",
                "Resource": f"{domain.domain_arn}/*",
                "Condition": {
                    "IpAddress": {
                        "aws:SourceIp": ["192.168.0.0/16"]
                    }
                }
            }
        ]
    })
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(self):
    # Creating OpenSearch domain with IP-based access policy using variable
    allowed_ips = ["10.0.0.1/32", "10.0.0.2/32"]
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
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
                    "Principal": {"AWS": "*"},
                    "Action": "es:*",
                    "Resource": "*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": allowed_ips
                        }
                    }
                }
            ]
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(self):
    # Creating OpenSearch domain with IP-based access policy using function
    def get_allowed_ips():
        return ["192.168.1.1/32", "192.168.1.2/32"]
    
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
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
                    "Principal": {"AWS": "*"},
                    "Action": "es:*",
                    "Resource": "*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": get_allowed_ips()
                        }
                    }
                }
            ]
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(self):
    # Creating OpenSearch domain with IP-based access policy using ipaddress module
    office_network = str(ipaddress.IPv4Network('10.10.0.0/16'))
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
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
                    "Principal": {"AWS": "*"},
                    "Action": "es:*",
                    "Resource": "*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": [office_network]
                        }
                    }
                }
            ]
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(self):
    # Creating OpenSearch domain with IP-based access policy using multiple conditions
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
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
                    "Principal": {"AWS": "*"},
                    "Action": "es:*",
                    "Resource": "*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": ["192.168.0.0/24"]
                        },
                        "Bool": {
                            "aws:SecureTransport": "true"
                        }
                    }
                }
            ]
        }
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(self):
    # Creating OpenSearch domain with VPC endpoint
    vpc = ec2.Vpc(self, "VPC")
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        vpc=vpc,
        vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        capacity={
            "data_nodes": 1
        },
        ebs={
            "volume_size": 10
        }
    )
    
    # Create VPC endpoint for OpenSearch
    ec2.InterfaceVpcEndpoint(self, "OpenSearchEndpoint",
        vpc=vpc,
        service=ec2.InterfaceVpcEndpointService(f"com.amazonaws.{self.region}.es"),
        private_dns_enabled=True,
        subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
    )
    return domain

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(self):
    # Creating OpenSearch domain with IP-based access policy and deny statement
    # ok: python-cdk-open-search-allowlisted-ips
    domain = opensearch.Domain(self, "Domain",
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
                    "Principal": {"AWS": "*"},
                    "Action": "es:*",
                    "Resource": "*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": ["10.0.0.0/8"]
                        }
                    }
                },
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": "*"},
                    "Action": "es:*",
                    "Resource": "*",
                    "Condition": {
                        "NotIpAddress": {
                            "aws:SourceIp": ["10.0.0.0/8"]
                        }
                    }
                }
            ]
        }
    )
    return domain
# {/fact}