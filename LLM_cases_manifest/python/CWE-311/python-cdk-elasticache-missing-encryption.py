import aws_cdk as cdk
from aws_cdk import (
    aws_elasticache as elasticache,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy,
)
from constructs import Construct
import aws_cdk.aws_ec2 as ec2

# True Positive Examples (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating an ElastiCache Redis cluster without encryption in transit
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis cluster for caching",
        engine="redis",
        cache_node_type="cache.t3.small",
        num_node_groups=1,
        replicas_per_node_group=1,
        automatic_failover_enabled=True,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating a Redis cluster with explicitly disabled encryption
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis cluster with encryption disabled",
        engine="redis",
        cache_node_type="cache.t3.small",
        transit_encryption_enabled=False,
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str, vpc: ec2.Vpc):
    # Creating a Redis cluster with subnet group but no encryption
    subnet_group = elasticache.CfnSubnetGroup(
        scope,
        "RedisSubnetGroup",
        description="Subnet group for Redis",
        subnet_ids=vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids,
    )
    
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis cluster in VPC",
        engine="redis",
        cache_node_type="cache.t3.small",
        cache_subnet_group_name=subnet_group.ref,
        num_node_groups=2,
        replicas_per_node_group=2,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a Redis cluster with auth token but no transit encryption
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis cluster with auth but no encryption",
        engine="redis",
        cache_node_type="cache.t3.medium",
        auth_token="secretAuthToken123",  # Auth token without encryption is problematic
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a Redis cluster with multiple configuration options but missing encryption
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Complex Redis setup",
        engine="redis",
        engine_version="6.x",
        cache_node_type="cache.m5.large",
        port=6379,
        snapshot_retention_limit=5,
        snapshot_window="00:00-01:00",
        automatic_failover_enabled=True,
        num_node_groups=3,
        replicas_per_node_group=2,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a Redis cluster with parameter group but no encryption
    parameter_group = elasticache.CfnParameterGroup(
        scope,
        "RedisParameterGroup",
        cache_parameter_group_family="redis6.x",
        description="Custom Redis parameters",
        properties={
            "maxmemory-policy": "volatile-lru",
        },
    )
    
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with custom parameters",
        engine="redis",
        cache_node_type="cache.t3.small",
        cache_parameter_group_name=parameter_group.ref,
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a Redis cluster with maintenance window but no encryption
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with maintenance window",
        engine="redis",
        cache_node_type="cache.t3.small",
        preferred_maintenance_window="sun:05:00-sun:06:00",
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a Redis cluster with at-rest encryption but not transit encryption
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with at-rest encryption only",
        engine="redis",
        cache_node_type="cache.t3.small",
        at_rest_encryption_enabled=True,  # At-rest encryption is enabled
        # Transit encryption is missing
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a Redis cluster with tags but no encryption
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with tags",
        engine="redis",
        cache_node_type="cache.t3.small",
        tags=[
            cdk.CfnTag(key="Environment", value="Production"),
            cdk.CfnTag(key="Department", value="Engineering"),
        ],
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a Redis cluster with multi-AZ but no encryption
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Multi-AZ Redis",
        engine="redis",
        cache_node_type="cache.t3.small",
        multi_az_enabled=True,
        automatic_failover_enabled=True,
        num_node_groups=2,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a Redis cluster with notification topic but no encryption
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with notifications",
        engine="redis",
        cache_node_type="cache.t3.small",
        notification_topic_arn="arn:aws:sns:us-east-1:123456789012:redis-notifications",
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a Redis cluster with security group but no encryption
    security_group = ec2.SecurityGroup(
        scope,
        "RedisSecurityGroup",
        vpc=ec2.Vpc(scope, "VPC"),
        description="Security group for Redis",
    )
    security_group.add_ingress_rule(
        peer=ec2.Peer.ipv4("10.0.0.0/16"),
        connection=ec2.Port.tcp(6379),
        description="Allow Redis traffic",
    )
    
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with security group",
        engine="redis",
        cache_node_type="cache.t3.small",
        security_group_ids=[security_group.security_group_id],
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a Redis cluster with snapshot settings but no encryption
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with snapshots",
        engine="redis",
        cache_node_type="cache.t3.small",
        snapshot_retention_limit=7,
        snapshot_window="02:00-03:00",
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a Redis cluster with node type configuration but no encryption
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with specific node type",
        engine="redis",
        cache_node_type="cache.r5.large",  # Memory optimized instance
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a Redis cluster with specific engine version but no encryption
    # ruleid: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with specific version",
        engine="redis",
        engine_version="6.2",
        cache_node_type="cache.t3.small",
        num_node_groups=1,
    )
    return cluster

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating an ElastiCache Redis cluster with encryption in transit enabled
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis cluster for caching",
        engine="redis",
        cache_node_type="cache.t3.small",
        transit_encryption_enabled=True,
        num_node_groups=1,
        replicas_per_node_group=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating a Redis cluster with both at-rest and transit encryption
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Fully encrypted Redis cluster",
        engine="redis",
        cache_node_type="cache.t3.small",
        at_rest_encryption_enabled=True,
        transit_encryption_enabled=True,
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct, id: str, vpc: ec2.Vpc):
    # Creating a Redis cluster in VPC with encryption enabled
    subnet_group = elasticache.CfnSubnetGroup(
        scope,
        "RedisSubnetGroup",
        description="Subnet group for Redis",
        subnet_ids=vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids,
    )
    
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis cluster in VPC with encryption",
        engine="redis",
        cache_node_type="cache.t3.small",
        cache_subnet_group_name=subnet_group.ref,
        transit_encryption_enabled=True,
        num_node_groups=2,
        replicas_per_node_group=2,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a Redis cluster with auth token and transit encryption
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis cluster with auth and encryption",
        engine="redis",
        cache_node_type="cache.t3.medium",
        auth_token="secretAuthToken123",
        transit_encryption_enabled=True,  # Properly securing auth token with encryption
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a Redis cluster with multiple configuration options and encryption
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Complex Redis setup with encryption",
        engine="redis",
        engine_version="6.x",
        cache_node_type="cache.m5.large",
        port=6379,
        snapshot_retention_limit=5,
        snapshot_window="00:00-01:00",
        automatic_failover_enabled=True,
        transit_encryption_enabled=True,
        num_node_groups=3,
        replicas_per_node_group=2,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a Redis cluster with parameter group and encryption
    parameter_group = elasticache.CfnParameterGroup(
        scope,
        "RedisParameterGroup",
        cache_parameter_group_family="redis6.x",
        description="Custom Redis parameters",
        properties={
            "maxmemory-policy": "volatile-lru",
        },
    )
    
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with custom parameters and encryption",
        engine="redis",
        cache_node_type="cache.t3.small",
        cache_parameter_group_name=parameter_group.ref,
        transit_encryption_enabled=True,
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a Redis cluster with maintenance window and encryption
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with maintenance window and encryption",
        engine="redis",
        cache_node_type="cache.t3.small",
        preferred_maintenance_window="sun:05:00-sun:06:00",
        transit_encryption_enabled=True,
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a Redis cluster with both at-rest and transit encryption explicitly enabled
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with comprehensive encryption",
        engine="redis",
        cache_node_type="cache.t3.small",
        at_rest_encryption_enabled=True,
        transit_encryption_enabled=True,
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a Redis cluster with tags and encryption
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with tags and encryption",
        engine="redis",
        cache_node_type="cache.t3.small",
        tags=[
            cdk.CfnTag(key="Environment", value="Production"),
            cdk.CfnTag(key="Department", value="Engineering"),
        ],
        transit_encryption_enabled=True,
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a Redis cluster with multi-AZ and encryption
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Multi-AZ Redis with encryption",
        engine="redis",
        cache_node_type="cache.t3.small",
        multi_az_enabled=True,
        automatic_failover_enabled=True,
        transit_encryption_enabled=True,
        num_node_groups=2,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a Redis cluster with notification topic and encryption
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with notifications and encryption",
        engine="redis",
        cache_node_type="cache.t3.small",
        notification_topic_arn="arn:aws:sns:us-east-1:123456789012:redis-notifications",
        transit_encryption_enabled=True,
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a Redis cluster with security group and encryption
    security_group = ec2.SecurityGroup(
        scope,
        "RedisSecurityGroup",
        vpc=ec2.Vpc(scope, "VPC"),
        description="Security group for Redis",
    )
    security_group.add_ingress_rule(
        peer=ec2.Peer.ipv4("10.0.0.0/16"),
        connection=ec2.Port.tcp(6379),
        description="Allow Redis traffic",
    )
    
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with security group and encryption",
        engine="redis",
        cache_node_type="cache.t3.small",
        security_group_ids=[security_group.security_group_id],
        transit_encryption_enabled=True,
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a Redis cluster with snapshot settings and encryption
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with snapshots and encryption",
        engine="redis",
        cache_node_type="cache.t3.small",
        snapshot_retention_limit=7,
        snapshot_window="02:00-03:00",
        transit_encryption_enabled=True,
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a Redis cluster with node type configuration and encryption
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with specific node type and encryption",
        engine="redis",
        cache_node_type="cache.r5.large",  # Memory optimized instance
        transit_encryption_enabled=True,
        num_node_groups=1,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a Redis cluster with specific engine version and encryption
    # ok: python-cdk-elasticache-missing-encryption
    cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis with specific version and encryption",
        engine="redis",
        engine_version="6.2",
        cache_node_type="cache.t3.small",
        transit_encryption_enabled=True,
        num_node_groups=1,
    )
    return cluster
# {/fact}