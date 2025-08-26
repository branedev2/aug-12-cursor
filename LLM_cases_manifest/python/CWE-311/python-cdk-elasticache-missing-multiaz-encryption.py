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
import aws_cdk.aws_kms as kms

# True Positives (Vulnerable Cases)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster without Multi-AZ
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis cluster without Multi-AZ",
        engine="redis",
        cache_node_type="cache.t3.small",
        num_cache_clusters=1,
        automatic_failover_enabled=False,  # No automatic failover = no Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with explicit Multi-AZ disabled
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisCluster",
        replication_group_description="Redis cluster with Multi-AZ explicitly disabled",
        engine="redis",
        cache_node_type="cache.t3.medium",
        num_cache_clusters=2,
        automatic_failover_enabled=False,  # Explicitly disabled
        multi_az_enabled=False,  # Explicitly disabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with only one node (can't be Multi-AZ)
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "SingleNodeRedis",
        replication_group_description="Single node Redis",
        engine="redis",
        cache_node_type="cache.m5.large",
        num_cache_clusters=1,  # Only one node, can't be Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with automatic failover but not Multi-AZ
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "RedisClusterWithFailover",
        replication_group_description="Redis with failover but no Multi-AZ",
        engine="redis",
        cache_node_type="cache.r5.large",
        num_cache_clusters=2,
        automatic_failover_enabled=True,
        multi_az_enabled=False,  # Explicitly disabled Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with encryption but no Multi-AZ
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "EncryptedRedisNoMultiAZ",
        replication_group_description="Encrypted Redis without Multi-AZ",
        engine="redis",
        cache_node_type="cache.m5.large",
        num_cache_clusters=1,
        at_rest_encryption_enabled=True,  # Encryption enabled
        transit_encryption_enabled=True,  # Encryption enabled
        automatic_failover_enabled=False,  # No Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster using ServerlessV2 but no Multi-AZ
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnServerlessCache(
        scope,
        "ServerlessRedisNoMultiAZ",
        engine="redis",
        serverless_cache_name="serverless-redis",
        multi_az_enabled=False,  # Explicitly disabled Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with custom parameter group but no Multi-AZ
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    parameter_group = elasticache.CfnParameterGroup(
        scope,
        "RedisParams",
        cache_parameter_group_family="redis6.x",
        description="Custom Redis parameters",
        properties={"maxmemory-policy": "volatile-lru"}
    )
    
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "CustomParamsRedis",
        replication_group_description="Redis with custom params without Multi-AZ",
        engine="redis",
        cache_node_type="cache.t3.medium",
        num_cache_clusters=2,
        cache_parameter_group_name=parameter_group.ref,
        automatic_failover_enabled=False,  # No Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with security group but no Multi-AZ
    vpc = ec2.Vpc(scope, "VPC")
    security_group = ec2.SecurityGroup(scope, "RedisSecurityGroup", vpc=vpc)
    
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "SecureRedisNoMultiAZ",
        replication_group_description="Redis with security group but no Multi-AZ",
        engine="redis",
        cache_node_type="cache.m5.large",
        num_cache_clusters=2,
        security_group_ids=[security_group.security_group_id],
        automatic_failover_enabled=False,  # No Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with KMS encryption but no Multi-AZ
    key = kms.Key(scope, "RedisEncryptionKey")
    
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "KmsEncryptedRedisNoMultiAZ",
        replication_group_description="KMS encrypted Redis without Multi-AZ",
        engine="redis",
        cache_node_type="cache.r5.large",
        num_cache_clusters=1,
        at_rest_encryption_enabled=True,
        kms_key_id=key.key_id,
        automatic_failover_enabled=False,  # No Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with snapshot retention but no Multi-AZ
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "BackupRedisNoMultiAZ",
        replication_group_description="Redis with backups but no Multi-AZ",
        engine="redis",
        cache_node_type="cache.m5.large",
        num_cache_clusters=2,
        snapshot_retention_limit=7,  # Backup retention enabled
        automatic_failover_enabled=False,  # No Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with maintenance window but no Multi-AZ
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "MaintWindowRedisNoMultiAZ",
        replication_group_description="Redis with maintenance window but no Multi-AZ",
        engine="redis",
        cache_node_type="cache.t3.medium",
        num_cache_clusters=2,
        preferred_maintenance_window="sun:05:00-sun:09:00",
        automatic_failover_enabled=False,  # No Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with auth token but no Multi-AZ
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "AuthRedisNoMultiAZ",
        replication_group_description="Redis with auth but no Multi-AZ",
        engine="redis",
        cache_node_type="cache.t3.medium",
        num_cache_clusters=2,
        auth_token="secretAuthToken123!",
        transit_encryption_enabled=True,  # Required for auth token
        automatic_failover_enabled=False,  # No Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with port customization but no Multi-AZ
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "CustomPortRedisNoMultiAZ",
        replication_group_description="Redis with custom port but no Multi-AZ",
        engine="redis",
        cache_node_type="cache.m5.large",
        num_cache_clusters=2,
        port=6380,  # Custom port
        automatic_failover_enabled=False,  # No Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with subnet group but no Multi-AZ
    vpc = ec2.Vpc(scope, "VPC")
    subnet_group = elasticache.CfnSubnetGroup(
        scope,
        "RedisSubnetGroup",
        description="Redis subnet group",
        subnet_ids=[subnet.subnet_id for subnet in vpc.private_subnets]
    )
    
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "SubnetGroupRedisNoMultiAZ",
        replication_group_description="Redis with subnet group but no Multi-AZ",
        engine="redis",
        cache_node_type="cache.t3.medium",
        num_cache_clusters=2,
        cache_subnet_group_name=subnet_group.ref,
        automatic_failover_enabled=False,  # No Multi-AZ
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster using L2 construct without Multi-AZ
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnCacheCluster(
        scope,
        "L2RedisNoMultiAZ",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        vpc_security_group_ids=[
            ec2.SecurityGroup(scope, "RedisSG", vpc=vpc).security_group_id
        ],
        # No Multi-AZ configuration available in this construct
    )
    return redis_cluster

# True Negatives (Secure Cases)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ enabled
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "MultiAZRedis",
        replication_group_description="Redis cluster with Multi-AZ",
        engine="redis",
        cache_node_type="cache.t3.medium",
        num_cache_clusters=2,
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ explicitly enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ and encryption
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "SecureMultiAZRedis",
        replication_group_description="Secure Redis with Multi-AZ",
        engine="redis",
        cache_node_type="cache.m5.large",
        num_cache_clusters=3,
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
        at_rest_encryption_enabled=True,
        transit_encryption_enabled=True,
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ using ServerlessV2
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnServerlessCache(
        scope,
        "ServerlessMultiAZRedis",
        engine="redis",
        serverless_cache_name="serverless-redis-multiaz",
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ and custom parameter group
    parameter_group = elasticache.CfnParameterGroup(
        scope,
        "RedisParams",
        cache_parameter_group_family="redis6.x",
        description="Custom Redis parameters",
        properties={"maxmemory-policy": "volatile-lru"}
    )
    
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "CustomParamsMultiAZRedis",
        replication_group_description="Redis with custom params and Multi-AZ",
        engine="redis",
        cache_node_type="cache.t3.medium",
        num_cache_clusters=2,
        cache_parameter_group_name=parameter_group.ref,
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ and security group
    vpc = ec2.Vpc(scope, "VPC")
    security_group = ec2.SecurityGroup(scope, "RedisSecurityGroup", vpc=vpc)
    
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "SecureMultiAZRedis",
        replication_group_description="Redis with security group and Multi-AZ",
        engine="redis",
        cache_node_type="cache.m5.large",
        num_cache_clusters=2,
        security_group_ids=[security_group.security_group_id],
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ and KMS encryption
    key = kms.Key(scope, "RedisEncryptionKey")
    
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "KmsEncryptedMultiAZRedis",
        replication_group_description="KMS encrypted Redis with Multi-AZ",
        engine="redis",
        cache_node_type="cache.r5.large",
        num_cache_clusters=3,
        at_rest_encryption_enabled=True,
        kms_key_id=key.key_id,
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ and snapshot retention
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "BackupMultiAZRedis",
        replication_group_description="Redis with backups and Multi-AZ",
        engine="redis",
        cache_node_type="cache.m5.large",
        num_cache_clusters=2,
        snapshot_retention_limit=7,  # Backup retention enabled
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ and maintenance window
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "MaintWindowMultiAZRedis",
        replication_group_description="Redis with maintenance window and Multi-AZ",
        engine="redis",
        cache_node_type="cache.t3.medium",
        num_cache_clusters=3,
        preferred_maintenance_window="sun:05:00-sun:09:00",
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ and auth token
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "AuthMultiAZRedis",
        replication_group_description="Redis with auth and Multi-AZ",
        engine="redis",
        cache_node_type="cache.t3.medium",
        num_cache_clusters=2,
        auth_token="secretAuthToken123!",
        transit_encryption_enabled=True,  # Required for auth token
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ and port customization
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "CustomPortMultiAZRedis",
        replication_group_description="Redis with custom port and Multi-AZ",
        engine="redis",
        cache_node_type="cache.m5.large",
        num_cache_clusters=2,
        port=6380,  # Custom port
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ and subnet group
    vpc = ec2.Vpc(scope, "VPC")
    subnet_group = elasticache.CfnSubnetGroup(
        scope,
        "RedisSubnetGroup",
        description="Redis subnet group",
        subnet_ids=[subnet.subnet_id for subnet in vpc.private_subnets]
    )
    
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "SubnetGroupMultiAZRedis",
        replication_group_description="Redis with subnet group and Multi-AZ",
        engine="redis",
        cache_node_type="cache.t3.medium",
        num_cache_clusters=3,
        cache_subnet_group_name=subnet_group.ref,
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ using cluster mode
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "ClusterModeMultiAZRedis",
        replication_group_description="Redis with cluster mode and Multi-AZ",
        engine="redis",
        cache_node_type="cache.m5.large",
        num_node_groups=2,  # Using cluster mode
        replicas_per_node_group=1,
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ and auto minor version upgrade
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "AutoUpgradeMultiAZRedis",
        replication_group_description="Redis with auto upgrade and Multi-AZ",
        engine="redis",
        engine_version="6.2",
        cache_node_type="cache.t3.medium",
        num_cache_clusters=2,
        auto_minor_version_upgrade=True,
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ and notification topic
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "NotificationMultiAZRedis",
        replication_group_description="Redis with notifications and Multi-AZ",
        engine="redis",
        cache_node_type="cache.m5.large",
        num_cache_clusters=3,
        notification_topic_arn="arn:aws:sns:us-east-1:123456789012:redis-notifications",
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating ElastiCache Redis cluster with Multi-AZ using L2 construct
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-elasticache-missing-multiaz-encryption
    subnet_group = elasticache.CfnSubnetGroup(
        scope,
        "RedisSubnetGroup",
        description="Redis subnet group",
        subnet_ids=[subnet.subnet_id for subnet in vpc.private_subnets]
    )
    
    redis_cluster = elasticache.CfnReplicationGroup(
        scope,
        "L2MultiAZRedis",
        replication_group_description="L2 construct Redis with Multi-AZ",
        engine="redis",
        cache_node_type="cache.t3.medium",
        num_cache_clusters=2,
        cache_subnet_group_name=subnet_group.ref,
        automatic_failover_enabled=True,
        multi_az_enabled=True,  # Multi-AZ enabled
    )
    return redis_cluster
# {/fact}