import aws_cdk as cdk
from aws_cdk import (
    aws_elasticache as elasticache,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy
)
from constructs import Construct


# {fact rule=code-injection@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a Redis cluster with default port (6379)
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisCluster",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating a Memcached cluster with default port (11211)
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    memcached_cluster = elasticache.CfnCacheCluster(
        scope, "MemcachedCluster",
        cache_node_type="cache.t3.micro",
        engine="memcached",
        num_cache_nodes=2,
    )
    return memcached_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a Redis replication group with default port
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    redis_replication_group = elasticache.CfnReplicationGroup(
        scope, "RedisReplicationGroup",
        replication_group_description="Redis replication group",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_clusters=2,
    )
    return redis_replication_group


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a Redis cluster with default port and explicitly setting engine version
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithVersion",
        cache_node_type="cache.t3.micro",
        engine="redis",
        engine_version="6.2",
        num_cache_nodes=1,
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a Redis cluster with default port and additional configurations
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithConfig",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        auto_minor_version_upgrade=True,
        snapshot_retention_limit=5,
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a Redis serverless cache with default port
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    redis_serverless = elasticache.CfnServerlessCache(
        scope, "RedisServerlessCache",
        engine="redis",
        serverless_cache_name="my-redis-serverless",
    )
    return redis_serverless


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a Redis cluster using L2 construct with default port
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    subnet_group = elasticache.CfnSubnetGroup(
        scope, "RedisSubnetGroup",
        description="Subnet group for Redis cluster",
        subnet_ids=["subnet-12345", "subnet-67890"]
    )
    
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithSubnetGroup",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        cache_subnet_group_name=subnet_group.ref,
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a Redis replication group with multi-AZ and default port
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    redis_replication_group = elasticache.CfnReplicationGroup(
        scope, "MultiAZRedisReplicationGroup",
        replication_group_description="Multi-AZ Redis replication group",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_clusters=2,
        automatic_failover_enabled=True,
        multi_az_enabled=True,
    )
    return redis_replication_group


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a Redis cluster with encryption but default port
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "EncryptedRedisCluster",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        engine_version="6.x",
        at_rest_encryption_enabled=True,
        transit_encryption_enabled=True,
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a Redis cluster with parameter group but default port
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    parameter_group = elasticache.CfnParameterGroup(
        scope, "RedisParameterGroup",
        cache_parameter_group_family="redis6.x",
        description="Custom Redis parameter group",
        properties={
            "maxmemory-policy": "volatile-lru"
        }
    )
    
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithParamGroup",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        cache_parameter_group_name=parameter_group.ref,
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a Redis cluster with security group but default port
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithSecurityGroup",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        vpc_security_group_ids=["sg-12345"],
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a Redis cluster with tags but default port
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithTags",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        tags=[
            cdk.CfnTag(key="Environment", value="Production"),
            cdk.CfnTag(key="Owner", value="DataTeam")
        ]
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a Redis replication group with cluster mode enabled but default port
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    redis_replication_group = elasticache.CfnReplicationGroup(
        scope, "ClusterModeRedisReplicationGroup",
        replication_group_description="Cluster mode Redis replication group",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_node_groups=2,
        replicas_per_node_group=1,
        cluster_mode="enabled",
    )
    return redis_replication_group


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a Redis Global Datastore with default port
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    primary_replication_group = elasticache.CfnReplicationGroup(
        scope, "PrimaryRedisReplicationGroup",
        replication_group_description="Primary Redis replication group",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_clusters=2,
        automatic_failover_enabled=True,
    )
    
    global_datastore = elasticache.CfnGlobalReplicationGroup(
        scope, "RedisGlobalDatastore",
        global_replication_group_id_suffix="global-datastore",
        primary_replication_group_id=primary_replication_group.ref,
    )
    return global_datastore


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a Redis cluster with snapshot import but default port
    # ruleid: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithSnapshotImport",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        snapshot_name="redis-snapshot-001",
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a Redis cluster with custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterCustomPort",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        port=6380,  # Using non-default port
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating a Memcached cluster with custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    memcached_cluster = elasticache.CfnCacheCluster(
        scope, "MemcachedClusterCustomPort",
        cache_node_type="cache.t3.micro",
        engine="memcached",
        num_cache_nodes=2,
        port=11212,  # Using non-default port
    )
    return memcached_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating a Redis replication group with custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    redis_replication_group = elasticache.CfnReplicationGroup(
        scope, "RedisReplicationGroupCustomPort",
        replication_group_description="Redis replication group with custom port",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_clusters=2,
        port=6381,  # Using non-default port
    )
    return redis_replication_group


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a Redis cluster with custom port and explicitly setting engine version
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithVersionCustomPort",
        cache_node_type="cache.t3.micro",
        engine="redis",
        engine_version="6.2",
        num_cache_nodes=1,
        port=6382,  # Using non-default port
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a Redis cluster with custom port and additional configurations
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithConfigCustomPort",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        auto_minor_version_upgrade=True,
        snapshot_retention_limit=5,
        port=6383,  # Using non-default port
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a Redis serverless cache with custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    redis_serverless = elasticache.CfnServerlessCache(
        scope, "RedisServerlessCacheCustomPort",
        engine="redis",
        serverless_cache_name="my-redis-serverless",
        endpoint=elasticache.CfnServerlessCache.EndpointProperty(
            port=6384  # Using non-default port
        )
    )
    return redis_serverless


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a Redis cluster using L2 construct with custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    subnet_group = elasticache.CfnSubnetGroup(
        scope, "RedisSubnetGroupCustomPort",
        description="Subnet group for Redis cluster",
        subnet_ids=["subnet-12345", "subnet-67890"]
    )
    
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithSubnetGroupCustomPort",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        cache_subnet_group_name=subnet_group.ref,
        port=6385,  # Using non-default port
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a Redis replication group with multi-AZ and custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    redis_replication_group = elasticache.CfnReplicationGroup(
        scope, "MultiAZRedisReplicationGroupCustomPort",
        replication_group_description="Multi-AZ Redis replication group with custom port",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_clusters=2,
        automatic_failover_enabled=True,
        multi_az_enabled=True,
        port=6386,  # Using non-default port
    )
    return redis_replication_group


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a Redis cluster with encryption and custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "EncryptedRedisClusterCustomPort",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        engine_version="6.x",
        at_rest_encryption_enabled=True,
        transit_encryption_enabled=True,
        port=6387,  # Using non-default port
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a Redis cluster with parameter group and custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    parameter_group = elasticache.CfnParameterGroup(
        scope, "RedisParameterGroupCustomPort",
        cache_parameter_group_family="redis6.x",
        description="Custom Redis parameter group",
        properties={
            "maxmemory-policy": "volatile-lru"
        }
    )
    
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithParamGroupCustomPort",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        cache_parameter_group_name=parameter_group.ref,
        port=6388,  # Using non-default port
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a Redis cluster with security group and custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithSecurityGroupCustomPort",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        vpc_security_group_ids=["sg-12345"],
        port=6389,  # Using non-default port
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a Redis cluster with tags and custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithTagsCustomPort",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        port=6390,  # Using non-default port
        tags=[
            cdk.CfnTag(key="Environment", value="Production"),
            cdk.CfnTag(key="Owner", value="DataTeam")
        ]
    )
    return redis_cluster


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a Redis replication group with cluster mode enabled and custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    redis_replication_group = elasticache.CfnReplicationGroup(
        scope, "ClusterModeRedisReplicationGroupCustomPort",
        replication_group_description="Cluster mode Redis replication group with custom port",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_node_groups=2,
        replicas_per_node_group=1,
        cluster_mode="enabled",
        port=6391,  # Using non-default port
    )
    return redis_replication_group


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a Redis Global Datastore with custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    primary_replication_group = elasticache.CfnReplicationGroup(
        scope, "PrimaryRedisReplicationGroupCustomPort",
        replication_group_description="Primary Redis replication group with custom port",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_clusters=2,
        automatic_failover_enabled=True,
        port=6392,  # Using non-default port
    )
    
    global_datastore = elasticache.CfnGlobalReplicationGroup(
        scope, "RedisGlobalDatastoreCustomPort",
        global_replication_group_id_suffix="global-datastore-custom",
        primary_replication_group_id=primary_replication_group.ref,
    )
    return global_datastore


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a Redis cluster with snapshot import and custom port
    # ok: python-cdk-elasticache-cluster-usage-of-default-port
    redis_cluster = elasticache.CfnCacheCluster(
        scope, "RedisClusterWithSnapshotImportCustomPort",
        cache_node_type="cache.t3.micro",
        engine="redis",
        num_cache_nodes=1,
        snapshot_name="redis-snapshot-001",
        port=6393,  # Using non-default port
    )
    return redis_cluster


# {/fact}

class ElastiCacheStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Example usage of the functions
        bad_case_1(self, "BadCase1")
        good_case_1(self, "GoodCase1")


app = cdk.App()
ElastiCacheStack(app, "ElastiCacheStack")
app.synth()