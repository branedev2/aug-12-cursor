import aws_cdk as cdk
from aws_cdk import (
    aws_elasticache as elasticache,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy,
)
from constructs import Construct


# True Positive Examples (Vulnerable Code)

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_1():
    # Creating a Redis cluster without authentication
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis cluster without auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                automatic_failover_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_2():
    # Creating a Redis cluster with explicit auth disabled
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis cluster with auth disabled",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                automatic_failover_enabled=True,
                auth_token=None
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_3():
    # Creating a Redis cluster with empty auth token
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis cluster with empty auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                automatic_failover_enabled=True,
                auth_token=""
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_4():
    # Creating a Redis serverless cache without authentication
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_serverless = elasticache.CfnServerlessCache(
                self, "RedisServerless",
                engine="redis",
                serverless_cache_name="my-redis-serverless"
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_5():
    # Creating a Redis cluster with transit encryption but no auth token
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with encryption but no auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_6():
    # Creating a Redis cluster with complex configuration but missing auth
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Complex Redis config without auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=3,
                automatic_failover_enabled=True,
                multi_az_enabled=True,
                port=6379,
                snapshot_retention_limit=5,
                snapshot_window="00:00-01:00"
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_7():
    # Creating a Redis cluster with parameter group but no auth
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            parameter_group = elasticache.CfnParameterGroup(
                self, "RedisParams",
                cache_parameter_group_family="redis6.x",
                description="Redis parameter group",
                properties={
                    "maxmemory-policy": "volatile-lru"
                }
            )
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with params but no auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                cache_parameter_group_name=parameter_group.ref
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_8():
    # Creating a Redis cluster with subnet group but no auth
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # Create a subnet group
            subnet_group = elasticache.CfnSubnetGroup(
                self, "RedisSubnetGroup",
                description="Redis subnet group",
                subnet_ids=["subnet-12345", "subnet-67890"]
            )
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with subnet group but no auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                cache_subnet_group_name=subnet_group.ref
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_9():
    # Creating a Redis cluster with security group but no auth
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with security group but no auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                security_group_ids=["sg-12345"]
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_10():
    # Creating a Redis cluster with at-rest encryption but no auth
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with at-rest encryption but no auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                at_rest_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_11():
    # Creating a Redis cluster with tags but no auth
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with tags but no auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                tags=[
                    cdk.CfnTag(key="Environment", value="Production"),
                    cdk.CfnTag(key="Owner", value="DataTeam")
                ]
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_12():
    # Creating a Redis cluster with maintenance window but no auth
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with maintenance window but no auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                preferred_maintenance_window="sun:05:00-sun:06:00"
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_13():
    # Creating a Redis cluster with node type specified as variable but no auth
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            node_type = "cache.t3.micro"
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with variable node type but no auth",
                engine="redis",
                cache_node_type=node_type,
                num_cache_clusters=2
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_14():
    # Creating a Redis cluster with conditional configuration but no auth
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            is_prod = True
            num_clusters = 3 if is_prod else 2
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with conditional config but no auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=num_clusters,
                automatic_failover_enabled=is_prod
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_15():
    # Creating a Redis cluster using a helper function but no auth
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            def create_redis_config():
                return {
                    "replication_group_description": "Redis from helper function but no auth",
                    "engine": "redis",
                    "cache_node_type": "cache.t3.micro",
                    "num_cache_clusters": 2
                }
            
            config = create_redis_config()
            
            # ruleid: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                **config
            )


# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_1():
    # Creating a Redis cluster with authentication
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis cluster with auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                automatic_failover_enabled=True,
                auth_token="MySecureAuthToken123!",
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_2():
    # Creating a Redis cluster with authentication from parameter
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            auth_token_param = cdk.CfnParameter(
                self, "RedisAuthToken",
                type="String",
                description="Auth token for Redis",
                no_echo=True
            )
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis cluster with auth from parameter",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                automatic_failover_enabled=True,
                auth_token=auth_token_param.value_as_string,
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_3():
    # Creating a Redis cluster with authentication from SSM parameter
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            from aws_cdk import aws_ssm as ssm
            
            auth_token = ssm.StringParameter.value_for_string_parameter(
                self, "/redis/auth-token"
            )
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis cluster with auth from SSM",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                automatic_failover_enabled=True,
                auth_token=auth_token,
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_4():
    # Creating a Redis serverless cache with authentication
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_serverless = elasticache.CfnServerlessCache(
                self, "RedisServerless",
                engine="redis",
                serverless_cache_name="my-redis-serverless",
                user_group_id="my-user-group"  # User group with authentication
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_5():
    # Creating a Redis cluster with authentication and complex configuration
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Complex Redis config with auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=3,
                automatic_failover_enabled=True,
                multi_az_enabled=True,
                port=6379,
                snapshot_retention_limit=5,
                snapshot_window="00:00-01:00",
                auth_token="SecurePassword123!",
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_6():
    # Creating a Redis cluster with authentication and parameter group
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            parameter_group = elasticache.CfnParameterGroup(
                self, "RedisParams",
                cache_parameter_group_family="redis6.x",
                description="Redis parameter group",
                properties={
                    "maxmemory-policy": "volatile-lru"
                }
            )
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with params and auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                cache_parameter_group_name=parameter_group.ref,
                auth_token="StrongAuthToken456!",
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_7():
    # Creating a Redis cluster with authentication and subnet group
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # Create a subnet group
            subnet_group = elasticache.CfnSubnetGroup(
                self, "RedisSubnetGroup",
                description="Redis subnet group",
                subnet_ids=["subnet-12345", "subnet-67890"]
            )
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with subnet group and auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                cache_subnet_group_name=subnet_group.ref,
                auth_token="ComplexAuthToken789!",
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_8():
    # Creating a Redis cluster with authentication and security group
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with security group and auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                security_group_ids=["sg-12345"],
                auth_token="SecureToken123!",
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_9():
    # Creating a Redis cluster with authentication and at-rest encryption
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with at-rest encryption and auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                at_rest_encryption_enabled=True,
                auth_token="VerySecureToken456!",
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_10():
    # Creating a Redis cluster with authentication and tags
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with tags and auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                tags=[
                    cdk.CfnTag(key="Environment", value="Production"),
                    cdk.CfnTag(key="Owner", value="DataTeam")
                ],
                auth_token="SuperSecureToken789!",
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_11():
    # Creating a Redis cluster with authentication and maintenance window
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with maintenance window and auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                preferred_maintenance_window="sun:05:00-sun:06:00",
                auth_token="MaintenanceSecureToken!",
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_12():
    # Creating a Redis cluster with authentication from Secrets Manager
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            from aws_cdk import aws_secretsmanager as secretsmanager
            
            redis_secret = secretsmanager.Secret(self, "RedisAuthSecret")
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with auth from Secrets Manager",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                auth_token=redis_secret.secret_value.to_string(),
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_13():
    # Creating a Redis cluster with authentication using a helper function
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            def create_redis_config():
                return {
                    "replication_group_description": "Redis from helper function with auth",
                    "engine": "redis",
                    "cache_node_type": "cache.t3.micro",
                    "num_cache_clusters": 2,
                    "auth_token": "HelperFunctionSecureToken!",
                    "transit_encryption_enabled": True
                }
            
            config = create_redis_config()
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                **config
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_14():
    # Creating a Redis cluster with authentication and conditional configuration
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            is_prod = True
            num_clusters = 3 if is_prod else 2
            auth_token = "StrongProdToken123!" if is_prod else "DevToken456!"
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with conditional config and auth",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=num_clusters,
                automatic_failover_enabled=is_prod,
                auth_token=auth_token,
                transit_encryption_enabled=True
            )


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_15():
    # Creating a Redis cluster with authentication from environment variable
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            import os
            
            # In a real scenario, this would be fetched from an environment variable
            # For this example, we'll simulate it
            auth_token = os.environ.get("REDIS_AUTH_TOKEN", "DefaultSecureToken!")
            
            # ok: python-cdk-elasticache-missing-redis-authorization
            redis_cluster = elasticache.CfnReplicationGroup(
                self, "RedisCluster",
                replication_group_description="Redis with auth from env var",
                engine="redis",
                cache_node_type="cache.t3.micro",
                num_cache_clusters=2,
                auth_token=auth_token,
                transit_encryption_enabled=True
            )
# {/fact}