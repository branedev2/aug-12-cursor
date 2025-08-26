import aws_cdk as cdk
from aws_cdk import (
    aws_opensearchservice as opensearch,
    aws_logs as logs,
    Stack,
    Duration,
    RemovalPolicy,
)
from constructs import Construct

# True Positives (Vulnerable Code Examples)

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_1(scope: Construct):
    # Creating an OpenSearch domain without configuring any logs to CloudWatch
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain1",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        removal_policy=RemovalPolicy.DESTROY
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_2(scope: Construct):
    # Creating an OpenSearch domain with only audit logs but no slow logs
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain2",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        logging=opensearch.LoggingOptions(
            audit_log_enabled=True
        ),
        removal_policy=RemovalPolicy.DESTROY
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_3(scope: Construct):
    # Creating an OpenSearch domain with application logs but no slow logs
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain3",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        logging=opensearch.LoggingOptions(
            app_log_enabled=True
        ),
        removal_policy=RemovalPolicy.DESTROY
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_4(scope: Construct):
    # Creating an OpenSearch domain with explicit disabling of slow logs
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain4",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=False,
            slow_index_log_enabled=False
        ),
        removal_policy=RemovalPolicy.DESTROY
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_5(scope: Construct):
    # Creating an OpenSearch domain with only one type of slow log enabled
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain5",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=False
        ),
        removal_policy=RemovalPolicy.DESTROY
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_6(scope: Construct):
    # Creating an OpenSearch domain with minimal configuration
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain6",
        version=opensearch.EngineVersion.ELASTICSEARCH_7_10,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_7(scope: Construct):
    # Creating an OpenSearch domain with advanced configuration but no logs
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain7",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="r5.large.search",
            data_nodes=2
        ),
        ebs=opensearch.EbsOptions(
            volume_size=20,
            volume_type=cdk.aws_ec2.EbsDeviceVolumeType.GP3
        ),
        zone_awareness=opensearch.ZoneAwarenessConfig(
            enabled=True,
            availability_zone_count=2
        ),
        removal_policy=RemovalPolicy.DESTROY
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_8(scope: Construct):
    # Creating an OpenSearch domain with custom endpoint but no logs
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain8",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        custom_endpoint=opensearch.CustomEndpointOptions(
            domain_name="search.example.com"
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_9(scope: Construct):
    # Creating an OpenSearch domain with encryption but no logs
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain9",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        encryption_at_rest=opensearch.EncryptionAtRestOptions(
            enabled=True
        ),
        node_to_node_encryption=True
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_10(scope: Construct):
    # Creating an OpenSearch domain with fine-grained access control but no logs
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain10",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        fine_grained_access_control=opensearch.AdvancedSecurityOptions(
            master_user_name="admin",
            master_user_password=cdk.SecretValue.unsafe_plain_text("StrongPassword123!")
        ),
        enforce_https=True,
        node_to_node_encryption=True,
        encryption_at_rest=opensearch.EncryptionAtRestOptions(
            enabled=True
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_11(scope: Construct):
    # Creating an OpenSearch domain with only index logs but not search logs
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain11",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        logging=opensearch.LoggingOptions(
            slow_index_log_enabled=True,
            slow_search_log_enabled=False
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_12(scope: Construct):
    # Creating an OpenSearch domain with logging object but no slow logs enabled
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain12",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        logging=opensearch.LoggingOptions()
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_13(scope: Construct):
    # Creating an OpenSearch domain with VPC configuration but no logs
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    vpc = cdk.aws_ec2.Vpc(scope, "VPC")
    security_group = cdk.aws_ec2.SecurityGroup(scope, "SecurityGroup", vpc=vpc)
    
    domain = opensearch.Domain(
        scope, "Domain13",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        vpc=vpc,
        vpc_subnets=[cdk.aws_ec2.SubnetSelection(subnet_type=cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        security_groups=[security_group]
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_14(scope: Construct):
    # Creating an OpenSearch domain with advanced options but no logs
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain14",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        advanced_options={
            "rest.action.multi.allow_explicit_index": "true",
            "indices.fielddata.cache.size": "40"
        }
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_15(scope: Construct):
    # Creating an OpenSearch domain with UltraWarm nodes but no logs
    # ruleid: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain15",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="r5.large.search",
            data_nodes=2,
            warm_enabled=True,
            warm_count=2,
            warm_type="ultrawarm1.medium.search"
        )
    )
    return domain

# True Negatives (Secure Code Examples)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_1(scope: Construct):
    # Creating an OpenSearch domain with both slow logs enabled
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain1",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=True
        ),
        removal_policy=RemovalPolicy.DESTROY
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_2(scope: Construct):
    # Creating an OpenSearch domain with all logs enabled
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain2",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=True,
            app_log_enabled=True,
            audit_log_enabled=True
        ),
        removal_policy=RemovalPolicy.DESTROY
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_3(scope: Construct):
    # Creating an OpenSearch domain with slow logs and custom log groups
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    search_log_group = logs.LogGroup(scope, "SearchLogGroup", 
                                    retention=logs.RetentionDays.ONE_WEEK)
    index_log_group = logs.LogGroup(scope, "IndexLogGroup", 
                                   retention=logs.RetentionDays.ONE_WEEK)
    
    domain = opensearch.Domain(
        scope, "Domain3",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_search_log_group=search_log_group,
            slow_index_log_enabled=True,
            slow_index_log_group=index_log_group
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_4(scope: Construct):
    # Creating an OpenSearch domain with slow logs and VPC configuration
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    vpc = cdk.aws_ec2.Vpc(scope, "VPC")
    security_group = cdk.aws_ec2.SecurityGroup(scope, "SecurityGroup", vpc=vpc)
    
    domain = opensearch.Domain(
        scope, "Domain4",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        vpc=vpc,
        vpc_subnets=[cdk.aws_ec2.SubnetSelection(subnet_type=cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        security_groups=[security_group],
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=True
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_5(scope: Construct):
    # Creating an OpenSearch domain with slow logs and encryption
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain5",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        encryption_at_rest=opensearch.EncryptionAtRestOptions(
            enabled=True
        ),
        node_to_node_encryption=True,
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=True
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_6(scope: Construct):
    # Creating an OpenSearch domain with slow logs and fine-grained access control
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain6",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        fine_grained_access_control=opensearch.AdvancedSecurityOptions(
            master_user_name="admin",
            master_user_password=cdk.SecretValue.unsafe_plain_text("StrongPassword123!")
        ),
        enforce_https=True,
        node_to_node_encryption=True,
        encryption_at_rest=opensearch.EncryptionAtRestOptions(
            enabled=True
        ),
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=True
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_7(scope: Construct):
    # Creating an OpenSearch domain with slow logs and custom endpoint
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain7",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        custom_endpoint=opensearch.CustomEndpointOptions(
            domain_name="search.example.com"
        ),
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=True
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_8(scope: Construct):
    # Creating an OpenSearch domain with slow logs and advanced options
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain8",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        advanced_options={
            "rest.action.multi.allow_explicit_index": "true",
            "indices.fielddata.cache.size": "40"
        },
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=True
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_9(scope: Construct):
    # Creating an OpenSearch domain with slow logs and UltraWarm nodes
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain9",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="r5.large.search",
            data_nodes=2,
            warm_enabled=True,
            warm_count=2,
            warm_type="ultrawarm1.medium.search"
        ),
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=True
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_10(scope: Construct):
    # Creating an OpenSearch domain with slow logs and zone awareness
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain10",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="r5.large.search",
            data_nodes=2
        ),
        ebs=opensearch.EbsOptions(
            volume_size=20,
            volume_type=cdk.aws_ec2.EbsDeviceVolumeType.GP3
        ),
        zone_awareness=opensearch.ZoneAwarenessConfig(
            enabled=True,
            availability_zone_count=2
        ),
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=True
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_11(scope: Construct):
    # Creating an OpenSearch domain with slow logs and custom log retention
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    search_log_group = logs.LogGroup(scope, "SearchLogGroup", 
                                    retention=logs.RetentionDays.THREE_MONTHS)
    index_log_group = logs.LogGroup(scope, "IndexLogGroup", 
                                   retention=logs.RetentionDays.THREE_MONTHS)
    
    domain = opensearch.Domain(
        scope, "Domain11",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_search_log_group=search_log_group,
            slow_index_log_enabled=True,
            slow_index_log_group=index_log_group
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_12(scope: Construct):
    # Creating an OpenSearch domain with slow logs and all other logs
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    app_log_group = logs.LogGroup(scope, "AppLogGroup")
    audit_log_group = logs.LogGroup(scope, "AuditLogGroup")
    search_log_group = logs.LogGroup(scope, "SearchLogGroup")
    index_log_group = logs.LogGroup(scope, "IndexLogGroup")
    
    domain = opensearch.Domain(
        scope, "Domain12",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        logging=opensearch.LoggingOptions(
            app_log_enabled=True,
            app_log_group=app_log_group,
            audit_log_enabled=True,
            audit_log_group=audit_log_group,
            slow_search_log_enabled=True,
            slow_search_log_group=search_log_group,
            slow_index_log_enabled=True,
            slow_index_log_group=index_log_group
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_13(scope: Construct):
    # Creating an OpenSearch domain with slow logs and dedicated master nodes
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain13",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="r5.large.search",
            data_nodes=3,
            master_nodes=3,
            master_node_instance_type="c5.large.search"
        ),
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=True
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_14(scope: Construct):
    # Creating an OpenSearch domain with slow logs and automated snapshot configuration
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain14",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        automated_snapshot_start_hour=3,
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=True
        )
    )
    return domain

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_15(scope: Construct):
    # Creating an OpenSearch domain with slow logs and older Elasticsearch version
    # ok: python-cdk-open-search-slow-logs-to-cloud-watch
    domain = opensearch.Domain(
        scope, "Domain15",
        version=opensearch.EngineVersion.ELASTICSEARCH_7_10,
        capacity=opensearch.CapacityConfig(
            data_node_instance_type="t3.small.search",
            data_nodes=1
        ),
        logging=opensearch.LoggingOptions(
            slow_search_log_enabled=True,
            slow_index_log_enabled=True
        )
    )
    return domain
# {/fact}