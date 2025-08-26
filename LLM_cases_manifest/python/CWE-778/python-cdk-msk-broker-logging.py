import aws_cdk as cdk
from aws_cdk import (
    aws_msk,
    Stack,
    CfnOutput,
    RemovalPolicy,
    Duration,
)
from constructs import Construct
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_logs as logs
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_kms as kms
import aws_cdk.aws_kinesis as kinesis
import aws_cdk.aws_iam as iam
import os

# True Positive Examples (Vulnerable/Insecure Code)

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # MSK cluster with no logging configuration at all
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterNoLogging",
        cluster_name="msk-cluster-no-logging",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # MSK cluster with empty logging_info property
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterEmptyLogging",
        cluster_name="msk-cluster-empty-logging",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # MSK cluster with broker_logs property but no actual logging destinations
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterEmptyBrokerLogs",
        cluster_name="msk-cluster-empty-broker-logs",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # MSK cluster with CloudWatch logs but disabled
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterDisabledCloudWatchLogs",
        cluster_name="msk-cluster-disabled-cloudwatch",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=aws_msk.CfnCluster.CloudWatchLogsProperty(
                    enabled=False,
                    log_group="msk-log-group"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # MSK cluster with S3 logs but disabled
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterDisabledS3Logs",
        cluster_name="msk-cluster-disabled-s3",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                s3=aws_msk.CfnCluster.S3Property(
                    enabled=False,
                    bucket="msk-logs-bucket",
                    prefix="logs/"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # MSK cluster with Firehose logs but disabled
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterDisabledFirehoseLogs",
        cluster_name="msk-cluster-disabled-firehose",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                firehose=aws_msk.CfnCluster.FirehoseProperty(
                    enabled=False,
                    delivery_stream="msk-delivery-stream"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # MSK cluster with all logging destinations but all disabled
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterAllLogsDisabled",
        cluster_name="msk-cluster-all-logs-disabled",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=aws_msk.CfnCluster.CloudWatchLogsProperty(
                    enabled=False,
                    log_group="msk-log-group"
                ),
                s3=aws_msk.CfnCluster.S3Property(
                    enabled=False,
                    bucket="msk-logs-bucket",
                    prefix="logs/"
                ),
                firehose=aws_msk.CfnCluster.FirehoseProperty(
                    enabled=False,
                    delivery_stream="msk-delivery-stream"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # MSK cluster using L2 construct without logging
    # ruleid: python-cdk-msk-broker-logging
    vpc = ec2.Vpc.from_lookup(scope, "VPC", vpc_id="vpc-12345")
    security_group = ec2.SecurityGroup(scope, "MSKSecurityGroup", vpc=vpc)
    
    msk_cluster = aws_msk.Cluster(
        scope,
        "MskClusterL2NoLogging",
        cluster_name="msk-cluster-l2-no-logging",
        kafka_version=aws_msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        instance_type=ec2.InstanceType("kafka.m5.large"),
        security_groups=[security_group],
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # MSK cluster with CloudWatch logs property but missing enabled flag
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterMissingEnabledFlag",
        cluster_name="msk-cluster-missing-enabled",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=aws_msk.CfnCluster.CloudWatchLogsProperty(
                    log_group="msk-log-group"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # MSK cluster with CloudWatch logs enabled but missing log group
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterMissingLogGroup",
        cluster_name="msk-cluster-missing-log-group",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=aws_msk.CfnCluster.CloudWatchLogsProperty(
                    enabled=True,
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # MSK cluster with S3 logs enabled but missing bucket
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterMissingS3Bucket",
        cluster_name="msk-cluster-missing-s3-bucket",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                s3=aws_msk.CfnCluster.S3Property(
                    enabled=True,
                    prefix="logs/"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # MSK cluster with Firehose logs enabled but missing delivery stream
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterMissingDeliveryStream",
        cluster_name="msk-cluster-missing-delivery-stream",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                firehose=aws_msk.CfnCluster.FirehoseProperty(
                    enabled=True,
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # MSK cluster using L2 construct with logging level set to NONE
    # ruleid: python-cdk-msk-broker-logging
    vpc = ec2.Vpc.from_lookup(scope, "VPC", vpc_id="vpc-12345")
    security_group = ec2.SecurityGroup(scope, "MSKSecurityGroup", vpc=vpc)
    
    msk_cluster = aws_msk.Cluster(
        scope,
        "MskClusterL2LoggingNone",
        cluster_name="msk-cluster-l2-logging-none",
        kafka_version=aws_msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        instance_type=ec2.InstanceType("kafka.m5.large"),
        security_groups=[security_group],
        logging=aws_msk.ClusterLoggingV2.none(),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # MSK cluster with logging_info but no broker_logs property
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterNoBrokerLogs",
        cluster_name="msk-cluster-no-broker-logs",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            # Missing broker_logs property
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # MSK cluster created with minimal configuration and no logging
    # ruleid: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MinimalMskCluster",
        cluster_name="minimal-msk-cluster",
        kafka_version="3.3.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.t3.small",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        # No logging_info property
    )
    return msk_cluster

# True Negative Examples (Secure/Safe Code)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # MSK cluster with CloudWatch logs enabled
    # ok: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterCloudWatchLogsEnabled",
        cluster_name="msk-cluster-cloudwatch-enabled",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=aws_msk.CfnCluster.CloudWatchLogsProperty(
                    enabled=True,
                    log_group="msk-log-group"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # MSK cluster with S3 logs enabled
    # ok: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterS3LogsEnabled",
        cluster_name="msk-cluster-s3-enabled",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                s3=aws_msk.CfnCluster.S3Property(
                    enabled=True,
                    bucket="msk-logs-bucket",
                    prefix="logs/"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # MSK cluster with Firehose logs enabled
    # ok: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterFirehoseLogsEnabled",
        cluster_name="msk-cluster-firehose-enabled",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                firehose=aws_msk.CfnCluster.FirehoseProperty(
                    enabled=True,
                    delivery_stream="msk-delivery-stream"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # MSK cluster with all logging destinations enabled
    # ok: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterAllLogsEnabled",
        cluster_name="msk-cluster-all-logs-enabled",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=aws_msk.CfnCluster.CloudWatchLogsProperty(
                    enabled=True,
                    log_group="msk-log-group"
                ),
                s3=aws_msk.CfnCluster.S3Property(
                    enabled=True,
                    bucket="msk-logs-bucket",
                    prefix="logs/"
                ),
                firehose=aws_msk.CfnCluster.FirehoseProperty(
                    enabled=True,
                    delivery_stream="msk-delivery-stream"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # MSK cluster with CloudWatch logs enabled and S3/Firehose disabled
    # ok: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterCloudWatchEnabledOthersDisabled",
        cluster_name="msk-cluster-mixed-logging",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=aws_msk.CfnCluster.CloudWatchLogsProperty(
                    enabled=True,
                    log_group="msk-log-group"
                ),
                s3=aws_msk.CfnCluster.S3Property(
                    enabled=False,
                    bucket="msk-logs-bucket",
                    prefix="logs/"
                ),
                firehose=aws_msk.CfnCluster.FirehoseProperty(
                    enabled=False,
                    delivery_stream="msk-delivery-stream"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # MSK cluster with S3 logs enabled and CloudWatch/Firehose disabled
    # ok: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterS3EnabledOthersDisabled",
        cluster_name="msk-cluster-s3-only",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=aws_msk.CfnCluster.CloudWatchLogsProperty(
                    enabled=False,
                    log_group="msk-log-group"
                ),
                s3=aws_msk.CfnCluster.S3Property(
                    enabled=True,
                    bucket="msk-logs-bucket",
                    prefix="logs/"
                ),
                firehose=aws_msk.CfnCluster.FirehoseProperty(
                    enabled=False,
                    delivery_stream="msk-delivery-stream"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # MSK cluster with Firehose logs enabled and CloudWatch/S3 disabled
    # ok: python-cdk-msk-broker-logging
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterFirehoseEnabledOthersDisabled",
        cluster_name="msk-cluster-firehose-only",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=aws_msk.CfnCluster.CloudWatchLogsProperty(
                    enabled=False,
                    log_group="msk-log-group"
                ),
                s3=aws_msk.CfnCluster.S3Property(
                    enabled=False,
                    bucket="msk-logs-bucket",
                    prefix="logs/"
                ),
                firehose=aws_msk.CfnCluster.FirehoseProperty(
                    enabled=True,
                    delivery_stream="msk-delivery-stream"
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # MSK cluster using L2 construct with CloudWatch logs enabled
    # ok: python-cdk-msk-broker-logging
    vpc = ec2.Vpc.from_lookup(scope, "VPC", vpc_id="vpc-12345")
    security_group = ec2.SecurityGroup(scope, "MSKSecurityGroup", vpc=vpc)
    log_group = logs.LogGroup(scope, "MSKLogGroup")
    
    msk_cluster = aws_msk.Cluster(
        scope,
        "MskClusterL2CloudWatchEnabled",
        cluster_name="msk-cluster-l2-cloudwatch",
        kafka_version=aws_msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        instance_type=ec2.InstanceType("kafka.m5.large"),
        security_groups=[security_group],
        logging=aws_msk.ClusterLoggingV2.cloud_watch(log_group=log_group),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # MSK cluster using L2 construct with S3 logs enabled
    # ok: python-cdk-msk-broker-logging
    vpc = ec2.Vpc.from_lookup(scope, "VPC", vpc_id="vpc-12345")
    security_group = ec2.SecurityGroup(scope, "MSKSecurityGroup", vpc=vpc)
    bucket = s3.Bucket(scope, "MSKLogsBucket")
    
    msk_cluster = aws_msk.Cluster(
        scope,
        "MskClusterL2S3Enabled",
        cluster_name="msk-cluster-l2-s3",
        kafka_version=aws_msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        instance_type=ec2.InstanceType("kafka.m5.large"),
        security_groups=[security_group],
        logging=aws_msk.ClusterLoggingV2.s3(bucket=bucket, prefix="msk-logs/"),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # MSK cluster using L2 construct with Firehose logs enabled
    # ok: python-cdk-msk-broker-logging
    vpc = ec2.Vpc.from_lookup(scope, "VPC", vpc_id="vpc-12345")
    security_group = ec2.SecurityGroup(scope, "MSKSecurityGroup", vpc=vpc)
    delivery_stream = kinesis.CfnDeliveryStream(
        scope, "MSKDeliveryStream", 
        delivery_stream_name="msk-delivery-stream",
        s3_destination_configuration=kinesis.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn="arn:aws:s3:::msk-logs-bucket",
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role",
        )
    )
    
    msk_cluster = aws_msk.Cluster(
        scope,
        "MskClusterL2FirehoseEnabled",
        cluster_name="msk-cluster-l2-firehose",
        kafka_version=aws_msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        instance_type=ec2.InstanceType("kafka.m5.large"),
        security_groups=[security_group],
        logging=aws_msk.ClusterLoggingV2.firehose(delivery_stream_name="msk-delivery-stream"),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # MSK cluster using L2 construct with all logs enabled
    # ok: python-cdk-msk-broker-logging
    vpc = ec2.Vpc.from_lookup(scope, "VPC", vpc_id="vpc-12345")
    security_group = ec2.SecurityGroup(scope, "MSKSecurityGroup", vpc=vpc)
    log_group = logs.LogGroup(scope, "MSKLogGroup")
    bucket = s3.Bucket(scope, "MSKLogsBucket")
    delivery_stream = kinesis.CfnDeliveryStream(
        scope, "MSKDeliveryStream", 
        delivery_stream_name="msk-delivery-stream",
        s3_destination_configuration=kinesis.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn="arn:aws:s3:::msk-logs-bucket",
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role",
        )
    )
    
    msk_cluster = aws_msk.Cluster(
        scope,
        "MskClusterL2AllLogsEnabled",
        cluster_name="msk-cluster-l2-all-logs",
        kafka_version=aws_msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        instance_type=ec2.InstanceType("kafka.m5.large"),
        security_groups=[security_group],
        logging=aws_msk.ClusterLoggingV2.all(
            cloud_watch_log_group=log_group,
            s3_bucket=bucket,
            s3_prefix="msk-logs/",
            firehose_delivery_stream_name="msk-delivery-stream"
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # MSK cluster with CloudWatch logs enabled using variables
    # ok: python-cdk-msk-broker-logging
    log_group_name = "msk-log-group"
    logging_enabled = True
    
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterVariableLogging",
        cluster_name="msk-cluster-variable-logging",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=aws_msk.CfnCluster.CloudWatchLogsProperty(
                    enabled=logging_enabled,
                    log_group=log_group_name
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # MSK cluster with CloudWatch logs enabled using environment variables
    # ok: python-cdk-msk-broker-logging
    log_group_name = os.environ.get("MSK_LOG_GROUP", "msk-log-group")
    
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterEnvVarLogging",
        cluster_name="msk-cluster-env-var-logging",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=aws_msk.CfnCluster.CloudWatchLogsProperty(
                    enabled=True,
                    log_group=log_group_name
                ),
            ),
        ),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # MSK cluster with CloudWatch logs enabled using a function
    # ok: python-cdk-msk-broker-logging
    def get_logging_config():
        return aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=aws_msk.CfnCluster.CloudWatchLogsProperty(
                    enabled=True,
                    log_group="msk-log-group"
                ),
            ),
        )
    
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterFunctionLogging",
        cluster_name="msk-cluster-function-logging",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=get_logging_config(),
    )
    return msk_cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # MSK cluster with CloudWatch logs enabled with conditional logic
    # ok: python-cdk-msk-broker-logging
    is_prod = True
    
    cloud_watch_config = aws_msk.CfnCluster.CloudWatchLogsProperty(
        enabled=True,
        log_group="msk-log-group-prod" if is_prod else "msk-log-group-dev"
    )
    
    msk_cluster = aws_msk.CfnCluster(
        scope,
        "MskClusterConditionalLogging",
        cluster_name="msk-cluster-conditional-logging",
        kafka_version="2.8.1",
        number_of_broker_nodes=3 if is_prod else 1,
        broker_node_group_info=aws_msk.CfnCluster.BrokerNodeGroupInfoProperty(
            instance_type="kafka.m5.large" if is_prod else "kafka.t3.small",
            client_subnets=["subnet-1", "subnet-2", "subnet-3"],
            security_groups=["sg-1"],
        ),
        logging_info=aws_msk.CfnCluster.LoggingInfoProperty(
            broker_logs=aws_msk.CfnCluster.BrokerLogsProperty(
                cloud_watch_logs=cloud_watch_config,
            ),
        ),
    )
    return msk_cluster
# {/fact}