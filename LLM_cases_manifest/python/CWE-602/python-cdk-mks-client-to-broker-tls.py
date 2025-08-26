import aws_cdk as cdk
from aws_cdk import (
    aws_msk as msk,
    aws_ec2 as ec2,
    aws_kms as kms,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy,
)
from constructs import Construct


# True Positives (Vulnerable Code)

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating MSK cluster without TLS for client-broker communication
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="my-kafka-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.PLAINTEXT
        )
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating MSK cluster with explicit PLAINTEXT setting
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="kafka-cluster-plaintext",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit={
            "client_broker": msk.ClientBrokerEncryption.PLAINTEXT,
            "in_cluster": True
        }
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating MSK cluster with dictionary notation and PLAINTEXT
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="insecure-kafka-cluster",
        kafka_version=msk.KafkaVersion.V2_6_2,
        vpc=vpc,
        encryption_in_transit=dict(
            client_broker=msk.ClientBrokerEncryption.PLAINTEXT,
            in_cluster=True
        )
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating MSK cluster with variable configuration but still PLAINTEXT
    vpc = ec2.Vpc(scope, "VPC")
    encryption_config = msk.EncryptionInTransitConfig(
        client_broker=msk.ClientBrokerEncryption.PLAINTEXT,
        in_cluster=True
    )
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="variable-config-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=encryption_config
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating MSK cluster with PLAINTEXT in a function
    vpc = ec2.Vpc(scope, "VPC")
    
    def get_encryption_config():
        return msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.PLAINTEXT,
            in_cluster=True
        )
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="function-config-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=get_encryption_config()
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating MSK cluster with conditional PLAINTEXT
    vpc = ec2.Vpc(scope, "VPC")
    use_tls = False
    
    encryption_config = msk.EncryptionInTransitConfig(
        client_broker=msk.ClientBrokerEncryption.TLS if use_tls else msk.ClientBrokerEncryption.PLAINTEXT,
        in_cluster=True
    )
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="conditional-config-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=encryption_config
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating MSK cluster with PLAINTEXT and other configurations
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="complex-config-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.PLAINTEXT,
            in_cluster=True
        ),
        monitoring=msk.MonitoringConfiguration(
            cloudwatch_monitoring=msk.CloudWatchMonitoringConfiguration(
                log_group=None
            )
        )
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating MSK cluster with PLAINTEXT and KMS encryption at rest
    vpc = ec2.Vpc(scope, "VPC")
    key = kms.Key(scope, "KafkaKey")
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="mixed-security-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.PLAINTEXT,
            in_cluster=True
        ),
        encryption_at_rest=msk.EncryptionAtRestConfig(
            kms_key=key
        )
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating MSK cluster with string literal for PLAINTEXT
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.CfnCluster(scope, "MyCluster",
        cluster_name="cfn-cluster",
        kafka_version="2.8.1",
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": [subnet.subnet_id for subnet in vpc.private_subnets]
        },
        encryption_info={
            "encryption_in_transit": {
                "client_broker": "PLAINTEXT",
                "in_cluster": True
            }
        }
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating MSK cluster with default config which doesn't specify TLS
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="default-config-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        # No encryption_in_transit specified, which defaults to PLAINTEXT
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating MSK cluster with PLAINTEXT and custom configuration
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="custom-config-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.PLAINTEXT,
            in_cluster=True
        ),
        configuration_info=msk.ConfigurationInfo(
            arn="arn:aws:kafka:us-east-1:123456789012:configuration/example-configuration-name/abcdabcd-1234-abcd-1234-abcd123e8e8e-1",
            revision=1
        )
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating MSK cluster with PLAINTEXT and setting broker count
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="multi-broker-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.PLAINTEXT,
            in_cluster=True
        ),
        broker_node_group_info=msk.BrokerNodeGroupInfo(
            instance_type=ec2.InstanceType("kafka.m5.large"),
            client_subnets=[subnet for subnet in vpc.private_subnets],
            broker_count=3
        )
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating MSK cluster with PLAINTEXT and setting removal policy
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="removable-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.PLAINTEXT,
            in_cluster=True
        ),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating MSK cluster with PLAINTEXT and setting storage
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="storage-optimized-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.PLAINTEXT,
            in_cluster=True
        ),
        storage_mode=msk.StorageMode.LOCAL
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating MSK cluster with PLAINTEXT and setting outputs
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="output-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.PLAINTEXT,
            in_cluster=True
        )
    )
    
    CfnOutput(scope, "BootstrapBrokers", value=cluster.bootstrap_brokers)
    return cluster


# True Negatives (Secure Code)

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating MSK cluster with TLS for client-broker communication
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-kafka-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.TLS,
            in_cluster=True
        )
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating MSK cluster with TLS using dictionary notation
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-dict-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit={
            "client_broker": msk.ClientBrokerEncryption.TLS,
            "in_cluster": True
        }
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating MSK cluster with TLS using variable configuration
    vpc = ec2.Vpc(scope, "VPC")
    encryption_config = msk.EncryptionInTransitConfig(
        client_broker=msk.ClientBrokerEncryption.TLS,
        in_cluster=True
    )
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-var-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=encryption_config
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating MSK cluster with TLS in a function
    vpc = ec2.Vpc(scope, "VPC")
    
    def get_secure_encryption_config():
        return msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.TLS,
            in_cluster=True
        )
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-func-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=get_secure_encryption_config()
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating MSK cluster with conditional TLS (always true)
    vpc = ec2.Vpc(scope, "VPC")
    use_tls = True
    
    encryption_config = msk.EncryptionInTransitConfig(
        client_broker=msk.ClientBrokerEncryption.TLS if use_tls else msk.ClientBrokerEncryption.PLAINTEXT,
        in_cluster=True
    )
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-conditional-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=encryption_config
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating MSK cluster with TLS and other configurations
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-complex-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.TLS,
            in_cluster=True
        ),
        monitoring=msk.MonitoringConfiguration(
            cloudwatch_monitoring=msk.CloudWatchMonitoringConfiguration(
                log_group=None
            )
        )
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating MSK cluster with TLS and KMS encryption at rest
    vpc = ec2.Vpc(scope, "VPC")
    key = kms.Key(scope, "KafkaKey")
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-kms-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.TLS,
            in_cluster=True
        ),
        encryption_at_rest=msk.EncryptionAtRestConfig(
            kms_key=key
        )
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating MSK cluster with string literal for TLS
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.CfnCluster(scope, "MyCluster",
        cluster_name="secure-cfn-cluster",
        kafka_version="2.8.1",
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": [subnet.subnet_id for subnet in vpc.private_subnets]
        },
        encryption_info={
            "encryption_in_transit": {
                "client_broker": "TLS",
                "in_cluster": True
            }
        }
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating MSK cluster with TLS_PLAINTEXT (which allows both but doesn't enforce TLS only)
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="mixed-mode-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.TLS,  # TLS only, not TLS_PLAINTEXT
            in_cluster=True
        )
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating MSK cluster with TLS and custom configuration
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-custom-config-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.TLS,
            in_cluster=True
        ),
        configuration_info=msk.ConfigurationInfo(
            arn="arn:aws:kafka:us-east-1:123456789012:configuration/example-configuration-name/abcdabcd-1234-abcd-1234-abcd123e8e8e-1",
            revision=1
        )
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating MSK cluster with TLS and setting broker count
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-multi-broker-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.TLS,
            in_cluster=True
        ),
        broker_node_group_info=msk.BrokerNodeGroupInfo(
            instance_type=ec2.InstanceType("kafka.m5.large"),
            client_subnets=[subnet for subnet in vpc.private_subnets],
            broker_count=3
        )
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating MSK cluster with TLS and setting removal policy
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-removable-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.TLS,
            in_cluster=True
        ),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating MSK cluster with TLS and setting storage
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-storage-optimized-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.TLS,
            in_cluster=True
        ),
        storage_mode=msk.StorageMode.LOCAL
    )
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating MSK cluster with TLS and setting outputs
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-output-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.TLS,
            in_cluster=True
        )
    )
    
    CfnOutput(scope, "BootstrapBrokersTls", value=cluster.bootstrap_brokers_tls)
    return cluster

# {/fact}

# {fact rule=client-side-enforcement-of-server-side-security@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating MSK cluster with explicit TLS setting and multiple outputs
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-mks-client-to-broker-tls
    cluster = msk.Cluster(scope, "MyCluster",
        cluster_name="secure-complete-cluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.TLS,
            in_cluster=True
        )
    )
    
    CfnOutput(scope, "BootstrapBrokersTls", value=cluster.bootstrap_brokers_tls)
    CfnOutput(scope, "ZookeeperConnectionString", value=cluster.zookeeper_connection_string)
    return cluster
# {/fact}