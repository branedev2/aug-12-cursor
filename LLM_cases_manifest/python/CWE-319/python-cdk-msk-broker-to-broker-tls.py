import aws_cdk as cdk
from aws_cdk import (
    aws_msk as msk,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy,
)
from constructs import Construct


# True Positives (Vulnerable Code)

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_1():
    # Creating MSK cluster with inCluster TLS disabled
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info={
            "encryptionInTransit": {
                # ruleid: python-cdk-msk-broker-to-broker-tls
                "inCluster": False
            }
        }
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_2():
    # Creating MSK cluster with inCluster explicitly set to false
    cluster_props = {
        "clusterName": "MyMskCluster",
        "kafkaVersion": "2.8.1",
        "numberOfBrokerNodes": 3,
        "brokerNodeGroupInfo": {
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        "encryptionInfo": {
            "encryptionInTransit": {
                # ruleid: python-cdk-msk-broker-to-broker-tls
                "inCluster": False,
                "clientBroker": "TLS"
            }
        }
    }
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        **cluster_props
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_3():
    # Using a variable to set inCluster to False
    in_cluster_tls = False
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info={
            "encryptionInTransit": {
                # ruleid: python-cdk-msk-broker-to-broker-tls
                "inCluster": in_cluster_tls
            }
        }
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_4():
    # Creating MSK cluster with inCluster disabled in a class
    class MskClusterStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            msk.CfnCluster(
                self, "MskCluster",
                cluster_name="MyMskCluster",
                kafka_version="2.8.1",
                number_of_broker_nodes=3,
                broker_node_group_info={
                    "instanceType": "kafka.m5.large",
                    "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
                    "securityGroups": ["sg-1"]
                },
                encryption_info={
                    "encryptionInTransit": {
                        # ruleid: python-cdk-msk-broker-to-broker-tls
                        "inCluster": False
                    }
                }
            )
    
    app = cdk.App()
    stack = MskClusterStack(app, "MskClusterStack")
    return app


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_5():
    # Creating MSK cluster with encryption config in a separate dictionary
    encryption_config = {
        "encryptionInTransit": {
            # ruleid: python-cdk-msk-broker-to-broker-tls
            "inCluster": False,
            "clientBroker": "TLS"
        },
        "encryptionAtRest": {
            "dataVolumeKMSKeyId": "alias/aws/kafka"
        }
    }
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info=encryption_config
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_6():
    # Creating MSK cluster with conditional setting of inCluster to False
    use_tls = False
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info={
            "encryptionInTransit": {
                # ruleid: python-cdk-msk-broker-to-broker-tls
                "inCluster": use_tls
            }
        }
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_7():
    # Creating MSK cluster with inCluster disabled using a function
    def get_encryption_config():
        return {
            "encryptionInTransit": {
                "inCluster": False,
                "clientBroker": "TLS"
            }
        }
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        # ruleid: python-cdk-msk-broker-to-broker-tls
        encryption_info=get_encryption_config()
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_8():
    # Creating MSK cluster with inCluster disabled in a loop
    clusters = []
    for i in range(3):
        cluster = msk.CfnCluster(
            scope=Stack(None, f"MyStack{i}"),
            id=f"MskCluster{i}",
            cluster_name=f"MyMskCluster{i}",
            kafka_version="2.8.1",
            number_of_broker_nodes=3,
            broker_node_group_info={
                "instanceType": "kafka.m5.large",
                "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
                "securityGroups": ["sg-1"]
            },
            encryption_info={
                "encryptionInTransit": {
                    # ruleid: python-cdk-msk-broker-to-broker-tls
                    "inCluster": False
                }
            }
        )
        clusters.append(cluster)
    return clusters


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_9():
    # Creating MSK cluster with inCluster disabled using a dictionary comprehension
    regions = ["us-east-1", "us-west-2", "eu-west-1"]
    
    encryption_configs = {
        region: {
            "encryptionInTransit": {
                "inCluster": False,
                "clientBroker": "TLS"
            }
        } for region in regions
    }
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        # ruleid: python-cdk-msk-broker-to-broker-tls
        encryption_info=encryption_configs["us-east-1"]
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_10():
    # Creating MSK cluster with inCluster disabled using environment variables
    import os
    
    # Simulating environment variable
    os.environ["USE_TLS"] = "false"
    
    use_tls = os.environ["USE_TLS"].lower() == "true"
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info={
            "encryptionInTransit": {
                # ruleid: python-cdk-msk-broker-to-broker-tls
                "inCluster": use_tls
            }
        }
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_11():
    # Creating MSK cluster with inCluster disabled in a nested function
    def create_cluster_stack():
        def get_encryption_config():
            return {
                "encryptionInTransit": {
                    "inCluster": False
                }
            }
        
        return msk.CfnCluster(
            scope=Stack(None, "MyStack"),
            id="MskCluster",
            cluster_name="MyMskCluster",
            kafka_version="2.8.1",
            number_of_broker_nodes=3,
            broker_node_group_info={
                "instanceType": "kafka.m5.large",
                "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
                "securityGroups": ["sg-1"]
            },
            # ruleid: python-cdk-msk-broker-to-broker-tls
            encryption_info=get_encryption_config()
        )
    
    return create_cluster_stack()


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_12():
    # Creating MSK cluster with inCluster disabled using a class method
    class MskClusterFactory:
        @staticmethod
        def create_cluster(scope, id, name):
            return msk.CfnCluster(
                scope=scope,
                id=id,
                cluster_name=name,
                kafka_version="2.8.1",
                number_of_broker_nodes=3,
                broker_node_group_info={
                    "instanceType": "kafka.m5.large",
                    "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
                    "securityGroups": ["sg-1"]
                },
                encryption_info={
                    "encryptionInTransit": {
                        # ruleid: python-cdk-msk-broker-to-broker-tls
                        "inCluster": False
                    }
                }
            )
    
    stack = Stack(None, "MyStack")
    cluster = MskClusterFactory.create_cluster(stack, "MskCluster", "MyMskCluster")
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_13():
    # Creating MSK cluster with inCluster disabled using a ternary operator
    is_production = False
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info={
            "encryptionInTransit": {
                # ruleid: python-cdk-msk-broker-to-broker-tls
                "inCluster": True if is_production else False
            }
        }
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_14():
    # Creating MSK cluster with inCluster disabled using a dictionary
    config = {
        "cluster_name": "MyMskCluster",
        "kafka_version": "2.8.1",
        "number_of_broker_nodes": 3,
        "broker_node_group_info": {
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        "encryption_info": {
            "encryptionInTransit": {
                "inCluster": False
            }
        }
    }
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        # ruleid: python-cdk-msk-broker-to-broker-tls
        **config
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_15():
    # Creating MSK cluster with inCluster omitted (defaults to False)
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info={
            # ruleid: python-cdk-msk-broker-to-broker-tls
            "encryptionInTransit": {}  # inCluster defaults to False when omitted
        }
    )
    return cluster


# True Negatives (Secure Code)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_1():
    # Creating MSK cluster with inCluster TLS enabled
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info={
            "encryptionInTransit": {
                # ok: python-cdk-msk-broker-to-broker-tls
                "inCluster": True
            }
        }
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_2():
    # Creating MSK cluster with inCluster explicitly set to true
    cluster_props = {
        "clusterName": "MyMskCluster",
        "kafkaVersion": "2.8.1",
        "numberOfBrokerNodes": 3,
        "brokerNodeGroupInfo": {
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        "encryptionInfo": {
            "encryptionInTransit": {
                # ok: python-cdk-msk-broker-to-broker-tls
                "inCluster": True,
                "clientBroker": "TLS"
            }
        }
    }
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        **cluster_props
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_3():
    # Using a variable to set inCluster to True
    in_cluster_tls = True
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info={
            "encryptionInTransit": {
                # ok: python-cdk-msk-broker-to-broker-tls
                "inCluster": in_cluster_tls
            }
        }
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_4():
    # Creating MSK cluster with inCluster enabled in a class
    class MskClusterStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            msk.CfnCluster(
                self, "MskCluster",
                cluster_name="MyMskCluster",
                kafka_version="2.8.1",
                number_of_broker_nodes=3,
                broker_node_group_info={
                    "instanceType": "kafka.m5.large",
                    "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
                    "securityGroups": ["sg-1"]
                },
                encryption_info={
                    "encryptionInTransit": {
                        # ok: python-cdk-msk-broker-to-broker-tls
                        "inCluster": True
                    }
                }
            )
    
    app = cdk.App()
    stack = MskClusterStack(app, "MskClusterStack")
    return app


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_5():
    # Creating MSK cluster with encryption config in a separate dictionary
    encryption_config = {
        "encryptionInTransit": {
            # ok: python-cdk-msk-broker-to-broker-tls
            "inCluster": True,
            "clientBroker": "TLS"
        },
        "encryptionAtRest": {
            "dataVolumeKMSKeyId": "alias/aws/kafka"
        }
    }
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info=encryption_config
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_6():
    # Creating MSK cluster with conditional setting of inCluster to True
    use_tls = True
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info={
            "encryptionInTransit": {
                # ok: python-cdk-msk-broker-to-broker-tls
                "inCluster": use_tls
            }
        }
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_7():
    # Creating MSK cluster with inCluster enabled using a function
    def get_encryption_config():
        return {
            "encryptionInTransit": {
                "inCluster": True,
                "clientBroker": "TLS"
            }
        }
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        # ok: python-cdk-msk-broker-to-broker-tls
        encryption_info=get_encryption_config()
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_8():
    # Creating MSK cluster with inCluster enabled in a loop
    clusters = []
    for i in range(3):
        cluster = msk.CfnCluster(
            scope=Stack(None, f"MyStack{i}"),
            id=f"MskCluster{i}",
            cluster_name=f"MyMskCluster{i}",
            kafka_version="2.8.1",
            number_of_broker_nodes=3,
            broker_node_group_info={
                "instanceType": "kafka.m5.large",
                "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
                "securityGroups": ["sg-1"]
            },
            encryption_info={
                "encryptionInTransit": {
                    # ok: python-cdk-msk-broker-to-broker-tls
                    "inCluster": True
                }
            }
        )
        clusters.append(cluster)
    return clusters


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_9():
    # Creating MSK cluster with inCluster enabled using a dictionary comprehension
    regions = ["us-east-1", "us-west-2", "eu-west-1"]
    
    encryption_configs = {
        region: {
            "encryptionInTransit": {
                "inCluster": True,
                "clientBroker": "TLS"
            }
        } for region in regions
    }
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        # ok: python-cdk-msk-broker-to-broker-tls
        encryption_info=encryption_configs["us-east-1"]
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_10():
    # Creating MSK cluster with inCluster enabled using environment variables
    import os
    
    # Simulating environment variable
    os.environ["USE_TLS"] = "true"
    
    use_tls = os.environ["USE_TLS"].lower() == "true"
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info={
            "encryptionInTransit": {
                # ok: python-cdk-msk-broker-to-broker-tls
                "inCluster": use_tls
            }
        }
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_11():
    # Creating MSK cluster with inCluster enabled in a nested function
    def create_cluster_stack():
        def get_encryption_config():
            return {
                "encryptionInTransit": {
                    "inCluster": True
                }
            }
        
        return msk.CfnCluster(
            scope=Stack(None, "MyStack"),
            id="MskCluster",
            cluster_name="MyMskCluster",
            kafka_version="2.8.1",
            number_of_broker_nodes=3,
            broker_node_group_info={
                "instanceType": "kafka.m5.large",
                "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
                "securityGroups": ["sg-1"]
            },
            # ok: python-cdk-msk-broker-to-broker-tls
            encryption_info=get_encryption_config()
        )
    
    return create_cluster_stack()


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_12():
    # Creating MSK cluster with inCluster enabled using a class method
    class MskClusterFactory:
        @staticmethod
        def create_cluster(scope, id, name):
            return msk.CfnCluster(
                scope=scope,
                id=id,
                cluster_name=name,
                kafka_version="2.8.1",
                number_of_broker_nodes=3,
                broker_node_group_info={
                    "instanceType": "kafka.m5.large",
                    "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
                    "securityGroups": ["sg-1"]
                },
                encryption_info={
                    "encryptionInTransit": {
                        # ok: python-cdk-msk-broker-to-broker-tls
                        "inCluster": True
                    }
                }
            )
    
    stack = Stack(None, "MyStack")
    cluster = MskClusterFactory.create_cluster(stack, "MskCluster", "MyMskCluster")
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_13():
    # Creating MSK cluster with inCluster enabled using a ternary operator
    is_production = True
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        cluster_name="MyMskCluster",
        kafka_version="2.8.1",
        number_of_broker_nodes=3,
        broker_node_group_info={
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        encryption_info={
            "encryptionInTransit": {
                # ok: python-cdk-msk-broker-to-broker-tls
                "inCluster": True if is_production else False
            }
        }
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_14():
    # Creating MSK cluster with inCluster enabled using a dictionary
    config = {
        "cluster_name": "MyMskCluster",
        "kafka_version": "2.8.1",
        "number_of_broker_nodes": 3,
        "broker_node_group_info": {
            "instanceType": "kafka.m5.large",
            "clientSubnets": ["subnet-1", "subnet-2", "subnet-3"],
            "securityGroups": ["sg-1"]
        },
        "encryption_info": {
            "encryptionInTransit": {
                "inCluster": True
            }
        }
    }
    
    cluster = msk.CfnCluster(
        scope=Stack(None, "MyStack"),
        id="MskCluster",
        # ok: python-cdk-msk-broker-to-broker-tls
        **config
    )
    return cluster


# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_15():
    # Using L2 construct with secure defaults
    vpc = None  # This would be a real VPC in actual code
    
    # L2 construct defaults to secure settings
    # ok: python-cdk-msk-broker-to-broker-tls
    cluster = msk.Cluster(
        Stack(None, "MyStack"),
        "MskCluster",
        cluster_name="MyMskCluster",
        kafka_version=msk.KafkaVersion.V2_8_1,
        vpc=vpc,
        encryption_in_transit=msk.EncryptionInTransitConfig(
            client_broker=msk.ClientBrokerEncryption.TLS,
            in_cluster=True
        )
    )
    return cluster
# {/fact}