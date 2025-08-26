import aws_cdk as cdk
from aws_cdk import (
    aws_opensearchservice as opensearch,
    Stack,
    App,
    CfnOutput,
    RemovalPolicy
)
from constructs import Construct

# True Positives (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "master_nodes": 3,
            "data_nodes": 2
        },
        ebs={
            "volume_size": 10
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "master_nodes": 0,
            "data_nodes": 1
        },
        zone_awareness=opensearch.ZoneAwarenessConfig(
            enabled=False
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    capacity = opensearch.CapacityConfig(
        data_nodes=3,
        master_nodes=3
    )
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_2,
        capacity=capacity
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.CfnDomain(stack, "Domain",
        engine_version="OpenSearch_1.0",
        cluster_config={
            "instanceCount": 2,
            "instanceType": "t3.small.search"
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.ELASTICSEARCH_7_10,
        capacity={
            "data_nodes": 2
        },
        ebs={
            "volume_size": 20
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6():
    class OpenSearchStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ruleid: python-cdk-open-search-zone-awareness
            opensearch.Domain(self, "Domain",
                version=opensearch.EngineVersion.OPENSEARCH_1_0,
                capacity={
                    "data_nodes": 4
                }
            )
    
    app = App()
    OpenSearchStack(app, "OpenSearchStack")

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.CfnDomain(stack, "Domain",
        engine_version="OpenSearch_1.0",
        cluster_config={
            "zoneAwarenessEnabled": False,
            "instanceCount": 3,
            "instanceType": "r5.large.search"
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    zone_config = opensearch.ZoneAwarenessConfig(
        enabled=False,
        availability_zone_count=2
    )
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_1,
        capacity={
            "data_nodes": 2
        },
        zone_awareness=zone_config
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_nodes=2,
            master_nodes=3
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.CfnDomain(stack, "Domain",
        engine_version="Elasticsearch_7.10",
        cluster_config={
            "dedicatedMasterEnabled": True,
            "dedicatedMasterCount": 3,
            "dedicatedMasterType": "c5.large.search",
            "instanceCount": 2,
            "instanceType": "r5.large.search"
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11():
    class MyStack(Stack):
        def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
            super().__init__(scope, construct_id, **kwargs)
            
            # ruleid: python-cdk-open-search-zone-awareness
            opensearch.Domain(self, "OpenSearchDomain",
                version=opensearch.EngineVersion.OPENSEARCH_1_3,
                capacity={
                    "data_nodes": 6,
                    "master_nodes": 3
                },
                ebs={
                    "volume_size": 100,
                    "volume_type": cdk.aws_ec2.EbsDeviceVolumeType.GP3
                }
            )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 10,
            "master_nodes": 5,
            "warm_nodes": 2,
            "warm_instance_type": "ultrawarm1.medium.search"
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.CfnDomain(stack, "Domain",
        engine_version="OpenSearch_1.2",
        cluster_config={
            "instanceCount": 4,
            "instanceType": "r6g.large.search",
            "dedicatedMasterEnabled": True,
            "dedicatedMasterCount": 3,
            "dedicatedMasterType": "c6g.large.search"
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_2_3,
        capacity={
            "data_nodes": 2,
            "master_nodes": 0
        },
        ebs={
            "volume_size": 20,
            "volume_type": cdk.aws_ec2.EbsDeviceVolumeType.GP3
        },
        encryption_at_rest={
            "enabled": True
        },
        node_to_node_encryption=True,
        enforce_https=True
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ruleid: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.ELASTICSEARCH_7_9,
        capacity={
            "data_node_instance_type": "r5.xlarge.search",
            "data_nodes": 3
        }
    )

# True Negatives (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "master_nodes": 3,
            "data_nodes": 2
        },
        zone_awareness={
            "enabled": True,
            "availability_zone_count": 2
        },
        ebs={
            "volume_size": 10
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "master_nodes": 3,
            "data_nodes": 4
        },
        zone_awareness=opensearch.ZoneAwarenessConfig(
            enabled=True,
            availability_zone_count=2
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    capacity = opensearch.CapacityConfig(
        data_nodes=4,
        master_nodes=3
    )
    
    zone_config = opensearch.ZoneAwarenessConfig(
        enabled=True,
        availability_zone_count=2
    )
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_2,
        capacity=capacity,
        zone_awareness=zone_config
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.CfnDomain(stack, "Domain",
        engine_version="OpenSearch_1.0",
        cluster_config={
            "instanceCount": 2,
            "instanceType": "t3.small.search",
            "zoneAwarenessEnabled": True,
            "zoneAwarenessConfig": {
                "availabilityZoneCount": 2
            }
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.ELASTICSEARCH_7_10,
        capacity={
            "data_nodes": 2
        },
        zone_awareness={
            "enabled": True
        },
        ebs={
            "volume_size": 20
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6():
    class OpenSearchStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            
            # ok: python-cdk-open-search-zone-awareness
            opensearch.Domain(self, "Domain",
                version=opensearch.EngineVersion.OPENSEARCH_1_0,
                capacity={
                    "data_nodes": 4
                },
                zone_awareness={
                    "enabled": True,
                    "availability_zone_count": 2
                }
            )
    
    app = App()
    OpenSearchStack(app, "OpenSearchStack")

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.CfnDomain(stack, "Domain",
        engine_version="OpenSearch_1.0",
        cluster_config={
            "zoneAwarenessEnabled": True,
            "zoneAwarenessConfig": {
                "availabilityZoneCount": 3
            },
            "instanceCount": 3,
            "instanceType": "r5.large.search"
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    zone_config = opensearch.ZoneAwarenessConfig(
        enabled=True,
        availability_zone_count=3
    )
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_1,
        capacity={
            "data_nodes": 6
        },
        zone_awareness=zone_config
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity=opensearch.CapacityConfig(
            data_nodes=4,
            master_nodes=3
        ),
        zone_awareness=opensearch.ZoneAwarenessConfig(
            enabled=True,
            availability_zone_count=2
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.CfnDomain(stack, "Domain",
        engine_version="Elasticsearch_7.10",
        cluster_config={
            "dedicatedMasterEnabled": True,
            "dedicatedMasterCount": 3,
            "dedicatedMasterType": "c5.large.search",
            "instanceCount": 4,
            "instanceType": "r5.large.search",
            "zoneAwarenessEnabled": True,
            "zoneAwarenessConfig": {
                "availabilityZoneCount": 2
            }
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11():
    class MyStack(Stack):
        def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
            super().__init__(scope, construct_id, **kwargs)
            
            # ok: python-cdk-open-search-zone-awareness
            opensearch.Domain(self, "OpenSearchDomain",
                version=opensearch.EngineVersion.OPENSEARCH_1_3,
                capacity={
                    "data_nodes": 6,
                    "master_nodes": 3
                },
                zone_awareness={
                    "enabled": True,
                    "availability_zone_count": 3
                },
                ebs={
                    "volume_size": 100,
                    "volume_type": cdk.aws_ec2.EbsDeviceVolumeType.GP3
                }
            )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_1_0,
        capacity={
            "data_nodes": 10,
            "master_nodes": 5,
            "warm_nodes": 2,
            "warm_instance_type": "ultrawarm1.medium.search"
        },
        zone_awareness={
            "enabled": True,
            "availability_zone_count": 3
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.CfnDomain(stack, "Domain",
        engine_version="OpenSearch_1.2",
        cluster_config={
            "instanceCount": 4,
            "instanceType": "r6g.large.search",
            "dedicatedMasterEnabled": True,
            "dedicatedMasterCount": 3,
            "dedicatedMasterType": "c6g.large.search",
            "zoneAwarenessEnabled": True
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.OPENSEARCH_2_3,
        capacity={
            "data_nodes": 2,
            "master_nodes": 0
        },
        zone_awareness=opensearch.ZoneAwarenessConfig(
            enabled=True,
            availability_zone_count=2
        ),
        ebs={
            "volume_size": 20,
            "volume_type": cdk.aws_ec2.EbsDeviceVolumeType.GP3
        },
        encryption_at_rest={
            "enabled": True
        },
        node_to_node_encryption=True,
        enforce_https=True
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15():
    app = cdk.App()
    stack = cdk.Stack(app, "OpenSearchStack")
    
    # ok: python-cdk-open-search-zone-awareness
    domain = opensearch.Domain(stack, "Domain",
        version=opensearch.EngineVersion.ELASTICSEARCH_7_9,
        capacity={
            "data_node_instance_type": "r5.xlarge.search",
            "data_nodes": 6
        },
        zone_awareness={
            "enabled": True,
            "availability_zone_count": 3
        }
    )
# {/fact}