import aws_cdk as cdk
from aws_cdk import (
    aws_redshift as redshift,
    Stack,
    Duration,
    RemovalPolicy,
)
from constructs import Construct

# True Positives (Vulnerable Cases)

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_1(scope: Construct) -> None:
    # Creating a Redshift cluster without enabling automated snapshots
    # ruleid: python-cdk-redshift-backup-enabled
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster1",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=0  # Explicitly disabling automated snapshots
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_2(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots disabled
    # ruleid: python-cdk-redshift-backup-enabled
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster2",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=0,
        removal_policy=RemovalPolicy.DESTROY
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_3(scope: Construct) -> None:
    # Creating a Redshift cluster with default parameters (not specifying automated snapshots)
    # ruleid: python-cdk-redshift-backup-enabled
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster3",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC")
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_4(scope: Construct) -> None:
    # Creating a production Redshift cluster with automated snapshots disabled
    # ruleid: python-cdk-redshift-backup-enabled
    cluster = redshift.Cluster(
        scope, "ProductionRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        node_type=redshift.NodeType.RA3_4XLARGE,
        number_of_nodes=3,
        automated_snapshot_retention_period=0,
        cluster_name="production-data-warehouse"
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_5(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots set to zero days
    # ruleid: python-cdk-redshift-backup-enabled
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster5",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=0,
        encryption=True
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_6(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots explicitly disabled
    # ruleid: python-cdk-redshift-backup-enabled
    retention_period = 0
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster6",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=retention_period
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_7(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots disabled in a function
    # ruleid: python-cdk-redshift-backup-enabled
    def get_retention_period():
        return 0
    
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster7",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=get_retention_period()
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_8(scope: Construct) -> None:
    # Creating multiple Redshift clusters with automated snapshots disabled
    # ruleid: python-cdk-redshift-backup-enabled
    for i in range(3):
        cluster = redshift.Cluster(
            scope, f"MyRedshiftCluster8-{i}",
            master_user=redshift.Login(
                master_username=f"admin-{i}"
            ),
            vpc=cdk.aws_ec2.Vpc(scope, f"VPC-{i}"),
            automated_snapshot_retention_period=0
        )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_9(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots disabled and other configurations
    # ruleid: python-cdk-redshift-backup-enabled
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster9",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=0,
        preferred_maintenance_window="sat:03:00-sat:04:00",
        publicly_accessible=False
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_10(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots disabled in a conditional
    # ruleid: python-cdk-redshift-backup-enabled
    is_dev_environment = True
    retention_period = 0 if is_dev_environment else 7
    
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster10",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=retention_period
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_11(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots disabled using a dictionary
    # ruleid: python-cdk-redshift-backup-enabled
    config = {
        "username": "admin",
        "snapshot_retention": 0
    }
    
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster11",
        master_user=redshift.Login(
            master_username=config["username"]
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=config["snapshot_retention"]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_12(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots disabled in a class
    # ruleid: python-cdk-redshift-backup-enabled
    class ClusterConfig:
        def __init__(self):
            self.retention_period = 0
    
    config = ClusterConfig()
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster12",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=config.retention_period
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_13(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots disabled using environment variables
    # ruleid: python-cdk-redshift-backup-enabled
    import os
    os.environ["SNAPSHOT_RETENTION"] = "0"
    
    retention = int(os.environ.get("SNAPSHOT_RETENTION", "7"))
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster13",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=retention
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_14(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots disabled in a try-except block
    # ruleid: python-cdk-redshift-backup-enabled
    try:
        retention_period = 1/0  # This will cause an exception
    except:
        retention_period = 0
    
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster14",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=retention_period
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_15(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots disabled using a lambda
    # ruleid: python-cdk-redshift-backup-enabled
    get_retention = lambda: 0
    
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster15",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=get_retention()
    )

# True Negatives (Secure Cases)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_1(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots enabled (default is 1)
    # ok: python-cdk-redshift-backup-enabled
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster1",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=1
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_2(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots enabled for 7 days
    # ok: python-cdk-redshift-backup-enabled
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster2",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=7
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_3(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots enabled for 30 days
    # ok: python-cdk-redshift-backup-enabled
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster3",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=30
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_4(scope: Construct) -> None:
    # Creating a production Redshift cluster with automated snapshots enabled
    # ok: python-cdk-redshift-backup-enabled
    cluster = redshift.Cluster(
        scope, "ProductionRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        node_type=redshift.NodeType.RA3_4XLARGE,
        number_of_nodes=3,
        automated_snapshot_retention_period=35,
        cluster_name="production-data-warehouse"
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_5(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots enabled and encryption
    # ok: python-cdk-redshift-backup-enabled
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster5",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=14,
        encryption=True
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_6(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots explicitly enabled
    # ok: python-cdk-redshift-backup-enabled
    retention_period = 7
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster6",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=retention_period
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_7(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots enabled in a function
    # ok: python-cdk-redshift-backup-enabled
    def get_retention_period():
        return 7
    
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster7",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=get_retention_period()
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_8(scope: Construct) -> None:
    # Creating multiple Redshift clusters with automated snapshots enabled
    # ok: python-cdk-redshift-backup-enabled
    for i in range(3):
        cluster = redshift.Cluster(
            scope, f"MyRedshiftCluster8-{i}",
            master_user=redshift.Login(
                master_username=f"admin-{i}"
            ),
            vpc=cdk.aws_ec2.Vpc(scope, f"VPC-{i}"),
            automated_snapshot_retention_period=7
        )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_9(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots enabled and other configurations
    # ok: python-cdk-redshift-backup-enabled
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster9",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=7,
        preferred_maintenance_window="sat:03:00-sat:04:00",
        publicly_accessible=False
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_10(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots enabled in a conditional
    # ok: python-cdk-redshift-backup-enabled
    is_dev_environment = True
    retention_period = 3 if is_dev_environment else 7
    
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster10",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=retention_period
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_11(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots enabled using a dictionary
    # ok: python-cdk-redshift-backup-enabled
    config = {
        "username": "admin",
        "snapshot_retention": 7
    }
    
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster11",
        master_user=redshift.Login(
            master_username=config["username"]
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=config["snapshot_retention"]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_12(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots enabled in a class
    # ok: python-cdk-redshift-backup-enabled
    class ClusterConfig:
        def __init__(self):
            self.retention_period = 14
    
    config = ClusterConfig()
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster12",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=config.retention_period
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_13(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots enabled using environment variables
    # ok: python-cdk-redshift-backup-enabled
    import os
    os.environ["SNAPSHOT_RETENTION"] = "7"
    
    retention = int(os.environ.get("SNAPSHOT_RETENTION", "7"))
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster13",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=retention
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_14(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots enabled in a try-except block
    # ok: python-cdk-redshift-backup-enabled
    try:
        retention_period = 1/0  # This will cause an exception
    except:
        retention_period = 7
    
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster14",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=retention_period
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_15(scope: Construct) -> None:
    # Creating a Redshift cluster with automated snapshots enabled using a lambda
    # ok: python-cdk-redshift-backup-enabled
    get_retention = lambda: 7
    
    cluster = redshift.Cluster(
        scope, "MyRedshiftCluster15",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=cdk.aws_ec2.Vpc(scope, "VPC"),
        automated_snapshot_retention_period=get_retention()
    )
# {/fact}