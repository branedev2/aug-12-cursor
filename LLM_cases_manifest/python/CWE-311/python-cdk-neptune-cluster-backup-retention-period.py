import aws_cdk as cdk
from aws_cdk import (
    aws_neptune as neptune,
    Stack,
    Duration,
    RemovalPolicy,
    CfnParameter
)
from constructs import Construct
import os
from dotenv import load_dotenv

# True Positives (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1():
    # Creating a Neptune cluster without specifying backup_retention_period
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2():
    # Setting backup_retention_period to 0 (disabled)
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(0),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3():
    # Setting backup_retention_period to less than 7 days (1 day)
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(1),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4():
    # Setting backup_retention_period to less than 7 days (3 days)
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(3),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5():
    # Setting backup_retention_period to less than 7 days (5 days)
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(5),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6():
    # Setting backup_retention_period to less than 7 days (6 days)
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(6),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7():
    # Setting backup_retention_period to hours instead of days (less than 7 days)
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.hours(36),  # Only 1.5 days
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8():
    # Using a variable that's set to less than 7 days
    retention_period = 4
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(retention_period),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9():
    # Using a parameter with default value less than 7 days
    retention_param = CfnParameter(Stack(None, "MyStack"), "RetentionPeriod",
                                  default="2",
                                  type="Number",
                                  description="Backup retention period in days")
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(int(retention_param.value_as_string)),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10():
    # Creating a Neptune cluster in a custom stack class without proper backup retention
    class NeptuneStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            vpc = cdk.aws_ec2.Vpc(self, "MyVpc")
            # ruleid: python-cdk-neptune-cluster-backup-retention-period
            neptune.DatabaseCluster(
                self, "MyCluster",
                instance_type=neptune.InstanceType.MEDIUM,
                vpc=vpc,
                removal_policy=RemovalPolicy.DESTROY
            )
    
    app = cdk.App()
    stack = NeptuneStack(app, "NeptuneStack")
    return app

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11():
    # Creating multiple Neptune clusters, one with insufficient backup retention
    vpc = cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc")
    
    # First cluster is fine
    cluster1 = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "Cluster1",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=vpc,
        backup_retention=cdk.Duration.days(14),
        removal_policy=RemovalPolicy.DESTROY
    )
    
    # Second cluster has insufficient backup retention
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster2 = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "Cluster2",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=vpc,
        backup_retention=cdk.Duration.days(3),
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return [cluster1, cluster2]

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12():
    # Using a calculated value that results in less than 7 days
    base_retention = 10
    reduction = 8
    final_retention = base_retention - reduction  # Results in 2 days
    
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(final_retention),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13():
    # Using a conditional that could result in less than 7 days
    is_development = True
    retention_period = 14 if not is_development else 3
    
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(retention_period),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14():
    # Using minutes which is less than 7 days
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.minutes(4320),  # 3 days in minutes
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15():
    # Using an environment variable that could be less than 7 days
    # Assuming the environment variable is set to a value less than 7
    os.environ['BACKUP_RETENTION_DAYS'] = '5'
    
    # ruleid: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(int(os.environ.get('BACKUP_RETENTION_DAYS', '1'))),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# True Negatives (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1():
    # Setting backup_retention_period to exactly 7 days (minimum recommended)
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(7),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2():
    # Setting backup_retention_period to more than 7 days (14 days)
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(14),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3():
    # Setting backup_retention_period to 30 days
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(30),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4():
    # Using a variable that's set to more than 7 days
    retention_period = 21
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(retention_period),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5():
    # Using a parameter with default value of 7 days or more
    retention_param = CfnParameter(Stack(None, "MyStack"), "RetentionPeriod",
                                  default="14",
                                  type="Number",
                                  description="Backup retention period in days")
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(int(retention_param.value_as_string)),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6():
    # Creating a Neptune cluster in a custom stack class with proper backup retention
    class NeptuneStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            vpc = cdk.aws_ec2.Vpc(self, "MyVpc")
            # ok: python-cdk-neptune-cluster-backup-retention-period
            neptune.DatabaseCluster(
                self, "MyCluster",
                instance_type=neptune.InstanceType.MEDIUM,
                vpc=vpc,
                backup_retention=cdk.Duration.days(14),
                removal_policy=RemovalPolicy.DESTROY
            )
    
    app = cdk.App()
    stack = NeptuneStack(app, "NeptuneStack")
    return app

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7():
    # Creating multiple Neptune clusters, all with sufficient backup retention
    vpc = cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc")
    
    # First cluster
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster1 = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "Cluster1",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=vpc,
        backup_retention=cdk.Duration.days(14),
        removal_policy=RemovalPolicy.DESTROY
    )
    
    # Second cluster
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster2 = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "Cluster2",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=vpc,
        backup_retention=cdk.Duration.days(7),
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return [cluster1, cluster2]

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8():
    # Using a calculated value that results in 7 days or more
    base_retention = 10
    addition = 5
    final_retention = base_retention + addition  # Results in 15 days
    
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(final_retention),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9():
    # Using a conditional that ensures at least 7 days
    is_development = True
    retention_period = 30 if not is_development else 7
    
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(retention_period),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10():
    # Using hours which is at least 7 days
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.hours(168),  # 7 days in hours
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11():
    # Using an environment variable with a safe default
    # Even if the environment variable is not set, it will use 14 days
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(int(os.environ.get('BACKUP_RETENTION_DAYS', '14'))),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12():
    # Using a function that returns a value of at least 7 days
    def get_retention_period():
        # Complex logic that determines retention period
        return 14
    
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(get_retention_period()),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13():
    # Using environment variables with validation to ensure minimum 7 days
    load_dotenv()  # Load environment variables from .env file
    
    # Get retention period from environment, with validation
    retention_days = int(os.environ.get('BACKUP_RETENTION_DAYS', '14'))
    if retention_days < 7:
        retention_days = 7  # Enforce minimum of 7 days
    
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(retention_days),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14():
    # Using the maximum allowed retention period (35 days)
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(35),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15():
    # Using a combination of days and hours that equals at least 7 days
    days_part = 5
    hours_part = 48  # 2 days in hours
    
    # ok: python-cdk-neptune-cluster-backup-retention-period
    cluster = neptune.DatabaseCluster(
        Stack(None, "MyStack"), "MyCluster",
        instance_type=neptune.InstanceType.MEDIUM,
        vpc=cdk.aws_ec2.Vpc(Stack(None, "MyStack"), "MyVpc"),
        backup_retention=cdk.Duration.days(days_part).plus(cdk.Duration.hours(hours_part)),
        removal_policy=RemovalPolicy.DESTROY
    )
    return cluster
# {/fact}