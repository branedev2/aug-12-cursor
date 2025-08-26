import aws_cdk as cdk
from aws_cdk import (
    aws_docdb as docdb,
    Duration,
    Stack,
    App
)
from constructs import Construct

# True Positives (Vulnerable Code)

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_1(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "MyDocDB",
        master_user=docdb.Login(
            username="myuser"
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": ec2.SubnetType.PRIVATE_WITH_NAT},
        vpc=vpc,
        removal_policy=cdk.RemovalPolicy.DESTROY,
        backup=docdb.BackupProps(
            retention=Duration.days(3)  # Less than 7 days
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_2(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "MyDocDB",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=docdb.InstanceType.T3_MEDIUM,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.days(1)  # Only 1 day retention
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_3(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "DocDBCluster",
        master_user=docdb.Login(
            username="dbadmin",
            password=cdk.SecretValue.unsafe_plain_text("password123")
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.days(5)  # 5 days is less than recommended 7 days
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_4(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "ProductionDocDB",
        master_user=docdb.Login(
            username="produser"
        ),
        instance_type=docdb.InstanceType.R5_XLARGE,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.hours(24 * 6)  # 6 days expressed in hours
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_5(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "AnalyticsDocDB",
        master_user=docdb.Login(
            username="analyst"
        ),
        instance_type=docdb.InstanceType.R5_2XLARGE,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.days(0)  # No backup retention
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_6(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    props = docdb.BackupProps(
        retention=Duration.days(2)  # 2 days is less than recommended 7 days
    )
    
    cluster = docdb.DatabaseCluster(scope, "TestDocDB",
        master_user=docdb.Login(username="testuser"),
        instance_type=docdb.InstanceType.T3_MEDIUM,
        vpc=vpc,
        backup=props
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_7(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    retention_days = 4  # Less than recommended 7 days
    
    cluster = docdb.DatabaseCluster(scope, "StagingDocDB",
        master_user=docdb.Login(username="stageuser"),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.days(retention_days)
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_8(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "MinimalBackupDocDB",
        master_user=docdb.Login(username="minuser"),
        instance_type=docdb.InstanceType.T3_MEDIUM,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.minutes(60 * 24 * 6)  # 6 days expressed in minutes
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_9(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    for i in range(3):
        cluster = docdb.DatabaseCluster(scope, f"MultiDocDB{i}",
            master_user=docdb.Login(username=f"user{i}"),
            instance_type=docdb.InstanceType.R5_LARGE,
            vpc=vpc,
            backup=docdb.BackupProps(
                retention=Duration.days(i + 2)  # 2, 3, 4 days - all less than 7
            )
        )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_10(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    backup_config = {
        "retention": Duration.days(6)  # 6 days is less than recommended 7 days
    }
    
    cluster = docdb.DatabaseCluster(scope, "ConfigDocDB",
        master_user=docdb.Login(username="configuser"),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc=vpc,
        backup=docdb.BackupProps(**backup_config)
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_11(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    if is_production:
        retention = Duration.days(30)  # Good for production
    else:
        retention = Duration.days(4)  # Bad for non-production
    
    cluster = docdb.DatabaseCluster(scope, "ConditionalDocDB",
        master_user=docdb.Login(username="conduser"),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc=vpc,
        backup=docdb.BackupProps(retention=retention)
    )
    
    # Assume is_production is False for this example

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_12(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    retention_period = Duration.days(int(environment_config.get("backup_days", "3")))  # Default is 3 days
    
    cluster = docdb.DatabaseCluster(scope, "EnvConfigDocDB",
        master_user=docdb.Login(username="envuser"),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc=vpc,
        backup=docdb.BackupProps(retention=retention_period)
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_13(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "WeekendDocDB",
        master_user=docdb.Login(username="weekenduser"),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.days(2),  # Only weekend days
            preferred_window="00:00-02:00"
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_14(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    class DocDBStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            docdb.DatabaseCluster(self, "ClassDocDB",
                master_user=docdb.Login(username="classuser"),
                instance_type=docdb.InstanceType.R5_LARGE,
                vpc=vpc,
                backup=docdb.BackupProps(
                    retention=Duration.days(6)  # 6 days is less than recommended 7 days
                )
            )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=1}
def bad_case_15(scope: Construct):
    # ruleid: python-cdk-document-db-cluster-backup-retention-period
    cluster_params = {
        "master_user": docdb.Login(username="paramuser"),
        "instance_type": docdb.InstanceType.R5_LARGE,
        "vpc": vpc,
        "backup": docdb.BackupProps(
            retention=Duration.seconds(60 * 60 * 24 * 5)  # 5 days expressed in seconds
        )
    }
    
    cluster = docdb.DatabaseCluster(scope, "ParamDocDB", **cluster_params)

# True Negatives (Secure Code)

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_1(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "MyDocDB",
        master_user=docdb.Login(
            username="myuser"
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": ec2.SubnetType.PRIVATE_WITH_NAT},
        vpc=vpc,
        removal_policy=cdk.RemovalPolicy.DESTROY,
        backup=docdb.BackupProps(
            retention=Duration.days(7)  # Minimum recommended 7 days
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_2(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "MyDocDB",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=docdb.InstanceType.T3_MEDIUM,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.days(14)  # 14 days, exceeds minimum
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_3(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "DocDBCluster",
        master_user=docdb.Login(
            username="dbadmin",
            password=cdk.SecretValue.unsafe_plain_text("password123")
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.days(30)  # 30 days, well above minimum
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_4(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "ProductionDocDB",
        master_user=docdb.Login(
            username="produser"
        ),
        instance_type=docdb.InstanceType.R5_XLARGE,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.hours(24 * 7)  # 7 days expressed in hours
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_5(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "AnalyticsDocDB",
        master_user=docdb.Login(
            username="analyst"
        ),
        instance_type=docdb.InstanceType.R5_2XLARGE,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.days(90)  # 90 days for analytics data
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_6(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    props = docdb.BackupProps(
        retention=Duration.days(7)  # Minimum recommended 7 days
    )
    
    cluster = docdb.DatabaseCluster(scope, "TestDocDB",
        master_user=docdb.Login(username="testuser"),
        instance_type=docdb.InstanceType.T3_MEDIUM,
        vpc=vpc,
        backup=props
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_7(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    retention_days = 14  # Exceeds minimum recommended 7 days
    
    cluster = docdb.DatabaseCluster(scope, "StagingDocDB",
        master_user=docdb.Login(username="stageuser"),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.days(retention_days)
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_8(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "MinimalBackupDocDB",
        master_user=docdb.Login(username="minuser"),
        instance_type=docdb.InstanceType.T3_MEDIUM,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.minutes(60 * 24 * 7)  # 7 days expressed in minutes
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_9(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    for i in range(3):
        cluster = docdb.DatabaseCluster(scope, f"MultiDocDB{i}",
            master_user=docdb.Login(username=f"user{i}"),
            instance_type=docdb.InstanceType.R5_LARGE,
            vpc=vpc,
            backup=docdb.BackupProps(
                retention=Duration.days(i + 7)  # 7, 8, 9 days - all meet or exceed minimum
            )
        )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_10(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    backup_config = {
        "retention": Duration.days(35)  # 35 days exceeds minimum
    }
    
    cluster = docdb.DatabaseCluster(scope, "ConfigDocDB",
        master_user=docdb.Login(username="configuser"),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc=vpc,
        backup=docdb.BackupProps(**backup_config)
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_11(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    if is_production:
        retention = Duration.days(30)  # Good for production
    else:
        retention = Duration.days(7)  # Minimum for non-production
    
    cluster = docdb.DatabaseCluster(scope, "ConditionalDocDB",
        master_user=docdb.Login(username="conduser"),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc=vpc,
        backup=docdb.BackupProps(retention=retention)
    )
    
    # Assume is_production is False, but still using 7 days minimum

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_12(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    retention_period = Duration.days(int(environment_config.get("backup_days", "7")))  # Default is 7 days
    
    cluster = docdb.DatabaseCluster(scope, "EnvConfigDocDB",
        master_user=docdb.Login(username="envuser"),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc=vpc,
        backup=docdb.BackupProps(retention=retention_period)
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_13(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    cluster = docdb.DatabaseCluster(scope, "WeekendDocDB",
        master_user=docdb.Login(username="weekenduser"),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.days(7),  # Minimum 7 days
            preferred_window="00:00-02:00"
        )
    )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_14(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    class DocDBStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            docdb.DatabaseCluster(self, "ClassDocDB",
                master_user=docdb.Login(username="classuser"),
                instance_type=docdb.InstanceType.R5_LARGE,
                vpc=vpc,
                backup=docdb.BackupProps(
                    retention=Duration.days(14)  # 14 days exceeds minimum
                )
            )

# {/fact}

# {fact rule=improper-authentication@v1.0 defects=0}
def good_case_15(scope: Construct):
    # ok: python-cdk-document-db-cluster-backup-retention-period
    cluster_params = {
        "master_user": docdb.Login(username="paramuser"),
        "instance_type": docdb.InstanceType.R5_LARGE,
        "vpc": vpc,
        "backup": docdb.BackupProps(
            retention=Duration.seconds(60 * 60 * 24 * 7)  # 7 days expressed in seconds
        )
    }
    
    cluster = docdb.DatabaseCluster(scope, "ParamDocDB", **cluster_params)
# {/fact}