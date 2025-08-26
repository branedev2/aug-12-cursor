import aws_cdk as cdk
from aws_cdk import (
    aws_rds as rds,
    aws_ec2 as ec2,
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "Instance",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        removal_policy=RemovalPolicy.DESTROY,
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "Instance",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        vpc=vpc,
        backup_retention=0,  # Explicitly set to 0, disabling backups
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    cluster = rds.DatabaseCluster(
        scope, "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_2_10_1),
        instances=2,
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        ),
        backup_retention=0,  # Explicitly set to 0, disabling backups
    )
    return cluster

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "DevInstance",
        engine=rds.DatabaseInstanceEngine.oracle_ee(version=rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.XLARGE),
        vpc=vpc,
        deletion_protection=False,
        backup_retention=0,  # Explicitly set to 0, disabling backups
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    serverless_cluster = rds.ServerlessCluster(
        scope, "AuroraServerlessCluster",
        engine=rds.DatabaseClusterEngine.AURORA_POSTGRESQL,
        vpc=vpc,
        scaling=rds.ServerlessScalingOptions(
            auto_pause=Duration.minutes(10),
            min_capacity=rds.AuroraCapacityUnit.ACU_2,
            max_capacity=rds.AuroraCapacityUnit.ACU_16,
        ),
        backup_retention=0,  # Explicitly set to 0, disabling backups
    )
    return serverless_cluster

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "SQLServerInstance",
        engine=rds.DatabaseInstanceEngine.sql_server_ex(version=rds.SqlServerEngineVersion.VER_15),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.LARGE),
        vpc=vpc,
        storage_encrypted=True,
        multi_az=False,
    )  # No backup_retention specified, defaults to 0
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    cluster = rds.DatabaseCluster(
        scope, "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_13_4),
        instances=1,
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        ),
    )  # No backup_retention specified, defaults to 0
    return cluster

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Create a parameter group
    parameter_group = rds.ParameterGroup(
        scope, "ParameterGroup",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        parameters={
            "shared_buffers": "8192",
            "max_connections": "100",
        }
    )
    
    # ruleid: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "Instance",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        parameter_group=parameter_group,
        backup_retention=0,  # Explicitly set to 0, disabling backups
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstanceFromSnapshot(
        scope, "InstanceFromSnapshot",
        snapshot_identifier="my-snapshot-id",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
    )  # No backup_retention specified, defaults to 0
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "Instance",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        backup_retention=0,  # Explicitly set to 0, disabling backups
        allocated_storage=20,
        storage_type=rds.StorageType.GP2,
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstanceReadReplica(
        scope, "ReadReplica",
        source_database_instance=rds.DatabaseInstance(
            scope, "SourceInstance",
            engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
            vpc=vpc,
        ),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        backup_retention=0,  # Explicitly set to 0, disabling backups
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    cluster = rds.DatabaseCluster(
        scope, "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_2_10_1),
        credentials=rds.Credentials.from_generated_secret("clusteradmin"),
        instances=2,
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        ),
        backup_retention=0,  # Explicitly set to 0, disabling backups
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "Instance",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        storage_encrypted=True,
        multi_az=True,
        backup_retention=0,  # Explicitly set to 0, disabling backups
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Create a security group
    security_group = ec2.SecurityGroup(
        scope, "SecurityGroup",
        vpc=vpc,
        description="Allow database access",
    )
    
    # ruleid: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "Instance",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        security_groups=[security_group],
    )  # No backup_retention specified, defaults to 0
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-instance-backup-enabled
    instance = rds.CfnDBInstance(
        scope, "Instance",
        engine="mysql",
        db_instance_class="db.t3.small",
        allocated_storage="20",
        backup_retention_period=0,  # Explicitly set to 0, disabling backups
    )
    return instance

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "Instance",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        backup_retention=Duration.days(7),  # Backups enabled for 7 days
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "Instance",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        vpc=vpc,
        backup_retention=Duration.days(14),  # Backups enabled for 14 days
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-instance-backup-enabled
    cluster = rds.DatabaseCluster(
        scope, "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_2_10_1),
        instances=2,
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        ),
        backup_retention=Duration.days(30),  # Backups enabled for 30 days
    )
    return cluster

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "ProdInstance",
        engine=rds.DatabaseInstanceEngine.oracle_ee(version=rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.XLARGE),
        vpc=vpc,
        deletion_protection=True,
        backup_retention=Duration.days(35),  # Backups enabled for 35 days
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-instance-backup-enabled
    serverless_cluster = rds.ServerlessCluster(
        scope, "AuroraServerlessCluster",
        engine=rds.DatabaseClusterEngine.AURORA_POSTGRESQL,
        vpc=vpc,
        scaling=rds.ServerlessScalingOptions(
            auto_pause=Duration.minutes(10),
            min_capacity=rds.AuroraCapacityUnit.ACU_2,
            max_capacity=rds.AuroraCapacityUnit.ACU_16,
        ),
        backup_retention=Duration.days(7),  # Backups enabled for 7 days
    )
    return serverless_cluster

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "SQLServerInstance",
        engine=rds.DatabaseInstanceEngine.sql_server_ex(version=rds.SqlServerEngineVersion.VER_15),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.LARGE),
        vpc=vpc,
        storage_encrypted=True,
        multi_az=True,
        backup_retention=Duration.days(14),  # Backups enabled for 14 days
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-instance-backup-enabled
    cluster = rds.DatabaseCluster(
        scope, "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_13_4),
        instances=2,
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        ),
        backup_retention=Duration.days(7),  # Backups enabled for 7 days
    )
    return cluster

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Create a parameter group
    parameter_group = rds.ParameterGroup(
        scope, "ParameterGroup",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        parameters={
            "shared_buffers": "8192",
            "max_connections": "100",
        }
    )
    
    # ok: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "Instance",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        parameter_group=parameter_group,
        backup_retention=Duration.days(7),  # Backups enabled for 7 days
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstanceFromSnapshot(
        scope, "InstanceFromSnapshot",
        snapshot_identifier="my-snapshot-id",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        backup_retention=Duration.days(14),  # Backups enabled for 14 days
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "Instance",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        backup_retention=Duration.days(30),  # Backups enabled for 30 days
        allocated_storage=20,
        storage_type=rds.StorageType.GP2,
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Create source instance with backups enabled
    source_instance = rds.DatabaseInstance(
        scope, "SourceInstance",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        backup_retention=Duration.days(7),  # Backups enabled for source
    )
    
    # ok: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstanceReadReplica(
        scope, "ReadReplica",
        source_database_instance=source_instance,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        backup_retention=Duration.days(3),  # Backups enabled for read replica
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-instance-backup-enabled
    cluster = rds.DatabaseCluster(
        scope, "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_2_10_1),
        credentials=rds.Credentials.from_generated_secret("clusteradmin"),
        instances=2,
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        ),
        backup_retention=Duration.days(14),  # Backups enabled for 14 days
        removal_policy=RemovalPolicy.SNAPSHOT,  # Take a snapshot before removal
    )
    return cluster

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "Instance",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        storage_encrypted=True,
        multi_az=True,
        backup_retention=Duration.days(35),  # Backups enabled for 35 days
        preferred_backup_window="03:00-04:00",  # Specify backup window
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Create a security group
    security_group = ec2.SecurityGroup(
        scope, "SecurityGroup",
        vpc=vpc,
        description="Allow database access",
    )
    
    # ok: python-cdk-rds-instance-backup-enabled
    instance = rds.DatabaseInstance(
        scope, "Instance",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        security_groups=[security_group],
        backup_retention=Duration.days(7),  # Backups enabled for 7 days
    )
    return instance

# {/fact}

# {fact rule=security-information-truncation@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-instance-backup-enabled
    instance = rds.CfnDBInstance(
        scope, "Instance",
        engine="mysql",
        db_instance_class="db.t3.small",
        allocated_storage="20",
        backup_retention_period=7,  # Backups enabled for 7 days
    )
    return instance
# {/fact}