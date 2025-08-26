import aws_cdk as cdk
from aws_cdk import (
    aws_rds as rds,
    aws_ec2 as ec2,
    Stack,
    Duration,
    RemovalPolicy,
)
from constructs import Construct

# True Positives (Vulnerable Code - Multi-AZ disabled)

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    instance = rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        multi_az=False,  # Explicitly disabled multi-AZ
        allocated_storage=20,
    )
    return instance

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    postgres_db = rds.DatabaseInstance(
        scope,
        "PostgresDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        vpc=vpc,
        multi_az=False,
        storage_encrypted=True,
    )
    return postgres_db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "MariaDB",
        engine=rds.DatabaseInstanceEngine.mariadb(version=rds.MariaDbEngineVersion.VER_10_6_8),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.STANDARD5, ec2.InstanceSize.XLARGE),
        vpc=vpc,
        multi_az=False,
        backup_retention=Duration.days(7),
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    subnet_group = rds.SubnetGroup(scope, "DBSubnetGroup", vpc=vpc, description="DB Subnet Group")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    instance = rds.DatabaseInstance(
        scope,
        "OracleDB",
        engine=rds.DatabaseInstanceEngine.oracle(version=rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.LARGE),
        vpc=vpc,
        subnet_group=subnet_group,
        multi_az=False,
        storage_type=rds.StorageType.IO1,
        iops=1000,
    )
    return instance

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "SQLServerDB",
        engine=rds.DatabaseInstanceEngine.sql_server_ex(version=rds.SqlServerEngineVersion.VER_15),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.XLARGE),
        vpc=vpc,
        multi_az=False,
        deletion_protection=True,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Default is False for multi_az if not specified
    # ruleid: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "DefaultMultiAzDB",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        allocated_storage=20,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "ProductionDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.XLARGE),
        vpc=vpc,
        multi_az=False,
        storage_encrypted=True,
        backup_retention=Duration.days(14),
        deletion_protection=True,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    db_instance = rds.DatabaseInstance(
        scope,
        "ConfiguredDB",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        multi_az=False,
        removal_policy=RemovalPolicy.SNAPSHOT,
        parameter_group=rds.ParameterGroup.from_parameter_group_name(
            scope, "ParamGroup", "default.mysql8.0"
        ),
    )
    return db_instance

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Using a variable but still setting to False
    enable_multi_az = False
    # ruleid: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "VariableConfigDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.STANDARD5, ec2.InstanceSize.LARGE),
        vpc=vpc,
        multi_az=enable_multi_az,
        allocated_storage=50,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "DevDB",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        multi_az=False,
        publicly_accessible=False,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "LowCostDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_12_9),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO),
        vpc=vpc,
        multi_az=False,
        allocated_storage=10,
        storage_type=rds.StorageType.GP2,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "TestDB",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_5_7),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.SMALL),
        vpc=vpc,
        multi_az=False,
        backup_retention=Duration.days(0),  # No backups
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "StagingDB",
        engine=rds.DatabaseInstanceEngine.mariadb(version=rds.MariaDbEngineVersion.VER_10_5_13),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.STANDARD5, ec2.InstanceSize.LARGE),
        vpc=vpc,
        multi_az=False,
        auto_minor_version_upgrade=True,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "CustomParameterDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        vpc=vpc,
        multi_az=False,
        parameters={
            "max_connections": "100",
            "shared_buffers": "4GB",
        },
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "EncryptedDB",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        multi_az=False,
        storage_encrypted=True,
        deletion_protection=True,
        backup_retention=Duration.days(7),
    )
    return db

# True Negatives (Secure Code - Multi-AZ enabled)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-multiaz-support-enabled
    instance = rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        multi_az=True,  # Explicitly enabled multi-AZ
        allocated_storage=20,
    )
    return instance

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-multiaz-support-enabled
    postgres_db = rds.DatabaseInstance(
        scope,
        "PostgresDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        vpc=vpc,
        multi_az=True,
        storage_encrypted=True,
    )
    return postgres_db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "MariaDB",
        engine=rds.DatabaseInstanceEngine.mariadb(version=rds.MariaDbEngineVersion.VER_10_6_8),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.STANDARD5, ec2.InstanceSize.XLARGE),
        vpc=vpc,
        multi_az=True,
        backup_retention=Duration.days(7),
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    subnet_group = rds.SubnetGroup(scope, "DBSubnetGroup", vpc=vpc, description="DB Subnet Group")
    # ok: python-cdk-rds-multiaz-support-enabled
    instance = rds.DatabaseInstance(
        scope,
        "OracleDB",
        engine=rds.DatabaseInstanceEngine.oracle(version=rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.LARGE),
        vpc=vpc,
        subnet_group=subnet_group,
        multi_az=True,
        storage_type=rds.StorageType.IO1,
        iops=1000,
    )
    return instance

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "SQLServerDB",
        engine=rds.DatabaseInstanceEngine.sql_server_ex(version=rds.SqlServerEngineVersion.VER_15),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.XLARGE),
        vpc=vpc,
        multi_az=True,
        deletion_protection=True,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Using a variable set to True
    enable_multi_az = True
    # ok: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "VariableConfigDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.STANDARD5, ec2.InstanceSize.LARGE),
        vpc=vpc,
        multi_az=enable_multi_az,
        allocated_storage=50,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "ProductionDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.XLARGE),
        vpc=vpc,
        multi_az=True,
        storage_encrypted=True,
        backup_retention=Duration.days(14),
        deletion_protection=True,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-multiaz-support-enabled
    db_instance = rds.DatabaseInstance(
        scope,
        "ConfiguredDB",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        multi_az=True,
        removal_policy=RemovalPolicy.SNAPSHOT,
        parameter_group=rds.ParameterGroup.from_parameter_group_name(
            scope, "ParamGroup", "default.mysql8.0"
        ),
    )
    return db_instance

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Using Aurora cluster instead of RDS instance (Aurora has built-in HA)
    # ok: python-cdk-rds-multiaz-support-enabled
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_02_0),
        instances=2,  # Multiple instances for HA
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        ),
        default_database_name="mydb",
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "DevDB",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        multi_az=True,
        publicly_accessible=False,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "HighAvailabilityDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_12_9),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        multi_az=True,
        allocated_storage=20,
        storage_type=rds.StorageType.GP2,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "TestDB",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_5_7),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.SMALL),
        vpc=vpc,
        multi_az=True,
        backup_retention=Duration.days(1),
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "StagingDB",
        engine=rds.DatabaseInstanceEngine.mariadb(version=rds.MariaDbEngineVersion.VER_10_5_13),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.STANDARD5, ec2.InstanceSize.LARGE),
        vpc=vpc,
        multi_az=True,
        auto_minor_version_upgrade=True,
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-multiaz-support-enabled
    db = rds.DatabaseInstance(
        scope,
        "CustomParameterDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        vpc=vpc,
        multi_az=True,
        parameters={
            "max_connections": "100",
            "shared_buffers": "4GB",
        },
    )
    return db

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Using Aurora PostgreSQL cluster (inherently highly available)
    # ok: python-cdk-rds-multiaz-support-enabled
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraPostgresCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_13_4),
        instances=2,
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        ),
        storage_encrypted=True,
        default_database_name="production",
    )
    return cluster
# {/fact}