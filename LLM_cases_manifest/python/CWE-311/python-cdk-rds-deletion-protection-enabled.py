import aws_cdk as cdk
from aws_cdk import (
    aws_rds as rds,
    aws_ec2 as ec2,
    Stack,
    RemovalPolicy,
    Duration,
    CfnOutput
)
from constructs import Construct


# True Positives (Vulnerable Code Examples)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        deletion_protection=False  # Explicitly disabled deletion protection
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "Database",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        # No deletion_protection parameter, defaults to False
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    cluster = rds.DatabaseCluster(scope, "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_13_4),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        ),
        # No deletion_protection parameter, defaults to False
    )
    return cluster


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    cluster = rds.DatabaseCluster(scope, "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_02_0),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.LARGE),
        ),
        deletion_protection=False  # Explicitly disabled deletion protection
    )
    return cluster


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "ProductionDB",
        engine=rds.DatabaseInstanceEngine.oracle_ee(version=rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
        multi_az=True,
        storage_encrypted=True,
        # Missing deletion_protection
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "Database",
        engine=rds.DatabaseInstanceEngine.sql_server_ee(version=rds.SqlServerEngineVersion.VER_15_00_4073_23_V1),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
        allocated_storage=200,
        storage_type=rds.StorageType.IO1,
        iops=1000,
        deletion_protection=False
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    cluster = rds.DatabaseCluster(scope, "AuroraServerlessCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_13_4),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        ),
        serverless_v2_min_capacity=0.5,
        serverless_v2_max_capacity=4,
        # Missing deletion_protection
    )
    return cluster


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "MariaDBInstance",
        engine=rds.DatabaseInstanceEngine.maria_db(version=rds.MariaDbEngineVersion.VER_10_6_8),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        backup_retention=Duration.days(7),
        deletion_protection=False
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    from_snapshot = rds.DatabaseInstanceFromSnapshot(scope, "DatabaseFromSnapshot",
        snapshot_identifier="my-snapshot-id",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        # Missing deletion_protection
    )
    return from_snapshot


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    cluster = rds.DatabaseCluster(scope, "GlobalCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_02_0),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        ),
        instances=2,
        deletion_protection=False,
        removal_policy=RemovalPolicy.SNAPSHOT
    )
    return cluster


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "HighPerformanceDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.XLARGE),
        storage_encrypted=True,
        multi_az=True,
        removal_policy=RemovalPolicy.SNAPSHOT,
        # Missing deletion_protection
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "CriticalDB",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.M6G, ec2.InstanceSize.LARGE),
        allocated_storage=500,
        storage_type=rds.StorageType.GP3,
        backup_retention=Duration.days(30),
        deletion_protection=False
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    cluster = rds.DatabaseCluster(scope, "MultiRegionCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_14_3),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
        ),
        instances=3,
        storage_encrypted=True,
        # Missing deletion_protection
    )
    return cluster


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "FinanceDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
        credentials=rds.Credentials.from_generated_secret("admin"),
        security_groups=[ec2.SecurityGroup.from_security_group_id(scope, "SG", "sg-12345")],
        deletion_protection=False
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-deletion-protection-enabled
    cluster = rds.DatabaseCluster(scope, "DataWarehouseCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_02_0),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.XLARGE),
        ),
        parameter_group=rds.ParameterGroup.from_parameter_group_name(
            scope, "ParameterGroup", "default.aurora-mysql8.0"
        ),
        # Missing deletion_protection
    )
    return cluster


# True Negatives (Secure Code Examples)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        deletion_protection=True  # Explicitly enabled deletion protection
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    cluster = rds.DatabaseCluster(scope, "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_13_4),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        ),
        deletion_protection=True  # Explicitly enabled deletion protection
    )
    return cluster


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "ProductionDB",
        engine=rds.DatabaseInstanceEngine.oracle_ee(version=rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
        multi_az=True,
        storage_encrypted=True,
        deletion_protection=True  # Explicitly enabled deletion protection
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    cluster = rds.DatabaseCluster(scope, "AuroraServerlessCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_13_4),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        ),
        serverless_v2_min_capacity=0.5,
        serverless_v2_max_capacity=4,
        deletion_protection=True  # Explicitly enabled deletion protection
    )
    return cluster


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    from_snapshot = rds.DatabaseInstanceFromSnapshot(scope, "DatabaseFromSnapshot",
        snapshot_identifier="my-snapshot-id",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        deletion_protection=True  # Explicitly enabled deletion protection
    )
    return from_snapshot


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "Database",
        engine=rds.DatabaseInstanceEngine.sql_server_ee(version=rds.SqlServerEngineVersion.VER_15_00_4073_23_V1),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.XLARGE),
        allocated_storage=200,
        storage_type=rds.StorageType.IO1,
        iops=1000,
        deletion_protection=True  # Explicitly enabled deletion protection
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "MariaDBInstance",
        engine=rds.DatabaseInstanceEngine.maria_db(version=rds.MariaDbEngineVersion.VER_10_6_8),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        backup_retention=Duration.days(7),
        deletion_protection=True  # Explicitly enabled deletion protection
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    cluster = rds.DatabaseCluster(scope, "GlobalCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_02_0),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        ),
        instances=2,
        deletion_protection=True,  # Explicitly enabled deletion protection
        removal_policy=RemovalPolicy.SNAPSHOT
    )
    return cluster


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "HighPerformanceDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.XLARGE),
        storage_encrypted=True,
        multi_az=True,
        removal_policy=RemovalPolicy.SNAPSHOT,
        deletion_protection=True  # Explicitly enabled deletion protection
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "CriticalDB",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.M6G, ec2.InstanceSize.LARGE),
        allocated_storage=500,
        storage_type=rds.StorageType.GP3,
        backup_retention=Duration.days(30),
        deletion_protection=True  # Explicitly enabled deletion protection
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    cluster = rds.DatabaseCluster(scope, "MultiRegionCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_14_3),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.XLARGE),
        ),
        instances=3,
        storage_encrypted=True,
        deletion_protection=True  # Explicitly enabled deletion protection
    )
    return cluster


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "FinanceDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
        credentials=rds.Credentials.from_generated_secret("admin"),
        security_groups=[ec2.SecurityGroup.from_security_group_id(scope, "SG", "sg-12345")],
        deletion_protection=True  # Explicitly enabled deletion protection
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-deletion-protection-enabled
    cluster = rds.DatabaseCluster(scope, "DataWarehouseCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_02_0),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.R6G, ec2.InstanceSize.XLARGE),
        ),
        parameter_group=rds.ParameterGroup.from_parameter_group_name(
            scope, "ParameterGroup", "default.aurora-mysql8.0"
        ),
        deletion_protection=True  # Explicitly enabled deletion protection
    )
    return cluster


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Define deletion protection as a variable to ensure it's enabled
    enable_deletion_protection = True
    
    # ok: python-cdk-rds-deletion-protection-enabled
    instance = rds.DatabaseInstance(scope, "ConfigurableDB",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
        deletion_protection=enable_deletion_protection  # Using a variable that's set to True
    )
    return instance


# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Define environment-specific configuration
    is_production = True
    
    # ok: python-cdk-rds-deletion-protection-enabled
    cluster = rds.DatabaseCluster(scope, "EnvironmentSpecificCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_14_3),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        ),
        instances=2,
        deletion_protection=is_production  # In production environments, this will be True
    )
    return cluster


# {/fact}

class MyStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Example usage of the functions
        vpc = ec2.Vpc(self, "VPC")
        
        # Secure database with deletion protection
        secure_db = good_case_1(self, "SecureDB")
        
        # Vulnerable database without deletion protection
        vulnerable_db = bad_case_1(self, "VulnerableDB")
        
        CfnOutput(self, "SecureDBEndpoint", value=secure_db.db_instance_endpoint_address)
        CfnOutput(self, "VulnerableDBEndpoint", value=vulnerable_db.db_instance_endpoint_address)


app = cdk.App()
MyStack(app, "RdsDeletionProtectionStack")
app.synth()