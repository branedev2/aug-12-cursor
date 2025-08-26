import aws_cdk as cdk
from aws_cdk import (
    aws_rds as rds,
    aws_ec2 as ec2,
    Stack,
    Duration,
    CfnOutput,
)
from constructs import Construct

# True Positives (Vulnerable Cases)

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "MyDatabase",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        port=3306,  # Default MySQL port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-non-default-port
    cluster = rds.DatabaseCluster(
        scope, "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_02_0),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        ),
        port=3306,  # Default Aurora MySQL port
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "PostgresDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        port=5432,  # Default PostgreSQL port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "SQLServerDB",
        engine=rds.DatabaseInstanceEngine.sql_server_ee(version=rds.SqlServerEngineVersion.VER_15),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.XLARGE),
        vpc=vpc,
        port=1433,  # Default SQL Server port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-non-default-port
    cluster = rds.DatabaseCluster(
        scope, "AuroraPostgresCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_13_7),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        ),
        port=5432,  # Default Aurora PostgreSQL port
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "MariaDB",
        engine=rds.DatabaseInstanceEngine.maria_db(version=rds.MariaDbEngineVersion.VER_10_6_8),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        port=3306,  # Default MariaDB port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    subnet_group = rds.SubnetGroup(scope, "SubnetGroup", vpc=vpc, description="RDS subnet group")
    # ruleid: python-cdk-rds-non-default-port
    cluster = rds.CfnDBCluster(
        scope, "AuroraClusterCfn",
        engine="aurora-mysql",
        engine_version="8.0.mysql_aurora.3.02.0",
        db_subnet_group_name=subnet_group.subnet_group_name,
        port=3306,  # Default Aurora MySQL port
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-non-default-port
    instance = rds.CfnDBInstance(
        scope, "PostgresCfnInstance",
        engine="postgres",
        db_instance_class="db.t3.medium",
        allocated_storage="20",
        port="5432",  # Default PostgreSQL port as string
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Create a parameter group first
    parameter_group = rds.ParameterGroup(
        scope, "ParameterGroup",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
    )
    # ruleid: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "MySQLWithParams",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        parameter_group=parameter_group,
        port=3306,  # Default MySQL port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstanceFromSnapshot(
        scope, "RestoreFromSnapshot",
        snapshot_identifier="my-snapshot-id",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
        vpc=vpc,
        port=5432,  # Default PostgreSQL port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    security_group = ec2.SecurityGroup(scope, "SecurityGroup", vpc=vpc)
    # ruleid: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "MySQLWithSG",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        security_groups=[security_group],
        port=3306,  # Default MySQL port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-non-default-port
    cluster = rds.ServerlessCluster(
        scope, "AuroraServerless",
        engine=rds.DatabaseClusterEngine.AURORA_POSTGRESQL,
        vpc=vpc,
        scaling=rds.ServerlessScalingOptions(
            auto_pause=Duration.minutes(10),
            min_capacity=rds.AuroraCapacityUnit.ACU_2,
            max_capacity=rds.AuroraCapacityUnit.ACU_16,
        ),
        port=5432,  # Default PostgreSQL port
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "OracleDB",
        engine=rds.DatabaseInstanceEngine.oracle_ee(version=rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
        vpc=vpc,
        port=1521,  # Default Oracle port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Define the port separately but still using default
    db_port = 3306
    # ruleid: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "MySQLWithVariablePort",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        port=db_port,  # Default MySQL port via variable
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Using integer conversion but still default port
    port_str = "5432"
    # ruleid: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "PostgresWithConvertedPort",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        port=int(port_str),  # Default PostgreSQL port via conversion
    )
    return instance

# True Negatives (Secure Cases)

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "MyDatabase",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        vpc=vpc,
        port=3307,  # Non-default MySQL port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-non-default-port
    cluster = rds.DatabaseCluster(
        scope, "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_02_0),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        ),
        port=3307,  # Non-default Aurora MySQL port
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "PostgresDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        port=5433,  # Non-default PostgreSQL port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "SQLServerDB",
        engine=rds.DatabaseInstanceEngine.sql_server_ee(version=rds.SqlServerEngineVersion.VER_15),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.XLARGE),
        vpc=vpc,
        port=1434,  # Non-default SQL Server port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-non-default-port
    cluster = rds.DatabaseCluster(
        scope, "AuroraPostgresCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_13_7),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
        ),
        port=5433,  # Non-default Aurora PostgreSQL port
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "MariaDB",
        engine=rds.DatabaseInstanceEngine.maria_db(version=rds.MariaDbEngineVersion.VER_10_6_8),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        port=3308,  # Non-default MariaDB port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    subnet_group = rds.SubnetGroup(scope, "SubnetGroup", vpc=vpc, description="RDS subnet group")
    # ok: python-cdk-rds-non-default-port
    cluster = rds.CfnDBCluster(
        scope, "AuroraClusterCfn",
        engine="aurora-mysql",
        engine_version="8.0.mysql_aurora.3.02.0",
        db_subnet_group_name=subnet_group.subnet_group_name,
        port=3310,  # Non-default Aurora MySQL port
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-non-default-port
    instance = rds.CfnDBInstance(
        scope, "PostgresCfnInstance",
        engine="postgres",
        db_instance_class="db.t3.medium",
        allocated_storage="20",
        port="5435",  # Non-default PostgreSQL port as string
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Create a parameter group first
    parameter_group = rds.ParameterGroup(
        scope, "ParameterGroup",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
    )
    # ok: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "MySQLWithParams",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        parameter_group=parameter_group,
        port=3309,  # Non-default MySQL port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstanceFromSnapshot(
        scope, "RestoreFromSnapshot",
        snapshot_identifier="my-snapshot-id",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.LARGE),
        vpc=vpc,
        port=5438,  # Non-default PostgreSQL port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    security_group = ec2.SecurityGroup(scope, "SecurityGroup", vpc=vpc)
    # ok: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "MySQLWithSG",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        security_groups=[security_group],
        port=13306,  # Non-default MySQL port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-non-default-port
    cluster = rds.ServerlessCluster(
        scope, "AuroraServerless",
        engine=rds.DatabaseClusterEngine.AURORA_POSTGRESQL,
        vpc=vpc,
        scaling=rds.ServerlessScalingOptions(
            auto_pause=Duration.minutes(10),
            min_capacity=rds.AuroraCapacityUnit.ACU_2,
            max_capacity=rds.AuroraCapacityUnit.ACU_16,
        ),
        port=15432,  # Non-default PostgreSQL port
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "OracleDB",
        engine=rds.DatabaseInstanceEngine.oracle_ee(version=rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.M5, ec2.InstanceSize.LARGE),
        vpc=vpc,
        port=1522,  # Non-default Oracle port
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Define a non-default port
    db_port = 3310
    # ok: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "MySQLWithVariablePort",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        port=db_port,  # Non-default MySQL port via variable
    )
    return instance

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Using integer conversion with non-default port
    port_str = "5439"
    # ok: python-cdk-rds-non-default-port
    instance = rds.DatabaseInstance(
        scope, "PostgresWithConvertedPort",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
        vpc=vpc,
        port=int(port_str),  # Non-default PostgreSQL port via conversion
    )
    return instance

# {/fact}

class MyStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Example usage
        bad_instance = bad_case_1(self, "BadInstance1")
        good_instance = good_case_1(self, "GoodInstance1")

app = cdk.App()
MyStack(app, "RDSPortSecurityStack")
app.synth()