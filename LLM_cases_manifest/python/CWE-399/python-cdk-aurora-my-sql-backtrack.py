import aws_cdk as cdk
from aws_cdk import (
    aws_rds as rds,
    aws_ec2 as ec2,
    Stack,
    Duration,
    RemovalPolicy,
)
from constructs import Construct

# True Positives (Vulnerable Code - Missing Backtrack Configuration)

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraMySQLCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_01_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
        ),
        removal_policy=RemovalPolicy.DESTROY,
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "Database",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_10_2
        ),
        credentials=rds.Credentials.from_generated_secret("admin"),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE
            ),
        ),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_02_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL
            ),
        ),
        backup=rds.BackupProps(
            retention=Duration.days(7),
            preferred_window="03:00-04:00",
        ),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    subnet_group = rds.SubnetGroup(
        scope,
        "SubnetGroup",
        description="Subnet group for Aurora cluster",
        vpc=vpc,
    )
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_07_1
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.XLARGE
            ),
        ),
        subnet_group=subnet_group,
        default_database_name="mydb",
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_01_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
        ),
        storage_encrypted=True,
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_10_2
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE
            ),
        ),
        backup=rds.BackupProps(
            retention=Duration.days(14),
        ),
        parameter_group=rds.ParameterGroup.from_parameter_group_name(
            scope, "ParameterGroup", "default.aurora-mysql5.7"
        ),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_02_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
        ),
        instances=2,
        storage_encrypted=True,
        deletion_protection=True,
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_10_2
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE
            ),
        ),
        port=3306,
        default_database_name="myapp",
        removal_policy=RemovalPolicy.SNAPSHOT,
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_01_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
        ),
        backup=rds.BackupProps(
            retention=Duration.days(30),
            preferred_window="01:00-02:00",
        ),
        preferred_maintenance_window="sat:03:00-sat:04:00",
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_07_1
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.XLARGE
            ),
        ),
        instances=3,
        storage_encrypted=True,
        cloudwatch_logs_exports=["audit", "error", "general", "slowquery"],
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    security_group = ec2.SecurityGroup(scope, "SecurityGroup", vpc=vpc)
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_02_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
            security_groups=[security_group],
        ),
        default_database_name="application",
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_10_2
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE
            ),
        ),
        storage_encrypted=True,
        deletion_protection=True,
        copy_tags_to_snapshot=True,
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_01_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
        ),
        instances=2,
        iam_authentication=True,
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_07_1
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.XLARGE
            ),
        ),
        storage_encrypted=True,
        enable_performance_insights=True,
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_02_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
        ),
        backup=rds.BackupProps(
            retention=Duration.days(35),
        ),
        monitoring_interval=Duration.seconds(60),
    )
    
    return cluster

# True Negatives (Secure Code - With Backtrack Configuration)

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraMySQLCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_01_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
        ),
        removal_policy=RemovalPolicy.DESTROY,
        backtrack_window=Duration.hours(24),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "Database",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_10_2
        ),
        credentials=rds.Credentials.from_generated_secret("admin"),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE
            ),
        ),
        backtrack_window=Duration.hours(48),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_02_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL
            ),
        ),
        backup=rds.BackupProps(
            retention=Duration.days(7),
            preferred_window="03:00-04:00",
        ),
        backtrack_window=Duration.hours(72),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    subnet_group = rds.SubnetGroup(
        scope,
        "SubnetGroup",
        description="Subnet group for Aurora cluster",
        vpc=vpc,
    )
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_07_1
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.XLARGE
            ),
        ),
        subnet_group=subnet_group,
        default_database_name="mydb",
        backtrack_window=Duration.hours(12),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_01_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
        ),
        storage_encrypted=True,
        backtrack_window=Duration.days(1),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_10_2
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE
            ),
        ),
        backup=rds.BackupProps(
            retention=Duration.days(14),
        ),
        parameter_group=rds.ParameterGroup.from_parameter_group_name(
            scope, "ParameterGroup", "default.aurora-mysql5.7"
        ),
        backtrack_window=Duration.hours(36),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_02_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
        ),
        instances=2,
        storage_encrypted=True,
        deletion_protection=True,
        backtrack_window=Duration.hours(24),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_10_2
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE
            ),
        ),
        port=3306,
        default_database_name="myapp",
        removal_policy=RemovalPolicy.SNAPSHOT,
        backtrack_window=Duration.hours(24),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_01_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
        ),
        backup=rds.BackupProps(
            retention=Duration.days(30),
            preferred_window="01:00-02:00",
        ),
        preferred_maintenance_window="sat:03:00-sat:04:00",
        backtrack_window=Duration.hours(48),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_07_1
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.XLARGE
            ),
        ),
        instances=3,
        storage_encrypted=True,
        cloudwatch_logs_exports=["audit", "error", "general", "slowquery"],
        backtrack_window=Duration.hours(72),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    security_group = ec2.SecurityGroup(scope, "SecurityGroup", vpc=vpc)
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_02_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
            security_groups=[security_group],
        ),
        default_database_name="application",
        backtrack_window=Duration.hours(24),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_10_2
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE
            ),
        ),
        storage_encrypted=True,
        deletion_protection=True,
        copy_tags_to_snapshot=True,
        backtrack_window=Duration.hours(24),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_01_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
        ),
        instances=2,
        iam_authentication=True,
        backtrack_window=Duration.hours(24),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_2_07_1
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.MEMORY5, ec2.InstanceSize.XLARGE
            ),
        ),
        storage_encrypted=True,
        enable_performance_insights=True,
        backtrack_window=Duration.hours(24),
    )
    
    return cluster

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-aurora-my-sql-backtrack
    cluster = rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(
            version=rds.AuroraMysqlEngineVersion.VER_3_02_0
        ),
        instance_props=rds.InstanceProps(
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM
            ),
        ),
        backup=rds.BackupProps(
            retention=Duration.days(35),
        ),
        monitoring_interval=Duration.seconds(60),
        backtrack_window=Duration.hours(24),
    )
    
    return cluster
# {/fact}