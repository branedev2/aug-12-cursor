import aws_cdk as cdk
from aws_cdk import (
    aws_ec2 as ec2,
    aws_rds as rds,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy,
)
from constructs import Construct


# True Positives (Vulnerable Cases)

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    security_group = ec2.SecurityGroup(
        scope,
        "DatabaseSecurityGroup",
        vpc=vpc,
        description="Allow database access",
    )
    security_group.add_ingress_rule(
        ec2.Peer.ipv4("0.0.0.0/0"),
        ec2.Port.tcp(3306),
        "Allow MySQL access from anywhere"
    )
    
    rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[security_group],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    db_security_group = ec2.SecurityGroup(
        scope,
        "PostgresSecurityGroup",
        vpc=vpc,
        description="Security group for Postgres database",
        allow_all_outbound=True,
    )
    
    db_security_group.add_ingress_rule(
        peer=ec2.Peer.ipv4('0.0.0.0/0'),
        connection=ec2.Port.tcp(5432),
        description="Allow Postgres traffic from anywhere"
    )
    
    rds.DatabaseInstance(
        scope,
        "PostgresDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        vpc=vpc,
        security_groups=[db_security_group],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "SecurityGroup", vpc=vpc)
    
    # Multiple ingress rules with one being open to the world
    sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(3306), "Allow internal access")
    sg.add_ingress_rule(ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.tcp(3306), "Allow public access")
    
    rds.DatabaseInstance(
        scope,
        "MySQLDatabase",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    security_group = ec2.SecurityGroup(
        scope,
        "OracleDBSecurityGroup",
        vpc=vpc,
        description="Security group for Oracle database",
    )
    
    # Using a variable for the CIDR but still allowing all IPs
    all_ips = "0.0.0.0/0"
    security_group.add_ingress_rule(
        ec2.Peer.ipv4(all_ips),
        ec2.Port.tcp(1521),
        "Allow Oracle access from anywhere"
    )
    
    rds.DatabaseInstance(
        scope,
        "OracleDB",
        engine=rds.DatabaseInstanceEngine.oracle(version=rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1),
        vpc=vpc,
        security_groups=[security_group],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.LARGE),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "SQLServerSG", vpc=vpc)
    
    # Allow SQL Server access from anywhere
    sg.add_ingress_rule(
        ec2.Peer.ipv4("0.0.0.0/0"),
        ec2.Port.tcp(1433),
        "Allow SQL Server access"
    )
    
    rds.DatabaseInstance(
        scope,
        "SQLServerDB",
        engine=rds.DatabaseInstanceEngine.sql_server_ex(version=rds.SqlServerEngineVersion.VER_15_00_4073_23_V1),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    security_group = ec2.SecurityGroup(scope, "MariaDBSG", vpc=vpc)
    
    # Using a port range that includes the MariaDB port
    security_group.add_ingress_rule(
        ec2.Peer.ipv4("0.0.0.0/0"),
        ec2.Port.tcp_range(3000, 4000),  # Includes MariaDB port 3306
        "Allow access to various services including MariaDB"
    )
    
    rds.DatabaseInstance(
        scope,
        "MariaDB",
        engine=rds.DatabaseInstanceEngine.maria_db(version=rds.MariaDbEngineVersion.VER_10_6_8),
        vpc=vpc,
        security_groups=[security_group],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "AuroraSG", vpc=vpc)
    
    # Allow access to Aurora MySQL
    sg.add_ingress_rule(
        ec2.Peer.any_ipv4(),  # This is equivalent to 0.0.0.0/0
        ec2.Port.tcp(3306),
        "Allow Aurora MySQL access from anywhere"
    )
    
    rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_02_0),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "AuroraPostgresSG", vpc=vpc)
    
    # Allow access to Aurora PostgreSQL
    sg.add_ingress_rule(
        ec2.Peer.ipv4("0.0.0.0/0"),
        ec2.Port.tcp(5432),
        "Allow Aurora PostgreSQL access from anywhere"
    )
    
    rds.DatabaseCluster(
        scope,
        "AuroraPostgresCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_13_7),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "MultiDBSG", vpc=vpc)
    
    # Multiple ports open to the world
    sg.add_ingress_rule(ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.tcp(3306), "MySQL")
    sg.add_ingress_rule(ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.tcp(5432), "PostgreSQL")
    sg.add_ingress_rule(ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.tcp(1521), "Oracle")
    
    rds.DatabaseInstance(
        scope,
        "MultiPurposeDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.LARGE),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "DBSecurityGroup", vpc=vpc)
    
    # Using a method that creates the security group with an open ingress rule
    def configure_security_group(security_group):
        security_group.add_ingress_rule(
            ec2.Peer.ipv4("0.0.0.0/0"),
            ec2.Port.tcp(3306),
            "Allow MySQL access from anywhere"
        )
    
    configure_security_group(sg)
    
    rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "DBSecurityGroup", vpc=vpc)
    
    # Using conditional logic but still allowing open access
    env = "dev"  # This could come from environment variables or parameters
    if env == "dev":
        sg.add_ingress_rule(
            ec2.Peer.ipv4("0.0.0.0/0"),
            ec2.Port.tcp(3306),
            "Allow MySQL access from anywhere in dev environment"
        )
    else:
        sg.add_ingress_rule(
            ec2.Peer.ipv4("10.0.0.0/16"),
            ec2.Port.tcp(3306),
            "Allow MySQL access from internal network in prod"
        )
    
    rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "DBSecurityGroup", vpc=vpc)
    
    # Using a list of CIDRs including the open one
    cidrs = ["10.0.0.0/16", "172.16.0.0/12", "0.0.0.0/0"]
    for cidr in cidrs:
        sg.add_ingress_rule(
            ec2.Peer.ipv4(cidr),
            ec2.Port.tcp(3306),
            f"Allow MySQL access from {cidr}"
        )
    
    rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "DBSecurityGroup", vpc=vpc)
    
    # Using security group from props but still adding open rule
    sg.add_ingress_rule(
        ec2.Peer.ipv4("0.0.0.0/0"),
        ec2.Port.tcp(3306),
        "Allow MySQL access from anywhere"
    )
    
    # Creating a serverless Aurora cluster with the insecure security group
    rds.ServerlessCluster(
        scope,
        "AuroraServerlessCluster",
        engine=rds.DatabaseClusterEngine.AURORA_MYSQL,
        vpc=vpc,
        security_groups=[sg],
        scaling=rds.ServerlessScalingOptions(
            auto_pause=Duration.minutes(10),
            min_capacity=rds.AuroraCapacityUnit.ACU_8,
            max_capacity=rds.AuroraCapacityUnit.ACU_32,
        ),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "DBSecurityGroup", vpc=vpc)
    
    # Using security group with IPv6 any
    sg.add_ingress_rule(
        ec2.Peer.ipv6("::/0"),  # This is the IPv6 equivalent of 0.0.0.0/0
        ec2.Port.tcp(3306),
        "Allow MySQL access from any IPv6 address"
    )
    
    rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "DBSecurityGroup", vpc=vpc)
    
    # Using both IPv4 and IPv6 any addresses
    sg.add_ingress_rule(
        ec2.Peer.ipv4("0.0.0.0/0"),
        ec2.Port.tcp(3306),
        "Allow MySQL access from any IPv4 address"
    )
    sg.add_ingress_rule(
        ec2.Peer.ipv6("::/0"),
        ec2.Port.tcp(3306),
        "Allow MySQL access from any IPv6 address"
    )
    
    rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# True Negatives (Secure Cases)

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    security_group = ec2.SecurityGroup(
        scope,
        "DatabaseSecurityGroup",
        vpc=vpc,
        description="Allow database access",
    )
    security_group.add_ingress_rule(
        ec2.Peer.ipv4("10.0.0.0/16"),
        ec2.Port.tcp(3306),
        "Allow MySQL access from internal network only"
    )
    
    rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[security_group],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    db_security_group = ec2.SecurityGroup(
        scope,
        "PostgresSecurityGroup",
        vpc=vpc,
        description="Security group for Postgres database",
        allow_all_outbound=True,
    )
    
    # Allow access only from specific security group
    app_security_group = ec2.SecurityGroup(scope, "AppSecurityGroup", vpc=vpc)
    db_security_group.add_ingress_rule(
        ec2.Peer.security_group_id(app_security_group.security_group_id),
        ec2.Port.tcp(5432),
        "Allow Postgres traffic from application servers only"
    )
    
    rds.DatabaseInstance(
        scope,
        "PostgresDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_13_4),
        vpc=vpc,
        security_groups=[db_security_group],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "SecurityGroup", vpc=vpc)
    
    # Multiple ingress rules but all restricted to specific networks
    sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(3306), "Allow internal access")
    sg.add_ingress_rule(ec2.Peer.ipv4("192.168.1.0/24"), ec2.Port.tcp(3306), "Allow VPN access")
    
    rds.DatabaseInstance(
        scope,
        "MySQLDatabase",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    security_group = ec2.SecurityGroup(
        scope,
        "OracleDBSecurityGroup",
        vpc=vpc,
        description="Security group for Oracle database",
    )
    
    # Using a variable for the CIDR with a restricted range
    internal_cidr = "10.0.0.0/8"
    security_group.add_ingress_rule(
        ec2.Peer.ipv4(internal_cidr),
        ec2.Port.tcp(1521),
        "Allow Oracle access from internal network"
    )
    
    rds.DatabaseInstance(
        scope,
        "OracleDB",
        engine=rds.DatabaseInstanceEngine.oracle(version=rds.OracleEngineVersion.VER_19_0_0_0_2021_04_R1),
        vpc=vpc,
        security_groups=[security_group],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.LARGE),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "SQLServerSG", vpc=vpc)
    
    # Allow SQL Server access only from VPC CIDR
    sg.add_ingress_rule(
        ec2.Peer.ipv4(vpc.vpc_cidr_block),
        ec2.Port.tcp(1433),
        "Allow SQL Server access from within VPC"
    )
    
    rds.DatabaseInstance(
        scope,
        "SQLServerDB",
        engine=rds.DatabaseInstanceEngine.sql_server_ex(version=rds.SqlServerEngineVersion.VER_15_00_4073_23_V1),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    security_group = ec2.SecurityGroup(scope, "MariaDBSG", vpc=vpc)
    
    # Using a port range but restricting access to specific IPs
    security_group.add_ingress_rule(
        ec2.Peer.ipv4("10.0.0.0/16"),
        ec2.Port.tcp_range(3000, 4000),  # Includes MariaDB port 3306
        "Allow access to various services including MariaDB from internal network"
    )
    
    rds.DatabaseInstance(
        scope,
        "MariaDB",
        engine=rds.DatabaseInstanceEngine.maria_db(version=rds.MariaDbEngineVersion.VER_10_6_8),
        vpc=vpc,
        security_groups=[security_group],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "AuroraSG", vpc=vpc)
    
    # Allow access to Aurora MySQL from specific prefixes
    for i in range(1, 4):
        sg.add_ingress_rule(
            ec2.Peer.ipv4(f"10.{i}.0.0/16"),
            ec2.Port.tcp(3306),
            f"Allow Aurora MySQL access from 10.{i}.0.0/16"
        )
    
    rds.DatabaseCluster(
        scope,
        "AuroraCluster",
        engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_02_0),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "AuroraPostgresSG", vpc=vpc)
    
    # Create a bastion host security group and allow access only from it
    bastion_sg = ec2.SecurityGroup(scope, "BastionSG", vpc=vpc)
    
    sg.add_ingress_rule(
        ec2.Peer.security_group_id(bastion_sg.security_group_id),
        ec2.Port.tcp(5432),
        "Allow Aurora PostgreSQL access only through bastion host"
    )
    
    rds.DatabaseCluster(
        scope,
        "AuroraPostgresCluster",
        engine=rds.DatabaseClusterEngine.aurora_postgres(version=rds.AuroraPostgresEngineVersion.VER_13_7),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.R5, ec2.InstanceSize.LARGE),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "MultiDBSG", vpc=vpc)
    
    # Multiple ports but all restricted to specific networks
    sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(3306), "MySQL from internal")
    sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(5432), "PostgreSQL from internal")
    sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(1521), "Oracle from internal")
    
    rds.DatabaseInstance(
        scope,
        "MultiPurposeDB",
        engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_14_3),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.LARGE),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "DBSecurityGroup", vpc=vpc)
    
    # Using a method that creates the security group with a restricted ingress rule
    def configure_security_group(security_group):
        security_group.add_ingress_rule(
            ec2.Peer.ipv4("10.0.0.0/16"),
            ec2.Port.tcp(3306),
            "Allow MySQL access from internal network"
        )
    
    configure_security_group(sg)
    
    rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "DBSecurityGroup", vpc=vpc)
    
    # Using conditional logic to always restrict access
    env = "dev"  # This could come from environment variables or parameters
    if env == "dev":
        sg.add_ingress_rule(
            ec2.Peer.ipv4("192.168.1.0/24"),
            ec2.Port.tcp(3306),
            "Allow MySQL access from developer network in dev environment"
        )
    else:
        sg.add_ingress_rule(
            ec2.Peer.ipv4("10.0.0.0/16"),
            ec2.Port.tcp(3306),
            "Allow MySQL access from internal network in prod"
        )
    
    rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "DBSecurityGroup", vpc=vpc)
    
    # Using a list of CIDRs with no open ones
    cidrs = ["10.0.0.0/16", "172.16.0.0/12", "192.168.0.0/16"]
    for cidr in cidrs:
        sg.add_ingress_rule(
            ec2.Peer.ipv4(cidr),
            ec2.Port.tcp(3306),
            f"Allow MySQL access from {cidr}"
        )
    
    rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "DBSecurityGroup", vpc=vpc)
    
    # Using security group from props with restricted rules
    sg.add_ingress_rule(
        ec2.Peer.ipv4("10.0.0.0/16"),
        ec2.Port.tcp(3306),
        "Allow MySQL access from internal network"
    )
    
    # Creating a serverless Aurora cluster with the secure security group
    rds.ServerlessCluster(
        scope,
        "AuroraServerlessCluster",
        engine=rds.DatabaseClusterEngine.AURORA_MYSQL,
        vpc=vpc,
        security_groups=[sg],
        scaling=rds.ServerlessScalingOptions(
            auto_pause=Duration.minutes(10),
            min_capacity=rds.AuroraCapacityUnit.ACU_8,
            max_capacity=rds.AuroraCapacityUnit.ACU_32,
        ),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "DBSecurityGroup", vpc=vpc)
    
    # Using security group with restricted IPv6
    sg.add_ingress_rule(
        ec2.Peer.ipv6("2001:db8::/32"),  # This is a specific IPv6 range
        ec2.Port.tcp(3306),
        "Allow MySQL access from specific IPv6 range"
    )
    
    rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )


# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python-cdk-allows-rds-db-security-group-for-inbound-access
    sg = ec2.SecurityGroup(scope, "DBSecurityGroup", vpc=vpc)
    
    # No ingress rules defined at all (default deny all)
    # This is secure because by default, security groups deny all inbound traffic
    
    rds.DatabaseInstance(
        scope,
        "Database",
        engine=rds.DatabaseInstanceEngine.mysql(version=rds.MysqlEngineVersion.VER_8_0_28),
        vpc=vpc,
        security_groups=[sg],
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
    )
# {/fact}