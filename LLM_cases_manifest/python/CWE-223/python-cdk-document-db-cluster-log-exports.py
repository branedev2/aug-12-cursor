import aws_cdk as cdk
from aws_cdk import (
    aws_docdb as docdb,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy,
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster1",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVpc"),
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster2",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVpc"),
        enable_cloudwatch_logs_exports=[],  # Empty list
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster3",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVpc"),
        enable_cloudwatch_logs_exports=["authenticate"],  # Missing createIndex and dropCollection
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster4",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVpc"),
        enable_cloudwatch_logs_exports=["createIndex"],  # Missing authenticate and dropCollection
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster5",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVpc"),
        enable_cloudwatch_logs_exports=["dropCollection"],  # Missing authenticate and createIndex
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster6",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVpc"),
        enable_cloudwatch_logs_exports=["authenticate", "createIndex"],  # Missing dropCollection
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster7",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVpc"),
        enable_cloudwatch_logs_exports=["authenticate", "dropCollection"],  # Missing createIndex
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster8",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVpc"),
        enable_cloudwatch_logs_exports=["createIndex", "dropCollection"],  # Missing authenticate
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a more complex stack with a DocumentDB cluster
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc9")
    security_group = cdk.aws_ec2.SecurityGroup(
        scope, "DocDBSecurityGroup9",
        vpc=vpc,
        description="Security group for DocumentDB cluster"
    )
    
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster9",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        security_group=security_group,
        instances=2,
        removal_policy=RemovalPolicy.DESTROY,
        # No enable_cloudwatch_logs_exports specified
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc10")
    
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster10",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        instances=3,
        backup=docdb.BackupProps(
            retention=Duration.days(7),
        ),
        enable_cloudwatch_logs_exports=["audit"],  # Using a different log type, missing required ones
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc11")
    
    # Define parameter group
    parameter_group = docdb.ClusterParameterGroup(
        scope, "DocDBParameterGroup11",
        description="Custom parameter group for DocumentDB",
        parameters={
            "tls": "enabled",
            "audit_logs": "enabled"
        }
    )
    
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster11",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        parameter_group=parameter_group,
        # No enable_cloudwatch_logs_exports specified
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc12")
    
    # Define a function to create cluster
    def create_cluster():
        # ruleid: python-cdk-document-db-cluster-log-exports
        return docdb.DatabaseCluster(
            scope, "MyDocDBCluster12",
            master_user=docdb.Login(
                username="admin",
            ),
            instance_type=docdb.InstanceType.R5_LARGE,
            vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
            vpc=vpc,
            enable_cloudwatch_logs_exports=["profiler"],  # Wrong log type
            removal_policy=RemovalPolicy.DESTROY,
        )
    
    cluster = create_cluster()
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc13")
    
    # Using a list variable for log exports
    log_exports = ["profiler", "slowquery"]  # Missing required log exports
    
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster13",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        enable_cloudwatch_logs_exports=log_exports,
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc14")
    
    # Using conditional logic but still missing required logs
    environment = "dev"
    log_exports = []
    
    if environment == "prod":
        log_exports = ["authenticate", "createIndex", "dropCollection"]
    else:
        log_exports = ["profiler"]  # Missing required logs in non-prod
    
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster14",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        enable_cloudwatch_logs_exports=log_exports,
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc15")
    
    # Using L1 construct (lower level)
    # ruleid: python-cdk-document-db-cluster-log-exports
    cluster = docdb.CfnDBCluster(
        scope, "MyDocDBCluster15",
        storage_encrypted=True,
        availability_zones=["us-east-1a", "us-east-1b", "us-east-1c"],
        db_cluster_identifier="my-docdb-cluster",
        engine="docdb",
        master_username="admin",
        master_user_password="password123",
        vpc_security_group_ids=["sg-12345"],
        enable_cloudwatch_logs_exports=["audit"],  # Missing required logs
    )
    return cluster

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster1",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVpc"),
        enable_cloudwatch_logs_exports=["authenticate", "createIndex", "dropCollection"],
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster2",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVpc"),
        enable_cloudwatch_logs_exports=["authenticate", "createIndex", "dropCollection", "profiler"],  # Additional logs are fine
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc3")
    
    # Using a variable for log exports
    log_exports = ["authenticate", "createIndex", "dropCollection"]
    
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster3",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        enable_cloudwatch_logs_exports=log_exports,
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc4")
    
    # Using a function to get log exports
    def get_log_exports():
        return ["authenticate", "createIndex", "dropCollection", "profiler", "slowquery"]
    
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster4",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        enable_cloudwatch_logs_exports=get_log_exports(),
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc5")
    
    # Using conditional logic with all required logs
    environment = "dev"
    log_exports = ["authenticate", "createIndex", "dropCollection"]
    
    if environment == "prod":
        log_exports.extend(["profiler", "slowquery"])
    
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster5",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        enable_cloudwatch_logs_exports=log_exports,
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc6")
    security_group = cdk.aws_ec2.SecurityGroup(
        scope, "DocDBSecurityGroup6",
        vpc=vpc,
        description="Security group for DocumentDB cluster"
    )
    
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster6",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        security_group=security_group,
        instances=3,
        enable_cloudwatch_logs_exports=["authenticate", "createIndex", "dropCollection"],
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc7")
    
    # Define parameter group
    parameter_group = docdb.ClusterParameterGroup(
        scope, "DocDBParameterGroup7",
        description="Custom parameter group for DocumentDB",
        parameters={
            "tls": "enabled",
            "audit_logs": "enabled"
        }
    )
    
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster7",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        parameter_group=parameter_group,
        enable_cloudwatch_logs_exports=["authenticate", "createIndex", "dropCollection"],
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc8")
    
    # Define a function to create cluster
    def create_cluster():
        # ok: python-cdk-document-db-cluster-log-exports
        return docdb.DatabaseCluster(
            scope, "MyDocDBCluster8",
            master_user=docdb.Login(
                username="admin",
            ),
            instance_type=docdb.InstanceType.R5_LARGE,
            vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
            vpc=vpc,
            enable_cloudwatch_logs_exports=["authenticate", "createIndex", "dropCollection"],
            removal_policy=RemovalPolicy.DESTROY,
        )
    
    cluster = create_cluster()
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc9")
    
    # Using a list with concatenation
    required_logs = ["authenticate", "createIndex", "dropCollection"]
    additional_logs = ["profiler", "slowquery"]
    all_logs = required_logs + additional_logs
    
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster9",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        enable_cloudwatch_logs_exports=all_logs,
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc10")
    
    # Using L1 construct (lower level) with proper logs
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.CfnDBCluster(
        scope, "MyDocDBCluster10",
        storage_encrypted=True,
        availability_zones=["us-east-1a", "us-east-1b", "us-east-1c"],
        db_cluster_identifier="my-docdb-cluster",
        engine="docdb",
        master_username="admin",
        master_user_password="password123",
        vpc_security_group_ids=["sg-12345"],
        enable_cloudwatch_logs_exports=["authenticate", "createIndex", "dropCollection"],
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc11")
    
    # Using a dictionary to map environments to log exports
    env_to_logs = {
        "dev": ["authenticate", "createIndex", "dropCollection"],
        "prod": ["authenticate", "createIndex", "dropCollection", "profiler", "slowquery"]
    }
    
    environment = "dev"
    
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster11",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        enable_cloudwatch_logs_exports=env_to_logs[environment],
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc12")
    
    # Using a class to manage DocumentDB configuration
    class DocDBConfig:
        @staticmethod
        def get_log_exports():
            return ["authenticate", "createIndex", "dropCollection"]
    
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster12",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        enable_cloudwatch_logs_exports=DocDBConfig.get_log_exports(),
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc13")
    
    # Using a more complex setup with proper logs
    subnet_group = docdb.CfnDBSubnetGroup(
        scope, "DocDBSubnetGroup",
        db_subnet_group_description="Subnet group for DocumentDB",
        subnet_ids=vpc.select_subnets(
            subnet_type=cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
        ).subnet_ids
    )
    
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.CfnDBCluster(
        scope, "MyDocDBCluster13",
        storage_encrypted=True,
        db_cluster_identifier="my-docdb-cluster",
        engine="docdb",
        master_username="admin",
        master_user_password="password123",
        db_subnet_group_name=subnet_group.ref,
        enable_cloudwatch_logs_exports=["authenticate", "createIndex", "dropCollection"],
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc14")
    
    # Using set operations to ensure all required logs are included
    base_logs = {"profiler", "slowquery"}
    required_logs = {"authenticate", "createIndex", "dropCollection"}
    
    # Ensure all required logs are included
    final_logs = list(base_logs.union(required_logs))
    
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster14",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        enable_cloudwatch_logs_exports=final_logs,
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=security-information-omission@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVpc15")
    
    # Using a more complex configuration with proper logs
    # ok: python-cdk-document-db-cluster-log-exports
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster15",
        master_user=docdb.Login(
            username="admin",
        ),
        instance_type=docdb.InstanceType.R5_LARGE,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=vpc,
        instances=3,
        backup=docdb.BackupProps(
            retention=Duration.days(14),
        ),
        deletion_protection=True,
        enable_cloudwatch_logs_exports=["authenticate", "createIndex", "dropCollection"],
        removal_policy=RemovalPolicy.SNAPSHOT,
    )
    return cluster

# Example stack implementation
# {/fact}

class DocumentDBStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Example usage of the functions
        bad_cluster = bad_case_1(self, "BadCluster")
        good_cluster = good_case_1(self, "GoodCluster")
        
        CfnOutput(self, "BadClusterEndpoint", value=bad_cluster.cluster_endpoint.hostname)
        CfnOutput(self, "GoodClusterEndpoint", value=good_cluster.cluster_endpoint.hostname)