import aws_cdk as cdk
from aws_cdk import (
    aws_neptune as neptune,
    Stack,
    App,
    CfnOutput,
    Duration,
    RemovalPolicy
)
from constructs import Construct

# True Positives (Vulnerable Code)

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_1():
    # Creating a Neptune cluster without multi_az enabled
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0"
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref,
        availability_zone="us-east-1a"
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_2():
    # Explicitly setting multi_az to False
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0"
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref,
        multi_az=False
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_3():
    # Using DatabaseCluster without multi_az
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    subnet_group = neptune.SubnetGroup(
        stack, "NeptuneSubnetGroup",
        vpc=vpc,
        description="Neptune Subnet Group"
    )
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        removal_policy=RemovalPolicy.DESTROY,
        subnet_group=subnet_group
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_4():
    # Using DatabaseCluster with explicit multi_az=False
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        removal_policy=RemovalPolicy.DESTROY,
        instances=1,
        parameter_group=neptune.ParameterGroup.from_parameter_group_name(
            stack, "ParameterGroup", "default.neptune1"
        ),
        auto_minor_version_upgrade=True
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_5():
    # Using DatabaseCluster with instances=1 (implies no multi-AZ)
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        instances=1,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_6():
    # Using CfnDBCluster without availability_zones
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0",
        db_subnet_group_name="my-subnet-group"
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_7():
    # Using CfnDBCluster with only one availability zone
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0",
        availability_zones=["us-east-1a"]
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_8():
    # Using DatabaseCluster with custom parameter group but no multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    parameter_group = neptune.ParameterGroup(
        stack, "ParameterGroup",
        description="Custom parameter group",
        parameters={
            "neptune_query_timeout": "120000"
        }
    )
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        parameter_group=parameter_group,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_9():
    # Using CfnDBCluster with security groups but no multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    security_group = cdk.aws_ec2.SecurityGroup(
        stack, "SecurityGroup",
        vpc=vpc,
        description="Neptune security group"
    )
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0",
        vpc_security_group_ids=[security_group.security_group_id]
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_10():
    # Using DatabaseCluster with backup configuration but no multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        backup_retention=Duration.days(7),
        preferred_backup_window="02:00-03:00",
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_11():
    # Using DatabaseCluster with IAM authentication but no multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        iam_authentication=True,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_12():
    # Using CfnDBCluster with tags but no multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0",
        tags=[
            cdk.CfnTag(key="Environment", value="Production"),
            cdk.CfnTag(key="Owner", value="DataTeam")
        ]
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_13():
    # Using DatabaseCluster with serverless configuration but no multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        engine_version="1.2.0.0",
        removal_policy=RemovalPolicy.DESTROY,
        serverless_scaling_configuration=neptune.ServerlessScalingConfiguration(
            min_capacity=1.0,
            max_capacity=128.0
        )
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_14():
    # Using CfnDBCluster with port configuration but no multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0",
        port=8182
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=1}
def bad_case_15():
    # Using DatabaseCluster with storage encryption but no multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=True,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return stack

# True Negatives (Secure Code)

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_1():
    # Using CfnDBCluster with multiple availability zones and multi_az=True
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0",
        availability_zones=["us-east-1a", "us-east-1b", "us-east-1c"]
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref,
        multi_az=True
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_2():
    # Using DatabaseCluster with instances=2 (implies multi-AZ)
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        instances=2,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_3():
    # Using DatabaseCluster with instances=3 (implies multi-AZ)
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        instances=3,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_4():
    # Using CfnDBCluster with multiple availability zones
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0",
        availability_zones=["us-east-1a", "us-east-1b"]
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref,
        multi_az=True
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_5():
    # Using DatabaseCluster with custom parameter group and multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    parameter_group = neptune.ParameterGroup(
        stack, "ParameterGroup",
        description="Custom parameter group",
        parameters={
            "neptune_query_timeout": "120000"
        }
    )
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        parameter_group=parameter_group,
        instances=2,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_6():
    # Using CfnDBCluster with security groups and multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    security_group = cdk.aws_ec2.SecurityGroup(
        stack, "SecurityGroup",
        vpc=vpc,
        description="Neptune security group"
    )
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0",
        vpc_security_group_ids=[security_group.security_group_id],
        availability_zones=["us-east-1a", "us-east-1b"]
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref,
        multi_az=True
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_7():
    # Using DatabaseCluster with backup configuration and multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        backup_retention=Duration.days(7),
        preferred_backup_window="02:00-03:00",
        instances=3,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_8():
    # Using DatabaseCluster with IAM authentication and multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        iam_authentication=True,
        instances=2,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_9():
    # Using CfnDBCluster with tags and multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0",
        tags=[
            cdk.CfnTag(key="Environment", value="Production"),
            cdk.CfnTag(key="Owner", value="DataTeam")
        ],
        availability_zones=["us-east-1a", "us-east-1b", "us-east-1c"]
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref,
        multi_az=True
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_10():
    # Using DatabaseCluster with serverless configuration and multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        engine_version="1.2.0.0",
        instances=2,
        removal_policy=RemovalPolicy.DESTROY,
        serverless_scaling_configuration=neptune.ServerlessScalingConfiguration(
            min_capacity=1.0,
            max_capacity=128.0
        )
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_11():
    # Using CfnDBCluster with port configuration and multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0",
        port=8182,
        availability_zones=["us-east-1a", "us-east-1b"]
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref,
        multi_az=True
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_12():
    # Using DatabaseCluster with storage encryption and multi-AZ
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=True,
        instances=3,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_13():
    # Using CfnDBCluster with multiple availability zones and explicit multi_az
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    subnet_group = neptune.CfnDBSubnetGroup(
        stack, "NeptuneSubnetGroup",
        db_subnet_group_description="Neptune Subnet Group",
        subnet_ids=["subnet-12345", "subnet-67890", "subnet-abcde"]
    )
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        db_cluster_identifier="my-neptune-cluster",
        engine_version="1.2.0.0",
        db_subnet_group_name=subnet_group.ref,
        availability_zones=["us-east-1a", "us-east-1b", "us-east-1c"]
    )
    
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref,
        multi_az=True
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_14():
    # Using DatabaseCluster with explicit multi-AZ configuration
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        removal_policy=RemovalPolicy.DESTROY,
        instances=2,
        cluster_parameter_group=neptune.ClusterParameterGroup(
            stack, "ClusterParams",
            description="Cluster parameter group",
            parameters={"neptune_enable_audit_log": "1"}
        )
    )
    
    return stack

# {/fact}

# {fact rule=coding-standards-violation@v1.0 defects=0}
def good_case_15():
    # Using DatabaseCluster with multiple instances and availability zones
    app = App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = cdk.aws_ec2.Vpc(
        stack, "VPC",
        max_azs=3
    )
    
    # ok: python-cdk-neptune-cluster-multi-az
    cluster = neptune.DatabaseCluster(
        stack, "NeptuneCluster",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        instances=3,
        removal_policy=RemovalPolicy.DESTROY,
        vpc_subnets=cdk.aws_ec2.SubnetSelection(
            subnet_type=cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS
        )
    )
    
    return stack
# {/fact}