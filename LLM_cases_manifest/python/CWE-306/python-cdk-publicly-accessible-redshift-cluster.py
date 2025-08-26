import aws_cdk as cdk
from aws_cdk import (
    aws_redshift as redshift,
    Stack,
    CfnOutput,
    RemovalPolicy,
    Duration,
)
from constructs import Construct
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_iam as iam

# True positive examples (vulnerable code)

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=True,
        db_name="mydb"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Creating a Redshift cluster with explicitly set publicly_accessible=True
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        vpc_security_group_ids=["sg-12345"],
        publicly_accessible=True,
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True and additional configuration
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=4,
        node_type="ra3.xlplus",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=True,
        db_name="datawarehouse",
        encrypted=True,
        port=5439
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True in a variable
    is_public = True
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=is_public,
        db_name="reporting"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True and snapshot settings
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=True,
        automated_snapshot_retention_period=7,
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Creating a Redshift cluster with publicly_accessible=True and subnet group
    subnet_group = redshift.CfnClusterSubnetGroup(
        scope,
        "RedshiftSubnetGroup",
        description="Redshift subnet group",
        subnet_ids=vpc.select_subnets(subnet_type=ec2.SubnetType.PUBLIC).subnet_ids,
    )
    
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        cluster_subnet_group_name=subnet_group.ref,
        publicly_accessible=True,
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True and enhanced VPC routing
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=True,
        enhanced_vpc_routing=True,
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True and logging enabled
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=True,
        logging=redshift.CfnCluster.LoggingProperty(
            bucket_name="my-log-bucket",
            s3_key_prefix="redshift-logs/"
        ),
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True and maintenance window
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=True,
        preferred_maintenance_window="sun:03:00-sun:04:00",
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True and tags
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=True,
        tags=[
            cdk.CfnTag(key="Environment", value="Production"),
            cdk.CfnTag(key="Owner", value="DataTeam")
        ],
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True and IAM roles
    role = iam.Role(scope, "RedshiftRole", assumed_by=iam.ServicePrincipal("redshift.amazonaws.com"))
    
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=True,
        iam_roles=[role.role_arn],
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True and KMS encryption
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=True,
        encrypted=True,
        kms_key_id="arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True and parameter group
    parameter_group = redshift.CfnClusterParameterGroup(
        scope,
        "RedshiftParameterGroup",
        description="Custom parameter group",
        parameter_group_family="redshift-1.0",
        parameters=[
            redshift.CfnClusterParameterGroup.ParameterProperty(
                parameter_name="enable_user_activity_logging",
                parameter_value="true"
            )
        ]
    )
    
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=True,
        cluster_parameter_group_name=parameter_group.ref,
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True and availability zone
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=True,
        availability_zone="us-west-2a",
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=True and cluster version
    # ruleid: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=True,
        cluster_version="1.0",
        db_name="analytics"
    )
    return cluster

# True negative examples (secure code)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=False
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=False,
        db_name="mydb"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Creating a Redshift cluster with explicitly set publicly_accessible=False
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        vpc_security_group_ids=["sg-12345"],
        publicly_accessible=False,
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=False and additional configuration
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=4,
        node_type="ra3.xlplus",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=False,
        db_name="datawarehouse",
        encrypted=True,
        port=5439
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=False in a variable
    is_public = False
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=is_public,
        db_name="reporting"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=False and snapshot settings
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=False,
        automated_snapshot_retention_period=7,
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Creating a Redshift cluster with publicly_accessible=False and subnet group
    subnet_group = redshift.CfnClusterSubnetGroup(
        scope,
        "RedshiftSubnetGroup",
        description="Redshift subnet group",
        subnet_ids=vpc.select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS).subnet_ids,
    )
    
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        cluster_subnet_group_name=subnet_group.ref,
        publicly_accessible=False,
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=False and enhanced VPC routing
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=False,
        enhanced_vpc_routing=True,
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=False and logging enabled
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=False,
        logging=redshift.CfnCluster.LoggingProperty(
            bucket_name="my-log-bucket",
            s3_key_prefix="redshift-logs/"
        ),
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=False and maintenance window
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=False,
        preferred_maintenance_window="sun:03:00-sun:04:00",
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=False and tags
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=False,
        tags=[
            cdk.CfnTag(key="Environment", value="Production"),
            cdk.CfnTag(key="Owner", value="DataTeam")
        ],
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=False and IAM roles
    role = iam.Role(scope, "RedshiftRole", assumed_by=iam.ServicePrincipal("redshift.amazonaws.com"))
    
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=False,
        iam_roles=[role.role_arn],
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly_accessible=False and KMS encryption
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        publicly_accessible=False,
        encrypted=True,
        kms_key_id="arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Using the L2 construct which defaults to private access
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        node_type=redshift.NodeType.DC2_LARGE,
        number_of_nodes=2,
        removal_policy=RemovalPolicy.DESTROY,
        vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a Redshift cluster without specifying publicly_accessible (defaults to False)
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="dc2.large",
        master_username="admin",
        master_user_password="Password123",
        db_name="analytics"
    )
    return cluster

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a Redshift cluster with secure configuration using L2 construct with explicit public access disabled
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-publicly-accessible-redshift-cluster
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        node_type=redshift.NodeType.DC2_LARGE,
        number_of_nodes=2,
        publicly_accessible=False,
        vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
    )
    return cluster
# {/fact}