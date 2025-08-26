import aws_cdk as cdk
from aws_cdk import (
    aws_redshift as redshift,
    aws_ec2 as ec2,
    Stack,
    RemovalPolicy,
    Duration,
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a Redshift cluster without specifying a VPC
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        default_database_name="mydb",
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating a Redshift cluster with vpc_subnets=None
    vpc = ec2.Vpc(scope, "MyVpc")
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        vpc_subnets=None,  # This effectively makes it not use the VPC
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a Redshift cluster with explicit vpc=None
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a Redshift cluster with minimal configuration
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin",
            master_password=cdk.SecretValue.unsafe_plain_text("Password123")
        ),
        node_type=redshift.NodeType.RA3_4XLARGE,
        number_of_nodes=2,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a Redshift cluster with encryption but no VPC
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        encrypted=True,
        cluster_type=redshift.ClusterType.MULTI_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        number_of_nodes=3,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a Redshift cluster with removal policy but no VPC
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        removal_policy=RemovalPolicy.SNAPSHOT,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a Redshift cluster with backup configuration but no VPC
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        automated_snapshot_retention_period=7,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a Redshift cluster with port configuration but no VPC
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        port=5439,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a Redshift cluster with preferred maintenance window but no VPC
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        preferred_maintenance_window="sat:03:00-sat:04:00",
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a Redshift cluster with publicly accessible but no VPC
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        publicly_accessible=False,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a Redshift cluster with parameter group but no VPC
    # ruleid: python-cdk-redshift-cluster-in-vpc
    parameter_group = redshift.ClusterParameterGroup(
        scope,
        "RedshiftParameterGroup",
        description="Custom parameter group",
        parameters={
            "enable_user_activity_logging": "true",
            "require_ssl": "true",
        }
    )
    
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        parameter_group=parameter_group,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a Redshift cluster with enhanced VPC routing but no VPC
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        enhanced_vpc_routing=True,  # This setting requires a VPC but none is provided
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a Redshift cluster with logging but no VPC
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        logging_properties=redshift.LoggingProperties(
            bucket_name="my-logging-bucket"
        ),
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a Redshift cluster with tags but no VPC
    # ruleid: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
    )
    cdk.Tags.of(cluster).add("Environment", "Production")
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a Redshift cluster with custom security groups but no VPC
    # This is a contradictory configuration since security groups require a VPC
    # ruleid: python-cdk-redshift-cluster-in-vpc
    security_group = ec2.SecurityGroup(scope, "RedshiftSG", vpc=ec2.Vpc(scope, "TempVpc"))
    
    # The cluster itself doesn't specify a VPC, which is the issue
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        security_groups=[security_group],  # Security groups require a VPC
    )
    return cluster

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC
    vpc = ec2.Vpc(scope, "MyVpc")
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with specific subnet selection
    vpc = ec2.Vpc(scope, "MyVpc")
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
        ),
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with security groups
    vpc = ec2.Vpc(scope, "MyVpc")
    security_group = ec2.SecurityGroup(scope, "RedshiftSG", vpc=vpc)
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        security_groups=[security_group],
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with encryption
    vpc = ec2.Vpc(scope, "MyVpc")
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        encrypted=True,
        cluster_type=redshift.ClusterType.MULTI_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        number_of_nodes=3,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with removal policy
    vpc = ec2.Vpc(scope, "MyVpc")
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        removal_policy=RemovalPolicy.SNAPSHOT,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with backup configuration
    vpc = ec2.Vpc(scope, "MyVpc")
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        automated_snapshot_retention_period=7,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with port configuration
    vpc = ec2.Vpc(scope, "MyVpc")
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        port=5439,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with preferred maintenance window
    vpc = ec2.Vpc(scope, "MyVpc")
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        preferred_maintenance_window="sat:03:00-sat:04:00",
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with publicly accessible set to false
    vpc = ec2.Vpc(scope, "MyVpc")
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        publicly_accessible=False,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with parameter group
    vpc = ec2.Vpc(scope, "MyVpc")
    parameter_group = redshift.ClusterParameterGroup(
        scope,
        "RedshiftParameterGroup",
        description="Custom parameter group",
        parameters={
            "enable_user_activity_logging": "true",
            "require_ssl": "true",
        }
    )
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        parameter_group=parameter_group,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with enhanced VPC routing
    vpc = ec2.Vpc(scope, "MyVpc")
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        enhanced_vpc_routing=True,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with logging
    vpc = ec2.Vpc(scope, "MyVpc")
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
        logging_properties=redshift.LoggingProperties(
            bucket_name="my-logging-bucket"
        ),
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with tags
    vpc = ec2.Vpc(scope, "MyVpc")
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
    )
    cdk.Tags.of(cluster).add("Environment", "Production")
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with imported VPC
    imported_vpc = ec2.Vpc.from_lookup(scope, "ImportedVpc", vpc_id="vpc-12345")
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=imported_vpc,
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
    )
    return cluster

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a Redshift cluster within a VPC with isolated subnets
    vpc = ec2.Vpc(scope, "MyVpc", 
        subnet_configuration=[
            ec2.SubnetConfiguration(
                name="Isolated",
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                cidr_mask=24
            )
        ]
    )
    
    # ok: python-cdk-redshift-cluster-in-vpc
    cluster = redshift.Cluster(
        scope,
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_ISOLATED
        ),
        cluster_type=redshift.ClusterType.SINGLE_NODE,
        node_type=redshift.NodeType.DC2_LARGE,
    )
    return cluster
# {/fact}