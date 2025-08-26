import aws_cdk as cdk
from aws_cdk import (
    aws_redshift as redshift,
    Stack,
    CfnParameter,
    SecretValue,
    RemovalPolicy,
    Duration,
)
from constructs import Construct
import os
from aws_cdk.aws_ec2 import (
    Vpc,
    SubnetType,
    SecurityGroup,
    Port,
    Peer,
)

# True Positives (Vulnerable Code)

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    """Creates a Redshift cluster with default port (5439)"""
    vpc = Vpc(scope, "VPC")
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        vpc_security_group_ids=["sg-12345"],
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    """Creates a Redshift cluster with explicitly set default port (5439)"""
    vpc = Vpc(scope, "VPC")
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=5439,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    """Creates a Redshift cluster with default port using a variable"""
    vpc = Vpc(scope, "VPC")
    default_port = 5439
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=default_port,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    """Creates a Redshift cluster with default port in a conditional statement"""
    vpc = Vpc(scope, "VPC")
    use_default = True
    port_to_use = 5439 if use_default else 5440
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=port_to_use,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    """Creates a Redshift cluster with default port using arithmetic"""
    vpc = Vpc(scope, "VPC")
    base_port = 5430
    offset = 9
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=base_port + offset,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    """Creates a Redshift cluster with default port in a multi-cluster setup"""
    vpc = Vpc(scope, "VPC")
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster1 = redshift.CfnCluster(
        scope,
        "PrimaryRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="primary",
    )
    
    # Second cluster also uses default port
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster2 = redshift.CfnCluster(
        scope,
        "SecondaryRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="secondary",
    )
    return [cluster1, cluster2]

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    """Creates a Redshift cluster with default port using a function"""
    vpc = Vpc(scope, "VPC")
    
    def get_port():
        return 5439
    
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=get_port(),
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    """Creates a Redshift cluster with default port using a dictionary lookup"""
    vpc = Vpc(scope, "VPC")
    
    config = {
        "username": "admin",
        "password": "Password1234",
        "port": 5439,
    }
    
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username=config["username"],
        master_user_password=config["password"],
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=config["port"],
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    """Creates a Redshift cluster with default port in a loop"""
    vpc = Vpc(scope, "VPC")
    
    clusters = []
    for i in range(3):
        # ruleid: python-cdk-redshift-cluster-usage-of-default-port
        cluster = redshift.CfnCluster(
            scope,
            f"RedshiftCluster{i}",
            master_username=f"admin{i}",
            master_user_password=f"Password{i}1234",
            node_type="ra3.4xlarge",
            cluster_type="single-node",
            db_name=f"db{i}",
            port=5439,
        )
        clusters.append(cluster)
    
    return clusters

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    """Creates a Redshift cluster with default port using a class attribute"""
    vpc = Vpc(scope, "VPC")
    
    class ClusterConfig:
        def __init__(self):
            self.port = 5439
    
    config = ClusterConfig()
    
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=config.port,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    """Creates a Redshift cluster with default port using hex notation"""
    vpc = Vpc(scope, "VPC")
    
    # 0x153F is hexadecimal for 5439
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=0x153F,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    """Creates a Redshift cluster with default port using environment variable with fallback"""
    vpc = Vpc(scope, "VPC")
    
    # os.getenv returns None if env var doesn't exist, so this falls back to 5439
    port = os.getenv("REDSHIFT_PORT", 5439)
    
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=port,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    """Creates a Redshift cluster with default port using string conversion"""
    vpc = Vpc(scope, "VPC")
    
    port_str = "5439"
    
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=int(port_str),
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    """Creates a Redshift cluster with default port using a CfnParameter with default value"""
    vpc = Vpc(scope, "VPC")
    
    port_param = CfnParameter(scope, "RedshiftPort", default="5439", type="Number")
    
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=port_param.value_as_number,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    """Creates a Redshift cluster with default port using a ternary with both options being default"""
    vpc = Vpc(scope, "VPC")
    
    is_prod = False
    port = 5439 if is_prod else 5439  # Both options are the default port
    
    # ruleid: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=port,
    )
    return cluster

# True Negatives (Secure Code)

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port"""
    vpc = Vpc(scope, "VPC")
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=5440,  # Non-default port
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port using a variable"""
    vpc = Vpc(scope, "VPC")
    custom_port = 8192
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=custom_port,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port from environment variable"""
    vpc = Vpc(scope, "VPC")
    # Using environment variable with a non-default fallback
    port = int(os.getenv("REDSHIFT_PORT", "7890"))
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=port,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port using arithmetic"""
    vpc = Vpc(scope, "VPC")
    base_port = 6000
    offset = 432
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=base_port + offset,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port using a function"""
    vpc = Vpc(scope, "VPC")
    
    def get_secure_port():
        return 9876
    
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=get_secure_port(),
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port using a dictionary lookup"""
    vpc = Vpc(scope, "VPC")
    
    config = {
        "username": "admin",
        "password": "Password1234",
        "port": 6543,
    }
    
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username=config["username"],
        master_user_password=config["password"],
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=config["port"],
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port in a loop"""
    vpc = Vpc(scope, "VPC")
    
    clusters = []
    base_port = 7000
    for i in range(3):
        # ok: python-cdk-redshift-cluster-usage-of-default-port
        cluster = redshift.CfnCluster(
            scope,
            f"RedshiftCluster{i}",
            master_username=f"admin{i}",
            master_user_password=f"Password{i}1234",
            node_type="ra3.4xlarge",
            cluster_type="single-node",
            db_name=f"db{i}",
            port=base_port + i,  # Each cluster gets a unique non-default port
        )
        clusters.append(cluster)
    
    return clusters

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port using a class attribute"""
    vpc = Vpc(scope, "VPC")
    
    class SecureClusterConfig:
        def __init__(self):
            self.port = 8765
    
    config = SecureClusterConfig()
    
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=config.port,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port using hex notation"""
    vpc = Vpc(scope, "VPC")
    
    # 0x1A85 is hexadecimal for 6789
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=0x1A85,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port using a CfnParameter"""
    vpc = Vpc(scope, "VPC")
    
    port_param = CfnParameter(scope, "RedshiftPort", default="7654", type="Number")
    
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=port_param.value_as_number,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port using a ternary operator"""
    vpc = Vpc(scope, "VPC")
    
    is_prod = True
    port = 8765 if is_prod else 6543  # Both options are non-default ports
    
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=port,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port using string conversion"""
    vpc = Vpc(scope, "VPC")
    
    port_str = "9876"
    
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=int(port_str),
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port using a list lookup"""
    vpc = Vpc(scope, "VPC")
    
    ports = [8080, 8443, 7654, 6543]
    selected_port = ports[2]  # 7654
    
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=selected_port,
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port using a lambda function"""
    vpc = Vpc(scope, "VPC")
    
    get_port = lambda: 8888
    
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=get_port(),
    )
    return cluster

# {/fact}

# {fact rule=code-injection@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    """Creates a Redshift cluster with non-default port using a complex expression"""
    vpc = Vpc(scope, "VPC")
    
    base = 5000
    offset = 1000
    adjustment = 432
    
    # ok: python-cdk-redshift-cluster-usage-of-default-port
    cluster = redshift.CfnCluster(
        scope,
        "MyRedshiftCluster",
        master_username="admin",
        master_user_password="Password1234",
        node_type="ra3.4xlarge",
        cluster_type="single-node",
        db_name="mydb",
        port=base + offset + adjustment,  # 6432
    )
    return cluster
# {/fact}