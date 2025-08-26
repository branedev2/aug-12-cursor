import aws_cdk as cdk
from aws_cdk import (
    aws_redshift as redshift,
    Stack,
    CfnOutput,
    RemovalPolicy,
    Duration,
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_1():
    """Redshift cluster with allow_version_upgrade explicitly set to False"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=False
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_2():
    """Redshift cluster with allow_version_upgrade set to False in a variable"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    upgrade_allowed = False
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="ra3.xlplus",
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=upgrade_allowed
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_3():
    """Redshift cluster with allow_version_upgrade set to None"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=None
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_4():
    """Redshift cluster with allow_version_upgrade omitted (defaults to None)"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=3,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb"
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_5():
    """Redshift cluster with allow_version_upgrade set to False in a conditional"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    is_prod = True
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=False if is_prod else True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_6():
    """Redshift cluster with allow_version_upgrade set to False in a dictionary"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    cluster_props = {
        "cluster_type": "multi-node",
        "node_type": "ra3.4xlarge",
        "number_of_nodes": 2,
        "master_username": "admin",
        "master_user_password": "Password123",
        "db_name": "mydb",
        "allow_version_upgrade": False
    }
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        **cluster_props
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_7():
    """Redshift cluster with allow_version_upgrade set to False in a function"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    def get_upgrade_setting():
        return False
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password": "Password123",
        db_name="mydb",
        allow_version_upgrade=get_upgrade_setting()
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_8():
    """Redshift cluster with allow_version_upgrade set to False in a class"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    class ClusterConfig:
        @staticmethod
        def get_version_upgrade():
            return False
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=ClusterConfig.get_version_upgrade()
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_9():
    """Redshift cluster with allow_version_upgrade set to False in a complex expression"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    env_settings = {"dev": True, "prod": False}
    current_env = "prod"
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=env_settings[current_env]
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_10():
    """Redshift cluster with allow_version_upgrade set to False in a custom construct"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    class CustomRedshiftCluster(Construct):
        def __init__(self, scope, id, **kwargs):
            super().__init__(scope, id)
            
            # ruleid: python-cdk-redshift-cluster-maintenance-settings
            self.cluster = redshift.CfnCluster(
                self,
                "Cluster",
                cluster_type="multi-node",
                node_type="ra3.4xlarge",
                number_of_nodes=2,
                master_username="admin",
                master_user_password="Password123",
                db_name="mydb",
                allow_version_upgrade=False
            )
    
    custom_cluster = CustomRedshiftCluster(stack, "CustomCluster")
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_11():
    """Redshift cluster with allow_version_upgrade set to False in a loop"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    environments = ["dev", "test", "prod"]
    
    for i, env in enumerate(environments):
        # ruleid: python-cdk-redshift-cluster-maintenance-settings
        cluster = redshift.CfnCluster(
            stack, 
            f"MyRedshiftCluster{env}",
            cluster_type="multi-node",
            node_type="ra3.4xlarge",
            number_of_nodes=2,
            master_username="admin",
            master_user_password=f"Password123{env}",
            db_name=f"mydb_{env}",
            allow_version_upgrade=False
        )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_12():
    """Redshift cluster with allow_version_upgrade set to False with other maintenance settings"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=False,
        automated_snapshot_retention_period=7,
        preferred_maintenance_window="sun:03:00-sun:05:00"
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_13():
    """Redshift cluster with allow_version_upgrade set to False with encryption enabled"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=False,
        encrypted=True,
        kms_key_id="arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_14():
    """Redshift cluster with allow_version_upgrade set to False with tags"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=False,
        tags=[
            {"key": "Environment", "value": "Production"},
            {"key": "Owner", "value": "DataTeam"}
        ]
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_15():
    """Redshift cluster with allow_version_upgrade set to False with VPC settings"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ruleid: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=False,
        cluster_subnet_group_name="my-subnet-group",
        vpc_security_group_ids=["sg-12345678"]
    )
    
    return stack

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_1():
    """Redshift cluster with allow_version_upgrade set to True"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_2():
    """Redshift cluster with allow_version_upgrade set to True in a variable"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    upgrade_allowed = True
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="single-node",
        node_type="ra3.xlplus",
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=upgrade_allowed
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_3():
    """Redshift cluster with allow_version_upgrade set to True in a conditional"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    is_prod = True
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=True if is_prod else False
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_4():
    """Redshift cluster with allow_version_upgrade set to True in a dictionary"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    cluster_props = {
        "cluster_type": "multi-node",
        "node_type": "ra3.4xlarge",
        "number_of_nodes": 2,
        "master_username": "admin",
        "master_user_password": "Password123",
        "db_name": "mydb",
        "allow_version_upgrade": True
    }
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        **cluster_props
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_5():
    """Redshift cluster with allow_version_upgrade set to True in a function"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    def get_upgrade_setting():
        return True
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=get_upgrade_setting()
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_6():
    """Redshift cluster with allow_version_upgrade set to True in a class"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    class ClusterConfig:
        @staticmethod
        def get_version_upgrade():
            return True
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=ClusterConfig.get_version_upgrade()
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_7():
    """Redshift cluster with allow_version_upgrade set to True in a complex expression"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    env_settings = {"dev": True, "prod": True}
    current_env = "prod"
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=env_settings[current_env]
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_8():
    """Redshift cluster with allow_version_upgrade set to True in a custom construct"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    class CustomRedshiftCluster(Construct):
        def __init__(self, scope, id, **kwargs):
            super().__init__(scope, id)
            
            # ok: python-cdk-redshift-cluster-maintenance-settings
            self.cluster = redshift.CfnCluster(
                self,
                "Cluster",
                cluster_type="multi-node",
                node_type="ra3.4xlarge",
                number_of_nodes=2,
                master_username="admin",
                master_user_password="Password123",
                db_name="mydb",
                allow_version_upgrade=True
            )
    
    custom_cluster = CustomRedshiftCluster(stack, "CustomCluster")
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_9():
    """Redshift cluster with allow_version_upgrade set to True in a loop"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    environments = ["dev", "test", "prod"]
    
    for i, env in enumerate(environments):
        # ok: python-cdk-redshift-cluster-maintenance-settings
        cluster = redshift.CfnCluster(
            stack, 
            f"MyRedshiftCluster{env}",
            cluster_type="multi-node",
            node_type="ra3.4xlarge",
            number_of_nodes=2,
            master_username="admin",
            master_user_password=f"Password123{env}",
            db_name=f"mydb_{env}",
            allow_version_upgrade=True
        )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_10():
    """Redshift cluster with allow_version_upgrade set to True with other maintenance settings"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=True,
        automated_snapshot_retention_period=7,
        preferred_maintenance_window="sun:03:00-sun:05:00"
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_11():
    """Redshift cluster with allow_version_upgrade set to True with encryption enabled"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=True,
        encrypted=True,
        kms_key_id="arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_12():
    """Redshift cluster with allow_version_upgrade set to True with tags"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=True,
        tags=[
            {"key": "Environment", "value": "Production"},
            {"key": "Owner", "value": "DataTeam"}
        ]
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_13():
    """Redshift cluster with allow_version_upgrade set to True with VPC settings"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.CfnCluster(
        stack, 
        "MyRedshiftCluster",
        cluster_type="multi-node",
        node_type="ra3.4xlarge",
        number_of_nodes=2,
        master_username="admin",
        master_user_password="Password123",
        db_name="mydb",
        allow_version_upgrade=True,
        cluster_subnet_group_name="my-subnet-group",
        vpc_security_group_ids=["sg-12345678"]
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_14():
    """Redshift cluster using L2 construct with default settings (allow_version_upgrade defaults to True)"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.Cluster(
        stack, 
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin",
            master_password=cdk.SecretValue.unsafe_plain_text("Password123")
        ),
        node_type=redshift.NodeType.RA3_4XLARGE,
        cluster_type=redshift.ClusterType.MULTI_NODE,
        number_of_nodes=2,
        default_database_name="mydb",
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_15():
    """Redshift cluster using L2 construct with explicit allow_version_upgrade set to True"""
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ok: python-cdk-redshift-cluster-maintenance-settings
    cluster = redshift.Cluster(
        stack, 
        "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin",
            master_password=cdk.SecretValue.unsafe_plain_text("Password123")
        ),
        node_type=redshift.NodeType.RA3_4XLARGE,
        cluster_type=redshift.ClusterType.MULTI_NODE,
        number_of_nodes=2,
        default_database_name="mydb",
        removal_policy=RemovalPolicy.DESTROY,
        allow_version_upgrade=True
    )
    
    return stack
# {/fact}