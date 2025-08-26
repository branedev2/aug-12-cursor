import aws_cdk as cdk
from aws_cdk import (
    aws_redshift as redshift,
    Stack,
    CfnParameter,
    RemovalPolicy,
)
from constructs import Construct
import os
import boto3
from aws_cdk.aws_ec2 import Vpc, SubnetType
from aws_cdk.aws_secretsmanager import Secret

# True Positives (Vulnerable Code Examples)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1():
    # Creating a Redshift cluster without enabling TLS/SSL
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2():
    # Creating a Redshift cluster with require_ssl explicitly set to False
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "InsecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=False,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3():
    # Creating a Redshift cluster with require_ssl as a variable set to False
    ssl_required = False
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "VariableConfiguredRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=ssl_required,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4():
    # Creating a Redshift cluster with require_ssl determined by a function that returns False
    def get_ssl_config():
        return False
    
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "FunctionConfiguredRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=get_ssl_config(),
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5():
    # Creating a Redshift cluster with require_ssl as a conditional that evaluates to False
    is_production = False
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "ConditionalRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=True if is_production else False,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6():
    # Creating a Redshift cluster with require_ssl from environment variable that's not set
    ssl_required = os.environ.get('REQUIRE_SSL', 'false').lower() == 'true'
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "EnvVarRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=ssl_required,  # Will be False if env var not set
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7():
    # Creating a Redshift cluster with require_ssl as a parameter with default False
    ssl_param = CfnParameter(self, "RequireSSL", default="false", type="String")
    ssl_required = ssl_param.value_as_string == "true"
    
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "ParameterizedRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=ssl_required,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8():
    # Creating a Redshift cluster with require_ssl in a dictionary that has False
    cluster_config = {
        "node_type": "ra3.xlplus",
        "number_of_nodes": 2,
        "require_ssl": False
    }
    
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "DictConfiguredRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=cluster_config["require_ssl"],
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9():
    # Creating multiple Redshift clusters in a loop without require_ssl
    cluster_names = ["dev", "test", "staging"]
    
    for name in cluster_names:
        # ruleid: python-cdk-redshift-require-tls-ssl
        cluster = redshift.Cluster(
            self, f"{name}RedshiftCluster",
            master_user=redshift.Login(
                master_username=f"admin-{name}"
            ),
            vpc=vpc,
            removal_policy=RemovalPolicy.DESTROY,
        )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10():
    # Creating a Redshift cluster with require_ssl as None (which defaults to False)
    ssl_setting = None
    
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "NoneConfiguredRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=ssl_setting,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11():
    # Creating a Redshift cluster with complex logic that results in require_ssl being False
    is_dev = True
    is_high_security = False
    
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "ComplexLogicRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=not is_dev or is_high_security,  # Evaluates to False
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12():
    # Creating a Redshift cluster with require_ssl toggled based on cluster type
    cluster_type = "development"
    
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "TypeBasedRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=cluster_type == "production",  # False for development
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13():
    # Creating a Redshift cluster with require_ssl in a class property
    class ClusterConfig:
        def __init__(self):
            self.require_ssl = False
    
    config = ClusterConfig()
    
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "ClassConfiguredRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=config.require_ssl,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14():
    # Creating a Redshift cluster with require_ssl from a config file (simulated)
    def load_config():
        return {"require_ssl": False}
    
    config = load_config()
    
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "FileConfiguredRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=config["require_ssl"],
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15():
    # Creating a Redshift cluster with require_ssl determined by a ternary based on node type
    node_type = "ra3.xlplus"
    
    # ruleid: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "NodeTypeBasedRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        node_type=node_type,
        require_ssl=True if node_type == "ra3.16xlarge" else False,  # False for ra3.xlplus
        removal_policy=RemovalPolicy.DESTROY,
    )

# True Negatives (Secure Code Examples)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1():
    # Creating a Redshift cluster with require_ssl explicitly set to True
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "SecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=True,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2():
    # Creating a Redshift cluster with require_ssl as a variable set to True
    ssl_required = True
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "VariableSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=ssl_required,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3():
    # Creating a Redshift cluster with require_ssl determined by a function that returns True
    def get_ssl_config():
        return True
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "FunctionSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=get_ssl_config(),
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4():
    # Creating a Redshift cluster with require_ssl as a conditional that evaluates to True
    is_production = True
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "ConditionalSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=True if is_production else False,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5():
    # Creating a Redshift cluster with require_ssl from environment variable set to true
    os.environ['REQUIRE_SSL'] = 'true'
    ssl_required = os.environ.get('REQUIRE_SSL', 'false').lower() == 'true'
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "EnvVarSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=ssl_required,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6():
    # Creating a Redshift cluster with require_ssl as a parameter with default True
    ssl_param = CfnParameter(self, "RequireSSL", default="true", type="String")
    ssl_required = ssl_param.value_as_string == "true"
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "ParameterizedSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=ssl_required,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7():
    # Creating a Redshift cluster with require_ssl in a dictionary that has True
    cluster_config = {
        "node_type": "ra3.xlplus",
        "number_of_nodes": 2,
        "require_ssl": True
    }
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "DictConfiguredSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=cluster_config["require_ssl"],
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8():
    # Creating multiple Redshift clusters in a loop with require_ssl set to True
    cluster_names = ["dev", "test", "staging"]
    
    for name in cluster_names:
        # ok: python-cdk-redshift-require-tls-ssl
        cluster = redshift.Cluster(
            self, f"{name}SecureRedshiftCluster",
            master_user=redshift.Login(
                master_username=f"admin-{name}"
            ),
            vpc=vpc,
            require_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9():
    # Creating a Redshift cluster with complex logic that results in require_ssl being True
    is_dev = False
    is_high_security = True
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "ComplexLogicSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=not is_dev or is_high_security,  # Evaluates to True
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10():
    # Creating a Redshift cluster with require_ssl toggled based on cluster type
    cluster_type = "production"
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "TypeBasedSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=cluster_type == "production",  # True for production
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11():
    # Creating a Redshift cluster with require_ssl in a class property
    class ClusterConfig:
        def __init__(self):
            self.require_ssl = True
    
    config = ClusterConfig()
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "ClassConfiguredSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=config.require_ssl,
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12():
    # Creating a Redshift cluster with require_ssl from a config file (simulated)
    def load_config():
        return {"require_ssl": True}
    
    config = load_config()
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "FileConfiguredSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=config["require_ssl"],
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13():
    # Creating a Redshift cluster with require_ssl determined by a ternary based on node type
    node_type = "ra3.16xlarge"
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "NodeTypeBasedSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        node_type=node_type,
        require_ssl=True if node_type == "ra3.16xlarge" else False,  # True for ra3.16xlarge
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14():
    # Creating a Redshift cluster with require_ssl set to True using logical OR with a default
    use_ssl = None
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "DefaultSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=use_ssl or True,  # None or True evaluates to True
        removal_policy=RemovalPolicy.DESTROY,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15():
    # Creating a Redshift cluster with require_ssl set to True based on security policy
    def get_security_policy():
        return {
            "encryption": {
                "in_transit": True,
                "at_rest": True
            }
        }
    
    security_policy = get_security_policy()
    
    # ok: python-cdk-redshift-require-tls-ssl
    cluster = redshift.Cluster(
        self, "PolicyBasedSecureRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=vpc,
        require_ssl=security_policy["encryption"]["in_transit"],
        removal_policy=RemovalPolicy.DESTROY,
    )
# {/fact}