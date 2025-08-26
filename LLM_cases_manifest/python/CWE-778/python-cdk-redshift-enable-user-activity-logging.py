import aws_cdk as cdk
from aws_cdk import (
    aws_redshift as redshift,
    Stack,
    CfnParameter,
    RemovalPolicy
)
from constructs import Construct
import os

# True Positive Examples (Vulnerable Code)

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_1():
    # Creating a Redshift cluster without enabling user activity logging
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None  # This would be a real VPC in production
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_2():
    # Creating a Redshift cluster with parameter group but not enabling user activity logging
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Creating a parameter group without enabling user activity logging
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            "query_group": "default",
            "require_ssl": "true"
        }
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_3():
    # Creating a Redshift cluster with parameter group but explicitly disabling user activity logging
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Creating a parameter group with user activity logging explicitly disabled
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            "enable_user_activity_logging": "false",
            "require_ssl": "true"
        }
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_4():
    # Creating a Redshift cluster with parameter group but setting user activity logging to 0
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Creating a parameter group with user activity logging set to 0 (disabled)
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            "enable_user_activity_logging": "0",
            "require_ssl": "true"
        }
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_5():
    # Using CfnCluster directly without enabling user activity logging
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.CfnCluster(stack, "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="ra3.4xlarge",
        master_username="admin",
        master_user_password="Password123"
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_6():
    # Using CfnCluster with parameter group but not enabling user activity logging
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    param_group = redshift.CfnClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameter_group_family="redshift-1.0",
        parameters=[
            {"parameter_name": "require_ssl", "parameter_value": "true"}
        ]
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.CfnCluster(stack, "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="ra3.4xlarge",
        master_username="admin",
        master_user_password="Password123",
        cluster_parameter_group_name=param_group.ref
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_7():
    # Creating multiple Redshift clusters without enabling user activity logging
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster1 = redshift.Cluster(stack, "ProductionRedshift",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None  # This would be a real VPC in production
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster2 = redshift.Cluster(stack, "StagingRedshift",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None  # This would be a real VPC in production
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_8():
    # Creating a Redshift cluster with parameter group but using incorrect parameter name
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Creating a parameter group with incorrect parameter name
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            "user_activity_logging": "true",  # Incorrect parameter name
            "require_ssl": "true"
        }
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_9():
    # Creating a Redshift cluster with parameter group but using incorrect value format
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Creating a parameter group with incorrect value format
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            "enable_user_activity_logging": "yes",  # Incorrect value format (should be "true")
            "require_ssl": "true"
        }
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_10():
    # Creating a Redshift cluster with imported parameter group (which doesn't have logging enabled)
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Import an existing parameter group (which doesn't have logging enabled)
    imported_param_group = redshift.ClusterParameterGroup.from_cluster_parameter_group_name(
        stack, "ImportedParamGroup", "existing-param-group-without-logging"
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=imported_param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_11():
    # Creating a Redshift cluster with parameter group defined separately
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Define parameter group separately without enabling user activity logging
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group without logging"
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_12():
    # Creating a Redshift cluster with conditional parameter that doesn't enable logging
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Conditional parameter that doesn't enable logging
    enable_ssl = True
    params = {}
    if enable_ssl:
        params["require_ssl"] = "true"
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters=params
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_13():
    # Creating a Redshift cluster with parameter group but using variable that resolves to false
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Using variable that resolves to false
    enable_logging = "false"
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            "enable_user_activity_logging": enable_logging,
            "require_ssl": "true"
        }
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_14():
    # Creating a Redshift cluster with parameter group from CloudFormation parameter that defaults to false
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # CloudFormation parameter that defaults to false
    enable_logging_param = CfnParameter(stack, "EnableLogging", 
        type="String",
        default="false",
        description="Enable user activity logging"
    )
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            "enable_user_activity_logging": enable_logging_param.value_as_string,
            "require_ssl": "true"
        }
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_15():
    # Creating a Redshift cluster with parameter group but using environment variable that's not set
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Using environment variable that's not set (will be None)
    enable_logging = os.environ.get("ENABLE_LOGGING", "false")
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            "enable_user_activity_logging": enable_logging,
            "require_ssl": "true"
        }
    )
    
    # ruleid: python-cdk-redshift-enable-user-activity-logging
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_1():
    # Creating a Redshift cluster with parameter group and enabling user activity logging
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Creating a parameter group with user activity logging enabled
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": "true",
            "require_ssl": "true"
        }
    )
    
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_2():
    # Creating a Redshift cluster with parameter group and enabling user activity logging using boolean
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Creating a parameter group with user activity logging enabled using boolean
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": "True",
            "require_ssl": "true"
        }
    )
    
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_3():
    # Using CfnCluster with parameter group and enabling user activity logging
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    param_group = redshift.CfnClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameter_group_family="redshift-1.0",
        parameters=[
            # ok: python-cdk-redshift-enable-user-activity-logging
            {"parameter_name": "enable_user_activity_logging", "parameter_value": "true"},
            {"parameter_name": "require_ssl", "parameter_value": "true"}
        ]
    )
    
    cluster = redshift.CfnCluster(stack, "MyRedshiftCluster",
        cluster_type="multi-node",
        number_of_nodes=2,
        node_type="ra3.4xlarge",
        master_username="admin",
        master_user_password="Password123",
        cluster_parameter_group_name=param_group.ref
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_4():
    # Creating multiple Redshift clusters with user activity logging enabled for all
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Creating a parameter group with user activity logging enabled
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": "true",
            "require_ssl": "true"
        }
    )
    
    cluster1 = redshift.Cluster(stack, "ProductionRedshift",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )
    
    cluster2 = redshift.Cluster(stack, "StagingRedshift",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_5():
    # Creating a Redshift cluster with parameter group and enabling user activity logging using numeric 1
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Creating a parameter group with user activity logging enabled using numeric 1
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": "1",
            "require_ssl": "true"
        }
    )
    
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_6():
    # Creating a Redshift cluster with parameter group and enabling user activity logging using environment variable
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Using environment variable with default to true
    enable_logging = os.environ.get("ENABLE_LOGGING", "true")
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": enable_logging,
            "require_ssl": "true"
        }
    )
    
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_7():
    # Creating a Redshift cluster with parameter group and enabling user activity logging using CloudFormation parameter
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # CloudFormation parameter that defaults to true
    enable_logging_param = CfnParameter(stack, "EnableLogging", 
        type="String",
        default="true",
        description="Enable user activity logging"
    )
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": enable_logging_param.value_as_string,
            "require_ssl": "true"
        }
    )
    
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_8():
    # Creating a Redshift cluster with parameter group and enabling user activity logging with conditional logic
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # Conditional parameter that enables logging
    is_production = True
    params = {
        "require_ssl": "true"
    }
    
    if is_production:
        # ok: python-cdk-redshift-enable-user-activity-logging
        params["enable_user_activity_logging"] = "true"
    else:
        params["enable_user_activity_logging"] = "true"  # Still enabled for non-production
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters=params
    )
    
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_9():
    # Creating a Redshift cluster with parameter group and enabling user activity logging with string concatenation
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # String concatenation to form parameter value
    enable_prefix = "tr"
    enable_suffix = "ue"
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": enable_prefix + enable_suffix,
            "require_ssl": "true"
        }
    )
    
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_10():
    # Creating a Redshift cluster with parameter group and enabling user activity logging with function call
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    def get_logging_value():
        return "true"
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": get_logging_value(),
            "require_ssl": "true"
        }
    )
    
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_11():
    # Creating a Redshift cluster with parameter group and enabling user activity logging with dictionary lookup
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    config = {
        "logging": "true",
        "ssl": "true"
    }
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": config["logging"],
            "require_ssl": config["ssl"]
        }
    )
    
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_12():
    # Creating a Redshift cluster with parameter group and enabling user activity logging with ternary operator
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    is_compliance_required = True
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": "true" if is_compliance_required else "true",  # Always true in this case
            "require_ssl": "true"
        }
    )
    
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_13():
    # Creating a Redshift cluster with parameter group and enabling user activity logging with uppercase TRUE
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": "TRUE",
            "require_ssl": "true"
        }
    )
    
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_14():
    # Creating a Redshift cluster with parameter group and enabling user activity logging with mixed case
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    param_group = redshift.ClusterParameterGroup(stack, "RedshiftParamGroup",
        description="Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": "TrUe",
            "require_ssl": "true"
        }
    )
    
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=param_group
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_15():
    # Creating a Redshift cluster with imported parameter group that has logging enabled
    app = cdk.App()
    stack = Stack(app, "RedshiftStack")
    
    # First create a parameter group with logging enabled
    secure_param_group = redshift.ClusterParameterGroup(stack, "SecureParamGroup",
        description="Secure Redshift parameter group",
        parameters={
            # ok: python-cdk-redshift-enable-user-activity-logging
            "enable_user_activity_logging": "true",
            "require_ssl": "true"
        }
    )
    
    # Then use the parameter group with a cluster
    cluster = redshift.Cluster(stack, "MyRedshiftCluster",
        master_user=redshift.Login(
            master_username="admin"
        ),
        vpc=None,  # This would be a real VPC in production
        parameter_group=secure_param_group
    )
# {/fact}