import aws_cdk as cdk
from aws_cdk import (
    aws_neptune as neptune,
    Stack,
    App,
    CfnOutput
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_1():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        auto_minor_version_upgrade=False,
        availability_zone="us-west-2a"
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_2():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        engine_version="1.1.0.0"
    )
    
    # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref,
        auto_minor_version_upgrade=False
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_3():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune cluster with auto minor version upgrade disabled
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    subnet_group = neptune.CfnDBSubnetGroup(
        stack, "NeptuneSubnetGroup",
        db_subnet_group_description="Neptune Subnet Group",
        subnet_ids=vpc.select_subnets().subnet_ids
    )
    
    # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_subnet_group_name=subnet_group.ref,
        auto_minor_version_upgrade=False
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_4():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Define configuration parameters
    instance_type = "db.r5.large"
    auto_upgrade = False
    
    # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class=instance_type,
        auto_minor_version_upgrade=auto_upgrade
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_5():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create multiple Neptune instances with auto minor version upgrade disabled
    for i in range(3):
        # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
        instance = neptune.CfnDBInstance(
            stack, f"NeptuneInstance{i}",
            db_instance_class="db.r5.large",
            auto_minor_version_upgrade=False
        )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_6():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Using a dictionary for configuration
    config = {
        "instance_class": "db.r5.large",
        "auto_upgrade": False
    }
    
    # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class=config["instance_class"],
        auto_minor_version_upgrade=config["auto_upgrade"]
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_7():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune cluster with specific parameters
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        engine_version="1.1.0.0",
        db_cluster_parameter_group_name="default.neptune1.1"
    )
    
    # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref,
        auto_minor_version_upgrade=False,
        preferred_maintenance_window="sun:04:00-sun:05:00"
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_8():
    class NeptuneStack(Stack):
        def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
            super().__init__(scope, construct_id, **kwargs)
            
            # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
            neptune.CfnDBInstance(
                self, "NeptuneInstance",
                db_instance_class="db.r5.large",
                auto_minor_version_upgrade=False
            )
    
    app = App()
    stack = NeptuneStack(app, "NeptuneStack")
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_9():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune instance with auto minor version upgrade explicitly disabled
    auto_upgrade_enabled = False
    
    # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        auto_minor_version_upgrade=auto_upgrade_enabled
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_10():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Function to create Neptune instances
    def create_neptune_instance(id_suffix, auto_upgrade):
        # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
        return neptune.CfnDBInstance(
            stack, f"NeptuneInstance{id_suffix}",
            db_instance_class="db.r5.large",
            auto_minor_version_upgrade=auto_upgrade
        )
    
    # Create instance with auto minor version upgrade disabled
    instance = create_neptune_instance("Primary", False)
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_11():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune instance with conditional configuration
    is_production = True
    
    # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large" if is_production else "db.r5.medium",
        auto_minor_version_upgrade=False
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_12():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune instance with all parameters
    # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        auto_minor_version_upgrade=False,
        allow_major_version_upgrade=True,
        db_parameter_group_name="default.neptune1.1",
        preferred_backup_window="02:00-03:00"
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_13():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune instance with auto minor version upgrade disabled through variable
    config_params = {}
    config_params["auto_minor_version_upgrade"] = False
    
    # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        **config_params
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_14():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune cluster with specific configuration
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    security_group = cdk.aws_ec2.SecurityGroup(
        stack, "NeptuneSecurityGroup",
        vpc=vpc,
        description="Security group for Neptune database"
    )
    
    # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        auto_minor_version_upgrade=False,
        vpc_security_groups=[security_group.security_group_id]
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_15():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create multiple Neptune instances with different configurations
    instance_configs = [
        {"id": "Primary", "class": "db.r5.large", "auto_upgrade": False},
        {"id": "Replica1", "class": "db.r5.medium", "auto_upgrade": True}
    ]
    
    for config in instance_configs:
        if not config["auto_upgrade"]:
            # ruleid: python-cdk-neptune-cluster-automatic-minor-version-upgrade
            instance = neptune.CfnDBInstance(
                stack, f"NeptuneInstance{config['id']}",
                db_instance_class=config["class"],
                auto_minor_version_upgrade=config["auto_upgrade"]
            )
        else:
            instance = neptune.CfnDBInstance(
                stack, f"NeptuneInstance{config['id']}",
                db_instance_class=config["class"],
                auto_minor_version_upgrade=config["auto_upgrade"]
            )
    
    return stack

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_1():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        auto_minor_version_upgrade=True,
        availability_zone="us-west-2a"
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_2():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        engine_version="1.1.0.0"
    )
    
    # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref,
        auto_minor_version_upgrade=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_3():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune cluster with auto minor version upgrade enabled
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    subnet_group = neptune.CfnDBSubnetGroup(
        stack, "NeptuneSubnetGroup",
        db_subnet_group_description="Neptune Subnet Group",
        subnet_ids=vpc.select_subnets().subnet_ids
    )
    
    # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_subnet_group_name=subnet_group.ref,
        auto_minor_version_upgrade=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_4():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Define configuration parameters
    instance_type = "db.r5.large"
    auto_upgrade = True
    
    # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class=instance_type,
        auto_minor_version_upgrade=auto_upgrade
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_5():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create multiple Neptune instances with auto minor version upgrade enabled
    for i in range(3):
        # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
        instance = neptune.CfnDBInstance(
            stack, f"NeptuneInstance{i}",
            db_instance_class="db.r5.large",
            auto_minor_version_upgrade=True
        )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_6():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Using a dictionary for configuration
    config = {
        "instance_class": "db.r5.large",
        "auto_upgrade": True
    }
    
    # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class=config["instance_class"],
        auto_minor_version_upgrade=config["auto_upgrade"]
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_7():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune cluster with specific parameters
    cluster = neptune.CfnDBCluster(
        stack, "NeptuneCluster",
        engine_version="1.1.0.0",
        db_cluster_parameter_group_name="default.neptune1.1"
    )
    
    # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        db_cluster_identifier=cluster.ref,
        auto_minor_version_upgrade=True,
        preferred_maintenance_window="sun:04:00-sun:05:00"
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_8():
    class NeptuneStack(Stack):
        def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
            super().__init__(scope, construct_id, **kwargs)
            
            # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
            neptune.CfnDBInstance(
                self, "NeptuneInstance",
                db_instance_class="db.r5.large",
                auto_minor_version_upgrade=True
            )
    
    app = App()
    stack = NeptuneStack(app, "NeptuneStack")
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_9():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune instance with auto minor version upgrade explicitly enabled
    auto_upgrade_enabled = True
    
    # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        auto_minor_version_upgrade=auto_upgrade_enabled
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_10():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Function to create Neptune instances
    def create_neptune_instance(id_suffix, auto_upgrade):
        # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
        return neptune.CfnDBInstance(
            stack, f"NeptuneInstance{id_suffix}",
            db_instance_class="db.r5.large",
            auto_minor_version_upgrade=auto_upgrade
        )
    
    # Create instance with auto minor version upgrade enabled
    instance = create_neptune_instance("Primary", True)
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_11():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune instance with default auto minor version upgrade (True)
    # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large"
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_12():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune instance with all parameters
    # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        auto_minor_version_upgrade=True,
        allow_major_version_upgrade=True,
        db_parameter_group_name="default.neptune1.1",
        preferred_backup_window="02:00-03:00"
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_13():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune instance with auto minor version upgrade enabled through variable
    config_params = {}
    config_params["auto_minor_version_upgrade"] = True
    
    # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        **config_params
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_14():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create a Neptune cluster with specific configuration
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    security_group = cdk.aws_ec2.SecurityGroup(
        stack, "NeptuneSecurityGroup",
        vpc=vpc,
        description="Security group for Neptune database"
    )
    
    # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
    instance = neptune.CfnDBInstance(
        stack, "NeptuneInstance",
        db_instance_class="db.r5.large",
        auto_minor_version_upgrade=True,
        vpc_security_groups=[security_group.security_group_id]
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_15():
    app = cdk.App()
    stack = cdk.Stack(app, "NeptuneStack")
    
    # Create multiple Neptune instances with different configurations
    instance_configs = [
        {"id": "Primary", "class": "db.r5.large"},
        {"id": "Replica1", "class": "db.r5.medium"}
    ]
    
    for config in instance_configs:
        # ok: python-cdk-neptune-cluster-automatic-minor-version-upgrade
        instance = neptune.CfnDBInstance(
            stack, f"NeptuneInstance{config['id']}",
            db_instance_class=config["class"],
            auto_minor_version_upgrade=True
        )
    
    return stack
# {/fact}