import aws_cdk as cdk
from aws_cdk import (
    aws_neptune as neptune,
    Stack,
    CfnParameter,
    RemovalPolicy,
    Duration,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_secretsmanager as secretsmanager
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1():
    # Creating a Neptune cluster without encryption at rest
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2():
    # Creating a Neptune cluster with encryption explicitly disabled
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=False,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3():
    # Creating a Neptune cluster with variable set to False
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    encryption_enabled = False
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=encryption_enabled,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4():
    # Creating a Neptune cluster with conditional encryption that's disabled
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    is_production = False
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=is_production,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5():
    # Creating a Neptune cluster with encryption determined by parameter that defaults to False
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    encrypt_param = CfnParameter(stack, "EncryptStorage", default="false", type="String")
    encrypt_value = encrypt_param.value_as_string == "true"
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=encrypt_value,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6():
    # Creating a Neptune cluster in a custom stack class without encryption
    class NeptuneStack(Stack):
        def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
            super().__init__(scope, construct_id, **kwargs)
            
            vpc = ec2.Vpc(self, "VPC")
            
            # ruleid: python-cdk-neptune-cluster-encryption-at-rest
            self.cluster = neptune.DatabaseCluster(self, "Database",
                vpc=vpc,
                instance_type=neptune.InstanceType.R5_LARGE,
                removal_policy=RemovalPolicy.DESTROY
            )
    
    app = cdk.App()
    stack = NeptuneStack(app, "NeptuneStack")
    return stack.cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7():
    # Creating a Neptune cluster with encryption determined by environment variable that's False
    import os
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    # Simulating environment variable
    os.environ["ENCRYPT_STORAGE"] = "False"
    encrypt_value = os.environ.get("ENCRYPT_STORAGE", "False").lower() == "true"
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=encrypt_value,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8():
    # Creating a Neptune cluster with complex conditional that results in no encryption
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    env = "dev"
    is_high_security = env in ["prod", "staging"]
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=is_high_security,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9():
    # Creating a Neptune cluster with encryption in a function that returns False
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    def should_encrypt():
        return False
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=should_encrypt(),
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10():
    # Creating a Neptune cluster with encryption in a dictionary lookup that's False
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    config = {
        "dev": {"encrypt": False},
        "prod": {"encrypt": True}
    }
    
    env = "dev"
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=config[env]["encrypt"],
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11():
    # Creating a Neptune cluster with encryption determined by a complex expression that's False
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    env_type = "development"
    is_sensitive_data = False
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=(env_type == "production" or is_sensitive_data),
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12():
    # Creating a Neptune cluster with encryption in a nested function that returns False
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    def get_config():
        def get_encryption_setting():
            return False
        return {"encrypt": get_encryption_setting()}
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=get_config()["encrypt"],
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13():
    # Creating a Neptune cluster with encryption in a class method that returns False
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    class ConfigProvider:
        @staticmethod
        def should_encrypt():
            return False
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=ConfigProvider.should_encrypt(),
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14():
    # Creating a Neptune cluster with encryption determined by a ternary that's False
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    is_prod = False
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=True if is_prod else False,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15():
    # Creating a Neptune cluster with encryption determined by a complex condition that's False
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    env = "dev"
    region = "us-east-1"
    compliance_required = False
    
    # ruleid: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=(env == "prod" and region == "us-west-2") or compliance_required,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1():
    # Creating a Neptune cluster with encryption at rest enabled
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=True,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2():
    # Creating a Neptune cluster with encryption and KMS key
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=True,
        removal_policy=RemovalPolicy.DESTROY,
        kms_key=cdk.aws_kms.Key(stack, "NeptuneKey")
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3():
    # Creating a Neptune cluster with variable set to True
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    encryption_enabled = True
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=encryption_enabled,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4():
    # Creating a Neptune cluster with conditional encryption that's enabled
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    is_production = True
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=is_production,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5():
    # Creating a Neptune cluster with encryption determined by parameter that defaults to True
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    encrypt_param = CfnParameter(stack, "EncryptStorage", default="true", type="String")
    encrypt_value = encrypt_param.value_as_string == "true"
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=encrypt_value,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6():
    # Creating a Neptune cluster in a custom stack class with encryption
    class NeptuneStack(Stack):
        def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
            super().__init__(scope, construct_id, **kwargs)
            
            vpc = ec2.Vpc(self, "VPC")
            
            # ok: python-cdk-neptune-cluster-encryption-at-rest
            self.cluster = neptune.DatabaseCluster(self, "Database",
                vpc=vpc,
                instance_type=neptune.InstanceType.R5_LARGE,
                storage_encrypted=True,
                removal_policy=RemovalPolicy.DESTROY
            )
    
    app = cdk.App()
    stack = NeptuneStack(app, "NeptuneStack")
    return stack.cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7():
    # Creating a Neptune cluster with encryption determined by environment variable that's True
    import os
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    # Simulating environment variable
    os.environ["ENCRYPT_STORAGE"] = "True"
    encrypt_value = os.environ.get("ENCRYPT_STORAGE", "True").lower() == "true"
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=encrypt_value,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8():
    # Creating a Neptune cluster with complex conditional that results in encryption
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    env = "prod"
    is_high_security = env in ["prod", "staging"]
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=is_high_security,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9():
    # Creating a Neptune cluster with encryption in a function that returns True
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    def should_encrypt():
        return True
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=should_encrypt(),
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10():
    # Creating a Neptune cluster with encryption in a dictionary lookup that's True
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    config = {
        "dev": {"encrypt": True},
        "prod": {"encrypt": True}
    }
    
    env = "dev"
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=config[env]["encrypt"],
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11():
    # Creating a Neptune cluster with encryption determined by a complex expression that's True
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    env_type = "production"
    is_sensitive_data = False
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=(env_type == "production" or is_sensitive_data),
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12():
    # Creating a Neptune cluster with encryption always enabled regardless of environment
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    env = "dev"  # Even in dev, we enforce encryption
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=True,  # Always encrypt, regardless of environment
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13():
    # Creating a Neptune cluster with encryption and custom backup retention
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=True,
        backup_retention=Duration.days(14),
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14():
    # Creating a Neptune cluster with encryption and IAM authentication
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=True,
        iam_authentication=True,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15():
    # Creating a Neptune cluster with encryption and parameter group
    app = cdk.App()
    stack = Stack(app, "NeptuneStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    param_group = neptune.ParameterGroup(stack, "NeptuneParamGroup",
        description="Custom parameter group",
        parameters={
            "neptune_enable_audit_log": "1"
        }
    )
    
    # ok: python-cdk-neptune-cluster-encryption-at-rest
    cluster = neptune.DatabaseCluster(stack, "Database",
        vpc=vpc,
        instance_type=neptune.InstanceType.R5_LARGE,
        storage_encrypted=True,
        parameter_group=param_group,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    return cluster
# {/fact}