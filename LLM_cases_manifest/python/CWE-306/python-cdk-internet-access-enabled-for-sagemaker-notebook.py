import aws_cdk as cdk
from aws_cdk import (
    aws_sagemaker as sagemaker,
    Stack,
    CfnOutput,
    aws_ec2 as ec2,
    aws_iam as iam
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a SageMaker notebook instance with direct internet access enabled (default)
    # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook1",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole"
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Explicitly enabling direct internet access
    # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook2",
        instance_type="ml.t3.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access="Enabled"
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Using a variable to set direct internet access to enabled
    internet_access = "Enabled"
    # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook3",
        instance_type="ml.m5.xlarge",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access=internet_access
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Using a function that returns "Enabled" for direct internet access
    def get_internet_access():
        return "Enabled"
    
    # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook4",
        instance_type="ml.c5.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access=get_internet_access()
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating notebook with internet access in a conditional block
    instance_type = "ml.t2.medium"
    if instance_type.startswith("ml.t"):
        # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
        notebook = sagemaker.CfnNotebookInstance(
            scope,
            "VulnerableNotebook5",
            instance_type=instance_type,
            role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
            direct_internet_access="Enabled"
        )
    else:
        notebook = sagemaker.CfnNotebookInstance(
            scope,
            "SecureNotebook",
            instance_type=instance_type,
            role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
            direct_internet_access="Disabled"
        )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating notebook with internet access using a dictionary for properties
    props = {
        "instance_type": "ml.t2.medium",
        "role_arn": "arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        "direct_internet_access": "Enabled"
    }
    
    # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook6",
        **props
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating multiple notebooks with one having internet access enabled
    notebook1 = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access="Disabled"
    )
    
    # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook2 = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook7",
        instance_type="ml.t2.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access="Enabled"
    )
    return [notebook1, notebook2]

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Using string concatenation to set direct internet access
    access_type = "En" + "abled"
    
    # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook8",
        instance_type="ml.m5.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access=access_type
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Using a loop to create notebooks with internet access enabled
    notebooks = []
    for i in range(3):
        # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
        notebook = sagemaker.CfnNotebookInstance(
            scope,
            f"VulnerableNotebook9_{i}",
            instance_type=f"ml.t2.medium",
            role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
            direct_internet_access="Enabled"
        )
        notebooks.append(notebook)
    return notebooks

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Using a class to create a notebook with internet access
    class NotebookCreator:
        def __init__(self, scope, id):
            self.scope = scope
            self.id = id
            
        def create_notebook(self):
            # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
            return sagemaker.CfnNotebookInstance(
                self.scope,
                f"VulnerableNotebook10",
                instance_type="ml.t2.medium",
                role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
                direct_internet_access="Enabled"
            )
    
    creator = NotebookCreator(scope, id)
    return creator.create_notebook()

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Using environment configuration with internet access enabled
    env_config = {
        "dev": {
            "instance_type": "ml.t2.medium",
            "internet_access": "Enabled"
        },
        "prod": {
            "instance_type": "ml.m5.large",
            "internet_access": "Disabled"
        }
    }
    
    env = "dev"
    # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook11",
        instance_type=env_config[env]["instance_type"],
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access=env_config[env]["internet_access"]
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Using a try-except block with internet access enabled in the try block
    try:
        # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
        notebook = sagemaker.CfnNotebookInstance(
            scope,
            "VulnerableNotebook12",
            instance_type="ml.t2.medium",
            role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
            direct_internet_access="Enabled"
        )
    except Exception:
        notebook = sagemaker.CfnNotebookInstance(
            scope,
            "FallbackNotebook",
            instance_type="ml.t2.small",
            role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
            direct_internet_access="Disabled"
        )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Using a custom stack with internet access enabled
    class SageMakerStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
            self.notebook = sagemaker.CfnNotebookInstance(
                self,
                "VulnerableNotebook13",
                instance_type="ml.t2.medium",
                role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
                direct_internet_access="Enabled"
            )
    
    stack = SageMakerStack(scope, "SageMakerStack")
    return stack.notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Using a map function to create notebooks with internet access
    instance_types = ["ml.t2.medium", "ml.t2.large", "ml.t3.medium"]
    
    def create_notebook(instance_type):
        # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
        return sagemaker.CfnNotebookInstance(
            scope,
            f"VulnerableNotebook14_{instance_type}",
            instance_type=instance_type,
            role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
            direct_internet_access="Enabled"
        )
    
    notebooks = list(map(create_notebook, instance_types))
    return notebooks

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Using a ternary operator to conditionally set internet access to enabled
    is_dev_environment = True
    
    # ruleid: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook15",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access="Enabled" if is_dev_environment else "Disabled"
    )
    return notebook

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a SageMaker notebook instance with direct internet access explicitly disabled
    # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook1",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access="Disabled"
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Using a variable to set direct internet access to disabled
    internet_access = "Disabled"
    # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook2",
        instance_type="ml.m5.xlarge",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access=internet_access
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Using a function that returns "Disabled" for direct internet access
    def get_internet_access():
        return "Disabled"
    
    # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook3",
        instance_type="ml.c5.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access=get_internet_access()
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating notebook with internet access disabled in a conditional block
    instance_type = "ml.t2.medium"
    if instance_type.startswith("ml.t"):
        # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
        notebook = sagemaker.CfnNotebookInstance(
            scope,
            "SecureNotebook4",
            instance_type=instance_type,
            role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
            direct_internet_access="Disabled"
        )
    else:
        notebook = sagemaker.CfnNotebookInstance(
            scope,
            "AlternateSecureNotebook",
            instance_type=instance_type,
            role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
            direct_internet_access="Disabled"
        )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating notebook with internet access disabled using a dictionary for properties
    props = {
        "instance_type": "ml.t2.medium",
        "role_arn": "arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        "direct_internet_access": "Disabled"
    }
    
    # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook5",
        **props
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating multiple notebooks all with internet access disabled
    notebook1 = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook6_1",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access="Disabled"
    )
    
    # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook2 = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook6_2",
        instance_type="ml.t2.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access="Disabled"
    )
    return [notebook1, notebook2]

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Using string concatenation to set direct internet access to disabled
    access_type = "Dis" + "abled"
    
    # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook7",
        instance_type="ml.m5.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access=access_type
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Using a loop to create notebooks with internet access disabled
    notebooks = []
    for i in range(3):
        # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
        notebook = sagemaker.CfnNotebookInstance(
            scope,
            f"SecureNotebook8_{i}",
            instance_type=f"ml.t2.medium",
            role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
            direct_internet_access="Disabled"
        )
        notebooks.append(notebook)
    return notebooks

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Using a class to create a notebook with internet access disabled
    class NotebookCreator:
        def __init__(self, scope, id):
            self.scope = scope
            self.id = id
            
        def create_notebook(self):
            # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
            return sagemaker.CfnNotebookInstance(
                self.scope,
                f"SecureNotebook9",
                instance_type="ml.t2.medium",
                role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
                direct_internet_access="Disabled"
            )
    
    creator = NotebookCreator(scope, id)
    return creator.create_notebook()

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Using environment configuration with internet access disabled
    env_config = {
        "dev": {
            "instance_type": "ml.t2.medium",
            "internet_access": "Disabled"
        },
        "prod": {
            "instance_type": "ml.m5.large",
            "internet_access": "Disabled"
        }
    }
    
    env = "dev"
    # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook10",
        instance_type=env_config[env]["instance_type"],
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access=env_config[env]["internet_access"]
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Using a try-except block with internet access disabled in both blocks
    try:
        # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
        notebook = sagemaker.CfnNotebookInstance(
            scope,
            "SecureNotebook11",
            instance_type="ml.t2.medium",
            role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
            direct_internet_access="Disabled"
        )
    except Exception:
        notebook = sagemaker.CfnNotebookInstance(
            scope,
            "FallbackSecureNotebook",
            instance_type="ml.t2.small",
            role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
            direct_internet_access="Disabled"
        )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Using a custom stack with internet access disabled
    class SageMakerStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
            self.notebook = sagemaker.CfnNotebookInstance(
                self,
                "SecureNotebook12",
                instance_type="ml.t2.medium",
                role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
                direct_internet_access="Disabled"
            )
    
    stack = SageMakerStack(scope, "SecureSageMakerStack")
    return stack.notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Using a map function to create notebooks with internet access disabled
    instance_types = ["ml.t2.medium", "ml.t2.large", "ml.t3.medium"]
    
    def create_notebook(instance_type):
        # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
        return sagemaker.CfnNotebookInstance(
            scope,
            f"SecureNotebook13_{instance_type}",
            instance_type=instance_type,
            role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
            direct_internet_access="Disabled"
        )
    
    notebooks = list(map(create_notebook, instance_types))
    return notebooks

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Using a ternary operator to always set internet access to disabled
    is_dev_environment = True
    
    # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook14",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access="Disabled" if is_dev_environment else "Disabled"
    )
    return notebook

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Using a VPC configuration instead of direct internet access
    vpc = ec2.Vpc(scope, "SageMakerVPC")
    security_group = ec2.SecurityGroup(scope, "SageMakerSG", vpc=vpc)
    
    # ok: python-cdk-internet-access-enabled-for-sagemaker-notebook
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook15",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole",
        direct_internet_access="Disabled",
        subnet_id=vpc.private_subnets[0].subnet_id,
        security_group_ids=[security_group.security_group_id]
    )
    return notebook
# {/fact}