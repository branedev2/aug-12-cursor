import aws_cdk as cdk
from aws_cdk import (
    aws_sagemaker as sagemaker,
    aws_kms as kms,
    aws_iam as iam,
    Stack,
    CfnOutput,
    RemovalPolicy
)
from constructs import Construct

# True Positives (Vulnerable Code Examples)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a SageMaker notebook instance without encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook1",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/AmazonSageMaker-ExecutionRole"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct):
    # Creating a notebook with minimal configuration, missing encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook2",
        instance_type="ml.t3.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        notebook_instance_name="data-science-notebook"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct):
    # Creating a notebook with tags but no encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook3",
        instance_type="ml.m5.xlarge",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        tags=[{"key": "Environment", "value": "Development"}]
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct):
    # Creating a notebook with lifecycle configuration but no encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook4",
        instance_type="ml.m5.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        lifecycle_config_name="my-lifecycle-config"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct):
    # Creating a notebook with direct internet access but no encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook5",
        instance_type="ml.t2.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        direct_internet_access="Enabled"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct):
    # Creating a notebook with volume size configuration but no encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook6",
        instance_type="ml.t2.xlarge",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        volume_size_in_gb=50
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct):
    # Creating a notebook with subnet and security group but no encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook7",
        instance_type="ml.m4.xlarge",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        subnet_id="subnet-12345",
        security_group_ids=["sg-12345"]
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct):
    # Creating a notebook with root access enabled but no encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook8",
        instance_type="ml.c5.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        root_access="Enabled"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct):
    # Creating a notebook with platform identifier but no encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook9",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        platform_identifier="notebook-al2-v1"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct):
    # Creating a notebook with additional code repositories but no encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook10",
        instance_type="ml.t3.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        additional_code_repositories=["https://github.com/example/repo"]
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct):
    # Creating a notebook with default code repository but no encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook11",
        instance_type="ml.m5.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        default_code_repository="https://github.com/example/default-repo"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct):
    # Creating a notebook with accelerator type but no encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook12",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        accelerator_types=["ml.eia1.medium"]
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct):
    # Creating a notebook with multiple configuration options but no encryption
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook13",
        instance_type="ml.t3.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        direct_internet_access="Enabled",
        volume_size_in_gb=100,
        root_access="Enabled",
        notebook_instance_name="data-science-workbench"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct):
    # Creating a notebook with empty kms_key_id (equivalent to no encryption)
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook14",
        instance_type="ml.m4.xlarge",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=""  # Empty string is equivalent to no encryption
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct):
    # Creating a notebook with None kms_key_id (equivalent to no encryption)
    # ruleid: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "VulnerableNotebook15",
        instance_type="ml.c5.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=None  # None is equivalent to no encryption
    )
    return notebook

# True Negatives (Secure Code Examples)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct):
    # Creating a notebook with KMS key for encryption
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key = kms.Key(scope, "NotebookEncryptionKey1", enable_key_rotation=True)
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook1",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=kms_key.key_id
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct):
    # Creating a notebook with imported KMS key
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    imported_key = kms.Key.from_key_arn(
        scope,
        "ImportedKey",
        "arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    )
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook2",
        instance_type="ml.t3.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=imported_key.key_id
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct):
    # Creating a notebook with KMS key ARN directly
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook3",
        instance_type="ml.m5.xlarge",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id="arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct):
    # Creating a notebook with KMS key and additional configurations
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key = kms.Key(scope, "NotebookEncryptionKey4", enable_key_rotation=True)
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook4",
        instance_type="ml.m5.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=kms_key.key_id,
        lifecycle_config_name="my-lifecycle-config",
        direct_internet_access="Disabled"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct):
    # Creating a notebook with KMS key and volume size
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key = kms.Key(scope, "NotebookEncryptionKey5", enable_key_rotation=True)
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook5",
        instance_type="ml.t2.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=kms_key.key_id,
        volume_size_in_gb=100
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct):
    # Creating a notebook with KMS key and network configuration
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key = kms.Key(scope, "NotebookEncryptionKey6", enable_key_rotation=True)
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook6",
        instance_type="ml.t2.xlarge",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=kms_key.key_id,
        subnet_id="subnet-12345",
        security_group_ids=["sg-12345"]
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct):
    # Creating a notebook with KMS key and root access
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key = kms.Key(scope, "NotebookEncryptionKey7", enable_key_rotation=True)
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook7",
        instance_type="ml.m4.xlarge",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=kms_key.key_id,
        root_access="Disabled"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct):
    # Creating a notebook with KMS key and platform identifier
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key = kms.Key(scope, "NotebookEncryptionKey8", enable_key_rotation=True)
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook8",
        instance_type="ml.c5.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=kms_key.key_id,
        platform_identifier="notebook-al2-v1"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct):
    # Creating a notebook with KMS key and code repositories
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key = kms.Key(scope, "NotebookEncryptionKey9", enable_key_rotation=True)
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook9",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=kms_key.key_id,
        additional_code_repositories=["https://github.com/example/repo"]
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct):
    # Creating a notebook with KMS key and default code repository
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key = kms.Key(scope, "NotebookEncryptionKey10", enable_key_rotation=True)
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook10",
        instance_type="ml.t3.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=kms_key.key_id,
        default_code_repository="https://github.com/example/default-repo"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct):
    # Creating a notebook with KMS key and accelerator type
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key = kms.Key(scope, "NotebookEncryptionKey11", enable_key_rotation=True)
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook11",
        instance_type="ml.m5.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=kms_key.key_id,
        accelerator_types=["ml.eia1.medium"]
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct):
    # Creating a notebook with KMS key and multiple configurations
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key = kms.Key(scope, "NotebookEncryptionKey12", enable_key_rotation=True)
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook12",
        instance_type="ml.t2.medium",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=kms_key.key_id,
        direct_internet_access="Disabled",
        volume_size_in_gb=100,
        root_access="Disabled",
        notebook_instance_name="secure-data-science-workbench"
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct):
    # Creating a notebook with KMS key and tags
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key = kms.Key(scope, "NotebookEncryptionKey13", enable_key_rotation=True)
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook13",
        instance_type="ml.t3.large",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=kms_key.key_id,
        tags=[{"key": "Environment", "value": "Production"}, {"key": "Security", "value": "Encrypted"}]
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct):
    # Creating a notebook with KMS key from a parameter
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key_id = cdk.CfnParameter(scope, "KmsKeyId", type="String", 
                                  description="KMS Key ID for notebook encryption").value_as_string
    
    notebook = sagemaker.CfnNotebookInstance(
        scope,
        "SecureNotebook14",
        instance_type="ml.m4.xlarge",
        role_arn="arn:aws:iam::123456789012:role/service-role/SageMakerRole",
        kms_key_id=kms_key_id
    )
    return notebook

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct):
    # Creating a notebook with KMS key using L2 construct
    # ok: python-cdk-sagemaker-notebook-missing-encryption
    kms_key = kms.Key(scope, "NotebookEncryptionKey15", enable_key_rotation=True)
    
    role = iam.Role(scope, "NotebookRole", assumed_by=iam.ServicePrincipal("sagemaker.amazonaws.com"))
    
    # Using the L2 construct which automatically sets up encryption with the provided KMS key
    notebook = sagemaker.NotebookInstance(
        scope,
        "SecureNotebook15",
        instance_type=sagemaker.InstanceType.M5_LARGE,
        role=role,
        kms_key=kms_key
    )
    return notebook

# {/fact}

class SageMakerStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Examples of vulnerable and secure SageMaker notebook instances
        bad_case_1(self, "BadCase1")
        good_case_1(self)

app = cdk.App()
SageMakerStack(app, "SageMakerStack")
app.synth()