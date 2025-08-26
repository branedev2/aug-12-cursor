import aws_cdk as cdk
from aws_cdk import (
    aws_kms as kms,
    Stack,
    Duration,
    RemovalPolicy,
    CfnOutput,
)
from constructs import Construct

# True Positives (Vulnerable Code - Missing Key Rotation)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1():
    # Creating a KMS key without enabling rotation
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=Stack(None, "MyStack"),
        id="MyKey1",
        description="My KMS Key for encryption",
        enable_key_rotation=False,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2():
    # Creating a KMS key without specifying rotation (defaults to False)
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=Stack(None, "MyStack"),
        id="MyKey2",
        description="Key for S3 encryption",
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3():
    # Creating a KMS key with explicit disable of rotation
    stack = Stack(None, "MyStack")
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey3",
        description="Key for RDS encryption",
        enable_key_rotation=False,
        removal_policy=RemovalPolicy.DESTROY,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4():
    # Creating a KMS key with rotation disabled and alias
    stack = Stack(None, "MyStack")
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey4",
        alias="alias/my-application-key",
        description="Key for application data",
        enable_key_rotation=False,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5():
    # Creating a KMS key with rotation disabled and custom admin principals
    stack = Stack(None, "MyStack")
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey5",
        description="Key with custom admins",
        enable_key_rotation=False,
        admins=["arn:aws:iam::123456789012:role/Admin"],
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6():
    # Creating a key in a custom stack class without rotation
    class CustomStack(Stack):
        def __init__(self, scope, id):
            super().__init__(scope, id)
            # ruleid: python_cdk_kms_backing_key_rotation_enabled
            self.key = kms.Key(
                scope=self,
                id="MyKey6",
                description="Key in custom stack",
                enable_key_rotation=False,
            )
    
    app = cdk.App()
    stack = CustomStack(app, "CustomStack")
    return stack.key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7():
    # Creating a key with specific key usage but no rotation
    stack = Stack(None, "MyStack")
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey7",
        description="Key for specific usage",
        enabled=True,
        key_usage=kms.KeyUsage.ENCRYPT_DECRYPT,
        enable_key_rotation=False,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8():
    # Creating a symmetric encryption key without rotation
    stack = Stack(None, "MyStack")
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey8",
        description="Symmetric encryption key",
        key_spec=kms.KeySpec.SYMMETRIC_DEFAULT,
        enable_key_rotation=False,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9():
    # Creating a key with pending window but no rotation
    stack = Stack(None, "MyStack")
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey9",
        description="Key with pending window",
        pending_window=Duration.days(7),
        enable_key_rotation=False,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10():
    # Creating a key with trusted accounts but no rotation
    stack = Stack(None, "MyStack")
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey10",
        description="Key with trusted accounts",
        trusted_account_ids=["123456789012"],
        enable_key_rotation=False,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11():
    # Creating a key with policy but no rotation
    stack = Stack(None, "MyStack")
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "kms:*",
                "Resource": "*"
            }
        ]
    }
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey11",
        description="Key with policy",
        policy=policy_document,
        enable_key_rotation=False,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12():
    # Creating a key with specific rotation but set to False
    stack = Stack(None, "MyStack")
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey12",
        description="Key with explicit False rotation",
        enable_key_rotation=False,
    )
    CfnOutput(stack, "KeyArn", value=key.key_arn)
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13():
    # Creating a key with variable but setting to False
    stack = Stack(None, "MyStack")
    rotation_enabled = False
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey13",
        description="Key with variable rotation setting",
        enable_key_rotation=rotation_enabled,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14():
    # Creating a key with conditional but defaulting to False
    stack = Stack(None, "MyStack")
    env = "dev"
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey14",
        description="Key with conditional rotation",
        enable_key_rotation=True if env == "prod" else False,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15():
    # Creating a key with complex configuration but no rotation
    stack = Stack(None, "MyStack")
    # ruleid: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey15",
        description="Complex key configuration",
        alias="alias/complex-key",
        enabled=True,
        key_usage=kms.KeyUsage.ENCRYPT_DECRYPT,
        key_spec=kms.KeySpec.SYMMETRIC_DEFAULT,
        pending_window=Duration.days(7),
        removal_policy=RemovalPolicy.RETAIN,
        enable_key_rotation=False,
    )
    return key

# True Negatives (Secure Code - Key Rotation Enabled)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1():
    # Creating a KMS key with rotation enabled
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=Stack(None, "MyStack"),
        id="MyKey1",
        description="My KMS Key for encryption",
        enable_key_rotation=True,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2():
    # Creating a KMS key with rotation enabled and alias
    stack = Stack(None, "MyStack")
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey2",
        alias="alias/my-secure-key",
        description="Secure key with rotation",
        enable_key_rotation=True,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3():
    # Creating a KMS key with rotation enabled in a custom stack
    class CustomStack(Stack):
        def __init__(self, scope, id):
            super().__init__(scope, id)
            # ok: python_cdk_kms_backing_key_rotation_enabled
            self.key = kms.Key(
                scope=self,
                id="MyKey3",
                description="Secure key in custom stack",
                enable_key_rotation=True,
            )
    
    app = cdk.App()
    stack = CustomStack(app, "CustomStack")
    return stack.key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4():
    # Creating a key with rotation enabled and specific key usage
    stack = Stack(None, "MyStack")
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey4",
        description="Secure key for specific usage",
        enabled=True,
        key_usage=kms.KeyUsage.ENCRYPT_DECRYPT,
        enable_key_rotation=True,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5():
    # Creating a symmetric encryption key with rotation enabled
    stack = Stack(None, "MyStack")
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey5",
        description="Secure symmetric encryption key",
        key_spec=kms.KeySpec.SYMMETRIC_DEFAULT,
        enable_key_rotation=True,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6():
    # Creating a key with pending window and rotation enabled
    stack = Stack(None, "MyStack")
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey6",
        description="Secure key with pending window",
        pending_window=Duration.days(7),
        enable_key_rotation=True,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7():
    # Creating a key with trusted accounts and rotation enabled
    stack = Stack(None, "MyStack")
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey7",
        description="Secure key with trusted accounts",
        trusted_account_ids=["123456789012"],
        enable_key_rotation=True,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8():
    # Creating a key with policy and rotation enabled
    stack = Stack(None, "MyStack")
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "kms:*",
                "Resource": "*"
            }
        ]
    }
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey8",
        description="Secure key with policy",
        policy=policy_document,
        enable_key_rotation=True,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9():
    # Creating a key with variable set to True
    stack = Stack(None, "MyStack")
    rotation_enabled = True
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey9",
        description="Secure key with variable rotation",
        enable_key_rotation=rotation_enabled,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10():
    # Creating a key with conditional always True
    stack = Stack(None, "MyStack")
    env = "dev"
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey10",
        description="Secure key with conditional rotation",
        enable_key_rotation=True if env in ["dev", "prod"] else True,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11():
    # Creating a key with complex configuration and rotation enabled
    stack = Stack(None, "MyStack")
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey11",
        description="Secure complex key configuration",
        alias="alias/secure-complex-key",
        enabled=True,
        key_usage=kms.KeyUsage.ENCRYPT_DECRYPT,
        key_spec=kms.KeySpec.SYMMETRIC_DEFAULT,
        pending_window=Duration.days(7),
        removal_policy=RemovalPolicy.RETAIN,
        enable_key_rotation=True,
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12():
    # Creating a key with rotation enabled and custom admins
    stack = Stack(None, "MyStack")
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey12",
        description="Secure key with custom admins",
        enable_key_rotation=True,
        admins=["arn:aws:iam::123456789012:role/Admin"],
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13():
    # Creating a key with rotation enabled and output
    stack = Stack(None, "MyStack")
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey13",
        description="Secure key with output",
        enable_key_rotation=True,
    )
    CfnOutput(stack, "KeyArn", value=key.key_arn)
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14():
    # Creating a key with rotation enabled using a function
    stack = Stack(None, "MyStack")
    
    def get_rotation_setting():
        return True
    
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey14",
        description="Secure key with function setting",
        enable_key_rotation=get_rotation_setting(),
    )
    return key

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15():
    # Creating a key with rotation enabled using a constant
    stack = Stack(None, "MyStack")
    ROTATION_ENABLED = True
    # ok: python_cdk_kms_backing_key_rotation_enabled
    key = kms.Key(
        scope=stack,
        id="MyKey15",
        description="Secure key with constant",
        enable_key_rotation=ROTATION_ENABLED,
    )
    return key
# {/fact}