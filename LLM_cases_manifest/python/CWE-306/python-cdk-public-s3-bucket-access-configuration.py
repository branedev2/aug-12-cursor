import aws_cdk as cdk
from aws_cdk import (
    aws_s3 as s3,
    Stack,
    App,
    RemovalPolicy,
)
from constructs import Construct


# True Positive Examples (Vulnerable Code)

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        versioned=True,
        removal_policy=RemovalPolicy.DESTROY
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        encryption=s3.BucketEncryption.S3_MANAGED,
        enforce_ssl=True
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        website_index_document="index.html",
        website_error_document="error.html"
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess(
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=False,  # Not blocking all public access
            restrict_public_buckets=True
        )
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess(
            block_public_acls=True,
            block_public_policy=False,  # Not blocking all public access
            ignore_public_acls=True,
            restrict_public_buckets=True
        )
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess(
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=False  # Not blocking all public access
        )
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess(
            block_public_acls=False,  # Not blocking all public access
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True
        )
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    props = {
        "versioned": True,
        "encryption": s3.BucketEncryption.KMS_MANAGED
    }
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id, **props)
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id)
    bucket.add_lifecycle_rule(
        id="cleanup",
        expiration=cdk.Duration.days(90)
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        cors=[s3.CorsRule(
            allowed_methods=[s3.HttpMethods.GET],
            allowed_origins=["*"],
            allowed_headers=["*"]
        )]
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        metrics=[s3.BucketMetrics(
            id="EntireBucket"
        )]
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        lifecycle_rules=[
            s3.LifecycleRule(
                expiration=cdk.Duration.days(365),
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.GLACIER,
                        transition_after=cdk.Duration.days(30)
                    )
                ]
            )
        ]
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        transfer_acceleration=True
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating partial block public access settings
    bpa = s3.BlockPublicAccess(
        block_public_acls=True,
        block_public_policy=True,
        ignore_public_acls=False,  # Not blocking all public access
        restrict_public_buckets=True
    )
    
    # ruleid: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=bpa
    )
    return bucket


# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        versioned=True,
        removal_policy=RemovalPolicy.DESTROY
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess(
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True
        ),
        encryption=s3.BucketEncryption.S3_MANAGED,
        enforce_ssl=True
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        website_index_document="index.html",
        website_error_document="error.html"
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a fully blocking public access setting
    bpa = s3.BlockPublicAccess(
        block_public_acls=True,
        block_public_policy=True,
        ignore_public_acls=True,
        restrict_public_buckets=True
    )
    
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=bpa
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    props = {
        "versioned": True,
        "encryption": s3.BucketEncryption.KMS_MANAGED,
        "block_public_access": s3.BlockPublicAccess.BLOCK_ALL
    }
    
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id, **props)
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL
    )
    bucket.add_lifecycle_rule(
        id="cleanup",
        expiration=cdk.Duration.days(90)
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        cors=[s3.CorsRule(
            allowed_methods=[s3.HttpMethods.GET],
            allowed_origins=["https://example.com"],
            allowed_headers=["*"]
        )]
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        metrics=[s3.BucketMetrics(
            id="EntireBucket"
        )]
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        lifecycle_rules=[
            s3.LifecycleRule(
                expiration=cdk.Duration.days(365),
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.GLACIER,
                        transition_after=cdk.Duration.days(30)
                    )
                ]
            )
        ]
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        transfer_acceleration=True
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        object_ownership=s3.ObjectOwnership.BUCKET_OWNER_ENFORCED
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        encryption=s3.BucketEncryption.KMS_MANAGED,
        enforce_ssl=True,
        versioned=True
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Define a secure bucket with all public access blocked
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        encryption=s3.BucketEncryption.S3_MANAGED
    )
    
    # Add a bucket policy that only allows specific IAM roles
    bucket.add_to_resource_policy(
        cdk.aws_iam.PolicyStatement(
            actions=["s3:GetObject"],
            resources=[bucket.arn_for_objects("*")],
            principals=[cdk.aws_iam.ArnPrincipal("arn:aws:iam::123456789012:role/MyRole")]
        )
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # ok: python-cdk-public-s3-bucket-access-configuration
    bucket = s3.Bucket(scope, id,
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        server_access_logs_bucket=s3.Bucket(scope, f"{id}-logs", 
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL)
    )
    return bucket


# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a custom stack with secure S3 bucket
    class SecureS3Stack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            # ok: python-cdk-public-s3-bucket-access-configuration
            self.bucket = s3.Bucket(self, "SecureBucket",
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                encryption=s3.BucketEncryption.KMS_MANAGED,
                enforce_ssl=True
            )
    
    # Create the stack
    app = App()
    secure_stack = SecureS3Stack(app, "SecureS3Stack")
    return secure_stack.bucket


# Example usage
# {/fact}

def main():
    app = App()
    stack = Stack(app, "ExampleStack")
    
    # Creating buckets with various configurations
    bad_bucket1 = bad_case_1(stack, "BadBucket1")
    good_bucket1 = good_case_1(stack, "GoodBucket1")
    
    app.synth()

if __name__ == "__main__":
    main()