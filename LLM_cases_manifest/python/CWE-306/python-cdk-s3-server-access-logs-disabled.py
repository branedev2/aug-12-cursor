import aws_cdk as cdk
from aws_cdk import (
    aws_s3 as s3,
    Stack,
    RemovalPolicy,
    Duration,
    CfnOutput,
)
from constructs import Construct

# True Positives (Vulnerable Code Examples)

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_1():
    # Creating an S3 bucket without server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "MyBucket",
        versioned=True,
        encryption=s3.BucketEncryption.S3_MANAGED,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_2():
    # Creating an S3 bucket with explicit server_access_logs_prefix but no target bucket
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "MyBucket",
        server_access_logs_prefix="logs/",
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_3():
    # Creating an S3 bucket with empty server access logs configuration
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "MyBucket",
        removal_policy=RemovalPolicy.DESTROY,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_4():
    # Creating a website bucket without server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "WebsiteBucket",
        website_index_document="index.html",
        website_error_document="error.html",
        public_read_access=True,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_5():
    # Creating a bucket with lifecycle rules but no server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "ArchiveBucket",
        lifecycle_rules=[
            s3.LifecycleRule(
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.GLACIER,
                        transition_after=Duration.days(30),
                    )
                ]
            )
        ],
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_6():
    # Creating a bucket with CORS configuration but no server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "ApiAssetsBucket",
        cors=[
            s3.CorsRule(
                allowed_methods=[s3.HttpMethods.GET],
                allowed_origins=["https://example.com"],
                allowed_headers=["*"],
            )
        ],
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_7():
    # Creating a bucket with encryption but no server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "EncryptedBucket",
        encryption=s3.BucketEncryption.KMS,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_8():
    # Creating a bucket with object lock enabled but no server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "ComplianceBucket",
        object_lock_enabled=True,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_9():
    # Creating a bucket with block public access disabled but no server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "PublicBucket",
        block_public_access=s3.BlockPublicAccess(
            block_public_acls=False,
            block_public_policy=False,
            ignore_public_acls=False,
            restrict_public_buckets=False,
        ),
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_10():
    # Creating a bucket with versioning but no server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "VersionedBucket",
        versioned=True,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_11():
    # Creating a bucket with transfer acceleration but no server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "FastBucket",
        transfer_acceleration=True,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_12():
    # Creating a bucket with intelligent tiering but no server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "TieredBucket",
        intelligent_tiering_configurations=[
            s3.IntelligentTieringConfiguration(
                name="archive-config",
                archive_access_tier_after=Duration.days(90),
                deep_archive_access_tier_after=Duration.days(180),
            )
        ],
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_13():
    # Creating a bucket with metrics but no server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "MetricsBucket",
        metrics=[s3.BucketMetrics(id="documents", prefix="documents/")],
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_14():
    # Creating a bucket with inventory but no server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    inventory_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "InventoryDestination")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "SourceBucket",
        inventory=[
            s3.Inventory(
                destination=s3.InventoryDestination.to_bucket(inventory_bucket),
                enabled=True,
                frequency=s3.InventoryFrequency.WEEKLY,
                include_object_versions=s3.InventoryObjectVersion.CURRENT,
            )
        ],
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_15():
    # Creating a bucket with event notifications but no server access logging
    # ruleid: python-cdk-s3-server-access-logs-disabled
    class MyStack(Stack):
        def __init__(self, scope, id):
            super().__init__(scope, id)
            bucket = s3.Bucket(
                self,
                "EventBucket",
            )
            # Add event notification (would normally connect to Lambda/SQS/SNS)
            bucket.add_event_notification(
                s3.EventType.OBJECT_CREATED,
                s3.BucketNotification()
            )
            return bucket
    
    app = cdk.App()
    stack = MyStack(app, "EventNotificationStack")
    return stack

# True Negatives (Secure Code Examples)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_1():
    # Creating a bucket with server access logging enabled
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "MyBucket",
        server_access_logs_bucket=log_bucket,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_2():
    # Creating a bucket with server access logging enabled and prefix
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "MyBucket",
        server_access_logs_bucket=log_bucket,
        server_access_logs_prefix="access-logs/",
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_3():
    # Creating a website bucket with server access logging enabled
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "WebsiteBucket",
        website_index_document="index.html",
        website_error_document="error.html",
        public_read_access=True,
        server_access_logs_bucket=log_bucket,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_4():
    # Creating a bucket with lifecycle rules and server access logging
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "ArchiveBucket",
        lifecycle_rules=[
            s3.LifecycleRule(
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.GLACIER,
                        transition_after=Duration.days(30),
                    )
                ]
            )
        ],
        server_access_logs_bucket=log_bucket,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_5():
    # Creating a bucket with CORS configuration and server access logging
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "ApiAssetsBucket",
        cors=[
            s3.CorsRule(
                allowed_methods=[s3.HttpMethods.GET],
                allowed_origins=["https://example.com"],
                allowed_headers=["*"],
            )
        ],
        server_access_logs_bucket=log_bucket,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_6():
    # Creating a bucket with encryption and server access logging
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "EncryptedBucket",
        encryption=s3.BucketEncryption.KMS,
        server_access_logs_bucket=log_bucket,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_7():
    # Creating a bucket with object lock enabled and server access logging
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "ComplianceBucket",
        object_lock_enabled=True,
        server_access_logs_bucket=log_bucket,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_8():
    # Creating a bucket with block public access disabled but with server access logging
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "PublicBucket",
        block_public_access=s3.BlockPublicAccess(
            block_public_acls=False,
            block_public_policy=False,
            ignore_public_acls=False,
            restrict_public_buckets=False,
        ),
        server_access_logs_bucket=log_bucket,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_9():
    # Creating a bucket with versioning and server access logging
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "VersionedBucket",
        versioned=True,
        server_access_logs_bucket=log_bucket,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_10():
    # Creating a bucket with transfer acceleration and server access logging
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "FastBucket",
        transfer_acceleration=True,
        server_access_logs_bucket=log_bucket,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_11():
    # Creating a bucket with intelligent tiering and server access logging
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "TieredBucket",
        intelligent_tiering_configurations=[
            s3.IntelligentTieringConfiguration(
                name="archive-config",
                archive_access_tier_after=Duration.days(90),
                deep_archive_access_tier_after=Duration.days(180),
            )
        ],
        server_access_logs_bucket=log_bucket,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_12():
    # Creating a bucket with metrics and server access logging
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "MetricsBucket",
        metrics=[s3.BucketMetrics(id="documents", prefix="documents/")],
        server_access_logs_bucket=log_bucket,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_13():
    # Creating a bucket with inventory and server access logging
    # ok: python-cdk-s3-server-access-logs-disabled
    log_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "LogBucket")
    inventory_bucket = s3.Bucket(Stack(cdk.App(), "MyStack"), "InventoryDestination")
    bucket = s3.Bucket(
        Stack(cdk.App(), "MyStack"),
        "SourceBucket",
        inventory=[
            s3.Inventory(
                destination=s3.InventoryDestination.to_bucket(inventory_bucket),
                enabled=True,
                frequency=s3.InventoryFrequency.WEEKLY,
                include_object_versions=s3.InventoryObjectVersion.CURRENT,
            )
        ],
        server_access_logs_bucket=log_bucket,
    )
    return bucket

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_14():
    # Creating a bucket with event notifications and server access logging
    # ok: python-cdk-s3-server-access-logs-disabled
    class MyStack(Stack):
        def __init__(self, scope, id):
            super().__init__(scope, id)
            log_bucket = s3.Bucket(self, "LogBucket")
            bucket = s3.Bucket(
                self,
                "EventBucket",
                server_access_logs_bucket=log_bucket,
            )
            # Add event notification (would normally connect to Lambda/SQS/SNS)
            bucket.add_event_notification(
                s3.EventType.OBJECT_CREATED,
                s3.BucketNotification()
            )
            return bucket
    
    app = cdk.App()
    stack = MyStack(app, "EventNotificationStack")
    return stack

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_15():
    # Creating a bucket with self-logging (logging to itself)
    # ok: python-cdk-s3-server-access-logs-disabled
    class SelfLoggingBucketStack(Stack):
        def __init__(self, scope, id):
            super().__init__(scope, id)
            
            # Create the bucket first
            bucket = s3.Bucket(self, "SelfLoggingBucket")
            
            # Then configure it to log to itself
            bucket.add_to_resource_policy(
                cdk.aws_iam.PolicyStatement(
                    actions=["s3:PutObject"],
                    resources=[f"{bucket.bucket_arn}/logs/*"],
                    principals=[cdk.aws_iam.ServicePrincipal("logging.s3.amazonaws.com")]
                )
            )
            
            # Set the server access logs configuration
            cfn_bucket = bucket.node.default_child
            cfn_bucket.logging_configuration = {
                "destination_bucket_name": bucket.bucket_name,
                "log_file_prefix": "logs/"
            }
            
            return bucket
    
    app = cdk.App()
    stack = SelfLoggingBucketStack(app, "SelfLoggingBucketStack")
    return stack
# {/fact}