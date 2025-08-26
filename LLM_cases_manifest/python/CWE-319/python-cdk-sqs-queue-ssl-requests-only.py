import aws_cdk as cdk
from aws_cdk import (
    aws_sqs as sqs,
    aws_iam as iam,
    Stack,
    CfnOutput,
    Duration
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating an SQS queue without SSL requirement
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(scope, "MyQueue1")
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating an SQS queue with explicit policy but no SSL requirement
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(scope, "MyQueue2")
    
    policy_document = iam.PolicyDocument(
        statements=[
            iam.PolicyStatement(
                actions=["sqs:SendMessage", "sqs:ReceiveMessage"],
                resources=["*"],
                principals=[iam.AnyPrincipal()]
            )
        ]
    )
    
    queue.add_to_resource_policy(policy_document.statements[0])
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a FIFO queue without SSL requirement
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(
        scope, 
        "MyQueue3",
        fifo=True,
        content_based_deduplication=True
    )
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a queue with encryption but no SSL requirement
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(
        scope, 
        "MyQueue4",
        encryption=sqs.QueueEncryption.KMS_MANAGED
    )
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a queue with retention period but no SSL requirement
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(
        scope, 
        "MyQueue5",
        retention_period=Duration.days(7)
    )
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a queue with visibility timeout but no SSL requirement
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(
        scope, 
        "MyQueue6",
        visibility_timeout=Duration.seconds(300)
    )
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a queue with dead letter queue but no SSL requirement
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    dlq = sqs.Queue(scope, "DeadLetterQueue")
    queue = sqs.Queue(
        scope, 
        "MyQueue7",
        dead_letter_queue=sqs.DeadLetterQueue(
            max_receive_count=3,
            queue=dlq
        )
    )
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a queue with policy that has some conditions but not SSL
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(scope, "MyQueue8")
    
    policy_statement = iam.PolicyStatement(
        actions=["sqs:SendMessage"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "StringEquals": {
                "aws:SourceAccount": "123456789012"
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a queue with explicit policy allowing specific principals but no SSL
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(scope, "MyQueue9")
    
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=["sqs:SendMessage", "sqs:ReceiveMessage"],
        resources=[queue.queue_arn],
        principals=[iam.ServicePrincipal("lambda.amazonaws.com")]
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a queue with incorrect SSL condition (wrong value)
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(scope, "MyQueue10")
    
    policy_statement = iam.PolicyStatement(
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"  # This actually allows non-SSL connections
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a queue with incorrect SSL condition (wrong key)
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(scope, "MyQueue11")
    
    policy_statement = iam.PolicyStatement(
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureConnection": "true"  # Wrong key name
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a queue with SSL condition but using Deny effect incorrectly
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(scope, "MyQueue12")
    
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "true"  # This denies SSL connections, which is wrong
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a queue with multiple policy statements but none for SSL
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(scope, "MyQueue13")
    
    statement1 = iam.PolicyStatement(
        actions=["sqs:SendMessage"],
        resources=[queue.queue_arn],
        principals=[iam.ServicePrincipal("lambda.amazonaws.com")]
    )
    
    statement2 = iam.PolicyStatement(
        actions=["sqs:ReceiveMessage"],
        resources=[queue.queue_arn],
        principals=[iam.ServicePrincipal("ec2.amazonaws.com")]
    )
    
    queue.add_to_resource_policy(statement1)
    queue.add_to_resource_policy(statement2)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a queue with policy that uses string condition instead of bool for SSL
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(scope, "MyQueue14")
    
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "StringEquals": {  # Wrong condition type
                "aws:SecureTransport": "false"
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a queue with policy that has partial SSL coverage
    # ruleid: python-cdk-sqs-queue-ssl-requests-only
    queue = sqs.Queue(scope, "MyQueue15")
    
    # This only covers SendMessage, not all actions
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:SendMessage"],  # Not covering all actions
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a queue with proper SSL requirement
    queue = sqs.Queue(scope, "SecureQueue1")
    
    # ok: python-cdk-sqs-queue-ssl-requests-only
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating a FIFO queue with SSL requirement
    queue = sqs.Queue(
        scope, 
        "SecureQueue2",
        fifo=True,
        content_based_deduplication=True
    )
    
    # ok: python-cdk-sqs-queue-ssl-requests-only
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating a queue with encryption and SSL requirement
    queue = sqs.Queue(
        scope, 
        "SecureQueue3",
        encryption=sqs.QueueEncryption.KMS_MANAGED
    )
    
    # ok: python-cdk-sqs-queue-ssl-requests-only
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a queue with SSL requirement and additional conditions
    queue = sqs.Queue(scope, "SecureQueue4")
    
    # ok: python-cdk-sqs-queue-ssl-requests-only
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            },
            "StringEquals": {
                "aws:SourceAccount": "123456789012"
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a queue with SSL requirement and specific service principals
    queue = sqs.Queue(scope, "SecureQueue5")
    
    # First add the SSL requirement
    # ok: python-cdk-sqs-queue-ssl-requests-only
    ssl_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    # Then add specific permissions
    service_statement = iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=["sqs:SendMessage"],
        resources=[queue.queue_arn],
        principals=[iam.ServicePrincipal("lambda.amazonaws.com")]
    )
    
    queue.add_to_resource_policy(ssl_statement)
    queue.add_to_resource_policy(service_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a queue with SSL requirement and dead letter queue
    dlq = sqs.Queue(scope, "SecureDLQ")
    
    # Add SSL requirement to DLQ
    dlq_ssl_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[dlq.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    dlq.add_to_resource_policy(dlq_ssl_statement)
    
    # Create main queue with DLQ
    queue = sqs.Queue(
        scope, 
        "SecureQueue6",
        dead_letter_queue=sqs.DeadLetterQueue(
            max_receive_count=3,
            queue=dlq
        )
    )
    
    # Add SSL requirement to main queue
    # ok: python-cdk-sqs-queue-ssl-requests-only
    queue_ssl_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    queue.add_to_resource_policy(queue_ssl_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a queue with SSL requirement using alternative pattern
    queue = sqs.Queue(scope, "SecureQueue7")
    
    # ok: python-cdk-sqs-queue-ssl-requests-only
    policy_document = iam.PolicyDocument(
        statements=[
            iam.PolicyStatement(
                effect=iam.Effect.DENY,
                actions=["sqs:*"],
                resources=[queue.queue_arn],
                principals=[iam.AnyPrincipal()],
                conditions={
                    "Bool": {
                        "aws:SecureTransport": "false"
                    }
                }
            )
        ]
    )
    
    for statement in policy_document.statements:
        queue.add_to_resource_policy(statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a queue with SSL requirement and specific resource ARN
    queue = sqs.Queue(scope, "SecureQueue8")
    
    # ok: python-cdk-sqs-queue-ssl-requests-only
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],  # Explicitly using the queue ARN
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a queue with SSL requirement and multiple action specifications
    queue = sqs.Queue(scope, "SecureQueue9")
    
    # ok: python-cdk-sqs-queue-ssl-requests-only
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=[
            "sqs:SendMessage",
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "sqs:GetQueueAttributes",
            "sqs:GetQueueUrl"
        ],  # Listing specific actions instead of wildcard
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a queue with SSL requirement and specific IAM roles
    queue = sqs.Queue(scope, "SecureQueue10")
    
    # First add the SSL requirement
    # ok: python-cdk-sqs-queue-ssl-requests-only
    ssl_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    # Then add role-specific permissions
    role_statement = iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=["sqs:SendMessage", "sqs:ReceiveMessage"],
        resources=[queue.queue_arn],
        principals=[iam.ArnPrincipal("arn:aws:iam::123456789012:role/MyRole")]
    )
    
    queue.add_to_resource_policy(ssl_statement)
    queue.add_to_resource_policy(role_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a queue with SSL requirement in a stack
    class SecureQueueStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            queue = sqs.Queue(self, "SecureQueue11")
            
            # ok: python-cdk-sqs-queue-ssl-requests-only
            policy_statement = iam.PolicyStatement(
                effect=iam.Effect.DENY,
                actions=["sqs:*"],
                resources=[queue.queue_arn],
                principals=[iam.AnyPrincipal()],
                conditions={
                    "Bool": {
                        "aws:SecureTransport": "false"
                    }
                }
            )
            
            queue.add_to_resource_policy(policy_statement)
            
            CfnOutput(self, "QueueUrl", value=queue.queue_url)
    
    app = cdk.App()
    stack = SecureQueueStack(app, "SecureQueueStack")
    return stack

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a queue with SSL requirement and queue URL output
    queue = sqs.Queue(scope, "SecureQueue12")
    
    # ok: python-cdk-sqs-queue-ssl-requests-only
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    
    CfnOutput(scope, "Queue12Url", value=queue.queue_url)
    CfnOutput(scope, "Queue12Arn", value=queue.queue_arn)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a queue with SSL requirement and custom KMS key
    encryption_key = cdk.aws_kms.Key(scope, "QueueEncryptionKey")
    
    queue = sqs.Queue(
        scope, 
        "SecureQueue13",
        encryption=sqs.QueueEncryption.KMS,
        encryption_master_key=encryption_key
    )
    
    # ok: python-cdk-sqs-queue-ssl-requests-only
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a queue with SSL requirement and visibility timeout
    queue = sqs.Queue(
        scope, 
        "SecureQueue14",
        visibility_timeout=Duration.seconds(300),
        retention_period=Duration.days(7)
    )
    
    # ok: python-cdk-sqs-queue-ssl-requests-only
    policy_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    queue.add_to_resource_policy(policy_statement)
    return queue

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a queue with SSL requirement and multiple policy statements
    queue = sqs.Queue(scope, "SecureQueue15")
    
    # First add the SSL requirement
    # ok: python-cdk-sqs-queue-ssl-requests-only
    ssl_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sqs:*"],
        resources=[queue.queue_arn],
        principals=[iam.AnyPrincipal()],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    
    # Add additional policy statements
    statement1 = iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=["sqs:SendMessage"],
        resources=[queue.queue_arn],
        principals=[iam.ServicePrincipal("lambda.amazonaws.com")]
    )
    
    statement2 = iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=["sqs:ReceiveMessage", "sqs:DeleteMessage"],
        resources=[queue.queue_arn],
        principals=[iam.ServicePrincipal("ec2.amazonaws.com")]
    )
    
    queue.add_to_resource_policy(ssl_statement)
    queue.add_to_resource_policy(statement1)
    queue.add_to_resource_policy(statement2)
    return queue
# {/fact}