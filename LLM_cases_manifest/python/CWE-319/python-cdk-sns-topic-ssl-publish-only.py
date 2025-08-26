import aws_cdk as cdk
from aws_cdk import (
    aws_sns as sns,
    aws_iam as iam,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_1(scope: Construct):
    # Creating an SNS topic without SSL requirement
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    topic = sns.Topic(scope, "VulnerableTopic1")
    
    # No policy enforcing SSL is added

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_2(scope: Construct):
    # Creating an SNS topic with explicit policy that doesn't enforce SSL
    topic = sns.Topic(scope, "VulnerableTopic2")
    
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn]
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_3(scope: Construct):
    # Creating an SNS topic with policy that allows both secure and insecure transport
    topic = sns.Topic(scope, "VulnerableTopic3")
    
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": ["true", "false"]
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_4(scope: Construct):
    # Creating multiple SNS topics without SSL requirement
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    topic1 = sns.Topic(scope, "VulnerableTopic4A")
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    topic2 = sns.Topic(scope, "VulnerableTopic4B")
    
    # No policies enforcing SSL are added

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_5(scope: Construct):
    # Creating an SNS topic with explicit policy that sets SecureTransport to false
    topic = sns.Topic(scope, "VulnerableTopic5")
    
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_6(scope: Construct):
    # Creating an SNS topic with a policy that doesn't mention SecureTransport
    topic = sns.Topic(scope, "VulnerableTopic6")
    
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "StringEquals": {
                "aws:SourceAccount": "123456789012"
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_7(scope: Construct):
    # Creating an SNS topic with FIFO but no SSL requirement
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    topic = sns.Topic(
        scope, 
        "VulnerableTopic7",
        fifo=True,
        content_based_deduplication=True
    )
    
    # No policy enforcing SSL is added

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_8(scope: Construct):
    # Creating an SNS topic with custom name but no SSL requirement
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    topic = sns.Topic(
        scope, 
        "VulnerableTopic8",
        topic_name="custom-topic-name"
    )
    
    # No policy enforcing SSL is added

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_9(scope: Construct):
    # Creating an SNS topic with display name but no SSL requirement
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    topic = sns.Topic(
        scope, 
        "VulnerableTopic9",
        display_name="My Topic Display Name"
    )
    
    # No policy enforcing SSL is added

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_10(scope: Construct):
    # Creating an SNS topic with policy that has incorrect condition key name
    topic = sns.Topic(scope, "VulnerableTopic10")
    
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureConnection": "true"  # Incorrect key name
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_11(scope: Construct):
    # Creating an SNS topic with policy that has incorrect condition value type
    topic = sns.Topic(scope, "VulnerableTopic11")
    
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": 1  # Should be string "true"
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_12(scope: Construct):
    # Creating an SNS topic with policy that uses StringEquals instead of Bool
    topic = sns.Topic(scope, "VulnerableTopic12")
    
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "StringEquals": {
                "aws:SecureTransport": "true"  # Should use Bool condition
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_13(scope: Construct):
    # Creating an SNS topic with encryption but no SSL requirement
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    topic = sns.Topic(
        scope, 
        "VulnerableTopic13",
        master_key=None  # Default AWS managed key
    )
    
    # No policy enforcing SSL is added

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_14(scope: Construct):
    # Creating an SNS topic with policy that denies non-SSL but doesn't require SSL for all actions
    topic = sns.Topic(scope, "VulnerableTopic14")
    
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    deny_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sns:Subscribe"],  # Only denies Subscribe, not Publish
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    topic.add_to_resource_policy(deny_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_15(scope: Construct):
    # Creating an SNS topic with a policy that allows all actions without SSL requirement
    topic = sns.Topic(scope, "VulnerableTopic15")
    
    # ruleid: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:*"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn]
    )
    topic.add_to_resource_policy(policy_statement)

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_1(scope: Construct):
    # Creating an SNS topic with policy that requires SSL
    topic = sns.Topic(scope, "SecureTopic1")
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "true"
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_2(scope: Construct):
    # Creating an SNS topic with policy that denies non-SSL connections
    topic = sns.Topic(scope, "SecureTopic2")
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    deny_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    topic.add_to_resource_policy(deny_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_3(scope: Construct):
    # Creating an SNS topic with server-side encryption enabled
    # ok: python-cdk-sns-topic-ssl-publish-only
    topic = sns.Topic(
        scope, 
        "SecureTopic3",
        encryption=sns.TopicEncryption.KMS_MANAGED
    )
    
    # Server-side encryption automatically enforces SSL

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_4(scope: Construct):
    # Creating an SNS topic with custom KMS key for encryption
    kms_key = cdk.aws_kms.Key(scope, "TopicKey")
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    topic = sns.Topic(
        scope, 
        "SecureTopic4",
        master_key=kms_key
    )
    
    # Server-side encryption with custom key automatically enforces SSL

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_5(scope: Construct):
    # Creating multiple SNS topics with SSL requirement
    topic1 = sns.Topic(scope, "SecureTopic5A")
    topic2 = sns.Topic(scope, "SecureTopic5B")
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic1.topic_arn, topic2.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "true"
            }
        }
    )
    topic1.add_to_resource_policy(policy_statement)
    topic2.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_6(scope: Construct):
    # Creating an SNS topic with policy that requires SSL for all actions
    topic = sns.Topic(scope, "SecureTopic6")
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:*"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "true"
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_7(scope: Construct):
    # Creating a FIFO SNS topic with SSL requirement
    topic = sns.Topic(
        scope, 
        "SecureTopic7",
        fifo=True,
        content_based_deduplication=True
    )
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "true"
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_8(scope: Construct):
    # Creating an SNS topic with both encryption and explicit SSL requirement
    kms_key = cdk.aws_kms.Key(scope, "TopicKey8")
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    topic = sns.Topic(
        scope, 
        "SecureTopic8",
        master_key=kms_key
    )
    
    # Adding explicit SSL requirement (redundant but secure)
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "true"
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_9(scope: Construct):
    # Creating an SNS topic with policy that denies all actions without SSL
    topic = sns.Topic(scope, "SecureTopic9")
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    deny_statement = iam.PolicyStatement(
        effect=iam.Effect.DENY,
        actions=["sns:*"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    )
    topic.add_to_resource_policy(deny_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_10(scope: Construct):
    # Creating an SNS topic with policy that allows specific principals with SSL
    topic = sns.Topic(scope, "SecureTopic10")
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.ArnPrincipal("arn:aws:iam::123456789012:role/MyRole")],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "true"
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_11(scope: Construct):
    # Creating an SNS topic with multiple policy statements, all requiring SSL
    topic = sns.Topic(scope, "SecureTopic11")
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    publish_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "true"
            }
        }
    )
    
    subscribe_statement = iam.PolicyStatement(
        actions=["sns:Subscribe"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "true"
            }
        }
    )
    
    topic.add_to_resource_policy(publish_statement)
    topic.add_to_resource_policy(subscribe_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_12(scope: Construct):
    # Creating an SNS topic with AWS managed encryption
    # ok: python-cdk-sns-topic-ssl-publish-only
    topic = sns.Topic(
        scope, 
        "SecureTopic12",
        encryption=sns.TopicEncryption.AWS_MANAGED
    )
    
    # AWS managed encryption automatically enforces SSL

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_13(scope: Construct):
    # Creating an SNS topic with both SSL requirement and source IP restriction
    topic = sns.Topic(scope, "SecureTopic13")
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "true"
            },
            "IpAddress": {
                "aws:SourceIp": ["192.168.0.0/24", "10.0.0.0/8"]
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_14(scope: Construct):
    # Creating an SNS topic with SSL requirement and custom topic name
    topic = sns.Topic(
        scope, 
        "SecureTopic14",
        topic_name="custom-secure-topic"
    )
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": "true"
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_15(scope: Construct):
    # Creating an SNS topic with SSL requirement using a variable
    topic = sns.Topic(scope, "SecureTopic15")
    
    secure_transport_value = "true"
    
    # ok: python-cdk-sns-topic-ssl-publish-only
    policy_statement = iam.PolicyStatement(
        actions=["sns:Publish"],
        principals=[iam.AnyPrincipal()],
        resources=[topic.topic_arn],
        conditions={
            "Bool": {
                "aws:SecureTransport": secure_transport_value
            }
        }
    )
    topic.add_to_resource_policy(policy_statement)
# {/fact}