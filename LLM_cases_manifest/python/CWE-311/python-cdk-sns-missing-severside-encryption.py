import aws_cdk as cdk
from aws_cdk import (
    aws_sns as sns,
    aws_kms as kms,
    aws_sns_subscriptions as subscriptions,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy
)
from constructs import Construct

# True Positives (Vulnerable Code Examples)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating an SNS topic without server-side encryption
    # ruleid: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(scope, "MyUnsecuredTopic1")
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating an SNS topic with explicit encryption disabled
    # ruleid: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(
        scope, 
        "MyUnsecuredTopic2",
        topic_name="explicit-unencrypted-topic"
    )
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating multiple SNS topics without encryption
    # ruleid: python-cdk-sns-missing-severside-encryption
    topic1 = sns.Topic(scope, "UnsecuredTopic3A")
    # ruleid: python-cdk-sns-missing-severside-encryption
    topic2 = sns.Topic(scope, "UnsecuredTopic3B")
    return [topic1, topic2]

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a FIFO topic without encryption
    # ruleid: python-cdk-sns-missing-severside-encryption
    fifo_topic = sns.Topic(
        scope,
        "UnsecuredFifoTopic",
        topic_name="my-fifo-topic.fifo",
        fifo=True,
        content_based_deduplication=True
    )
    return fifo_topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a topic with subscription but no encryption
    # ruleid: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(scope, "UnsecuredTopicWithSubscription")
    topic.add_subscription(subscriptions.EmailSubscription("admin@example.com"))
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a topic with display name but no encryption
    # ruleid: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(
        scope,
        "UnsecuredTopicWithDisplayName",
        display_name="Customer Notifications"
    )
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a topic with custom resource policy but no encryption
    # ruleid: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(scope, "UnsecuredTopicWithPolicy")
    topic.add_to_resource_policy(
        cdk.aws_iam.PolicyStatement(
            actions=["sns:Publish"],
            principals=[cdk.aws_iam.ArnPrincipal("arn:aws:iam::123456789012:role/PublishRole")],
            resources=[topic.topic_arn]
        )
    )
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a topic from imported ARN without encryption
    # ruleid: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic.from_topic_arn(
        scope,
        "ImportedUnsecuredTopic",
        "arn:aws:sns:us-east-1:123456789012:my-topic"
    )
    # Note: This is actually a false positive since we can't modify encryption on imported topics
    # But we're including it as a bad case for demonstration
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a topic with dead letter queue but no encryption
    # ruleid: python-cdk-sns-missing-severside-encryption
    dead_letter_queue = cdk.aws_sqs.Queue(scope, "DeadLetterQueue")
    topic = sns.Topic(
        scope,
        "UnsecuredTopicWithDLQ",
        topic_name="topic-with-dlq",
        dead_letter_queue=dead_letter_queue
    )
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a topic in a stack without encryption
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            # ruleid: python-cdk-sns-missing-severside-encryption
            self.topic = sns.Topic(self, "UnsecuredStackTopic")
    
    app = cdk.App()
    stack = MyStack(app, "MyStack")
    return stack.topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a topic with conditional logic but no encryption
    env_type = "dev"
    # ruleid: python-cdk-sns-missing-severside-encryption
    if env_type == "prod":
        topic = sns.Topic(scope, "ProdTopic", topic_name="prod-notifications")
    else:
        topic = sns.Topic(scope, "DevTopic", topic_name="dev-notifications")
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a topic with removal policy but no encryption
    # ruleid: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(
        scope,
        "UnsecuredTopicWithRemovalPolicy",
        topic_name="disposable-topic"
    )
    topic.apply_removal_policy(RemovalPolicy.DESTROY)
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a topic with multiple subscriptions but no encryption
    # ruleid: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(scope, "UnsecuredMultiSubTopic")
    topic.add_subscription(subscriptions.EmailSubscription("user1@example.com"))
    topic.add_subscription(subscriptions.EmailSubscription("user2@example.com"))
    topic.add_subscription(subscriptions.SmsSubscription("+12345678901"))
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a topic with output export but no encryption
    # ruleid: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(scope, "UnsecuredExportedTopic")
    CfnOutput(
        scope,
        "TopicArn",
        value=topic.topic_arn,
        export_name="UnsecuredTopicArn"
    )
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a topic using a factory function but no encryption
    def create_topic(scope, id_prefix, count):
        topics = []
        for i in range(count):
            # ruleid: python-cdk-sns-missing-severside-encryption
            topic = sns.Topic(scope, f"{id_prefix}-{i}")
            topics.append(topic)
        return topics
    
    return create_topic(scope, "UnsecuredFactoryTopic", 3)

# True Negatives (Secure Code Examples)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating an SNS topic with server-side encryption using a new KMS key
    # ok: python-cdk-sns-missing-severside-encryption
    key = kms.Key(scope, "TopicEncryptionKey1", enable_key_rotation=True)
    topic = sns.Topic(
        scope,
        "SecuredTopic1",
        master_key=key
    )
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating an SNS topic with server-side encryption using AWS managed key
    # ok: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(
        scope,
        "SecuredTopic2",
        master_key=kms.Key.from_lookup(scope, "AliasKey", alias_name="alias/aws/sns")
    )
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating multiple SNS topics with encryption
    key = kms.Key(scope, "TopicEncryptionKey3", enable_key_rotation=True)
    # ok: python-cdk-sns-missing-severside-encryption
    topic1 = sns.Topic(scope, "SecuredTopic3A", master_key=key)
    # ok: python-cdk-sns-missing-severside-encryption
    topic2 = sns.Topic(scope, "SecuredTopic3B", master_key=key)
    return [topic1, topic2]

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a FIFO topic with encryption
    key = kms.Key(scope, "FifoTopicEncryptionKey", enable_key_rotation=True)
    # ok: python-cdk-sns-missing-severside-encryption
    fifo_topic = sns.Topic(
        scope,
        "SecuredFifoTopic",
        topic_name="my-secured-fifo-topic.fifo",
        fifo=True,
        content_based_deduplication=True,
        master_key=key
    )
    return fifo_topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a topic with subscription and encryption
    key = kms.Key(scope, "TopicEncryptionKey5", enable_key_rotation=True)
    # ok: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(scope, "SecuredTopicWithSubscription", master_key=key)
    topic.add_subscription(subscriptions.EmailSubscription("admin@example.com"))
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a topic with display name and encryption
    key = kms.Key(scope, "TopicEncryptionKey6", enable_key_rotation=True)
    # ok: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(
        scope,
        "SecuredTopicWithDisplayName",
        display_name="Secure Customer Notifications",
        master_key=key
    )
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a topic with custom resource policy and encryption
    key = kms.Key(scope, "TopicEncryptionKey7", enable_key_rotation=True)
    # ok: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(scope, "SecuredTopicWithPolicy", master_key=key)
    topic.add_to_resource_policy(
        cdk.aws_iam.PolicyStatement(
            actions=["sns:Publish"],
            principals=[cdk.aws_iam.ArnPrincipal("arn:aws:iam::123456789012:role/PublishRole")],
            resources=[topic.topic_arn]
        )
    )
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a topic with imported KMS key
    imported_key = kms.Key.from_key_arn(
        scope,
        "ImportedKey",
        "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
    )
    # ok: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(scope, "SecuredTopicWithImportedKey", master_key=imported_key)
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a topic with dead letter queue and encryption
    dead_letter_queue = cdk.aws_sqs.Queue(scope, "SecureDLQ")
    key = kms.Key(scope, "TopicEncryptionKey9", enable_key_rotation=True)
    # ok: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(
        scope,
        "SecuredTopicWithDLQ",
        topic_name="secure-topic-with-dlq",
        dead_letter_queue=dead_letter_queue,
        master_key=key
    )
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a topic in a stack with encryption
    class MySecureStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            key = kms.Key(self, "TopicEncryptionKey10", enable_key_rotation=True)
            # ok: python-cdk-sns-missing-severside-encryption
            self.topic = sns.Topic(self, "SecuredStackTopic", master_key=key)
    
    app = cdk.App()
    stack = MySecureStack(app, "MySecureStack")
    return stack.topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a topic with conditional logic and encryption
    env_type = "dev"
    key = kms.Key(scope, "TopicEncryptionKey11", enable_key_rotation=True)
    # ok: python-cdk-sns-missing-severside-encryption
    if env_type == "prod":
        topic = sns.Topic(
            scope, 
            "SecureProdTopic", 
            topic_name="secure-prod-notifications",
            master_key=key
        )
    else:
        topic = sns.Topic(
            scope, 
            "SecureDevTopic", 
            topic_name="secure-dev-notifications",
            master_key=key
        )
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a topic with removal policy and encryption
    key = kms.Key(scope, "TopicEncryptionKey12", enable_key_rotation=True)
    # ok: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(
        scope,
        "SecuredTopicWithRemovalPolicy",
        topic_name="secure-disposable-topic",
        master_key=key
    )
    topic.apply_removal_policy(RemovalPolicy.DESTROY)
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a topic with multiple subscriptions and encryption
    key = kms.Key(scope, "TopicEncryptionKey13", enable_key_rotation=True)
    # ok: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(scope, "SecuredMultiSubTopic", master_key=key)
    topic.add_subscription(subscriptions.EmailSubscription("user1@example.com"))
    topic.add_subscription(subscriptions.EmailSubscription("user2@example.com"))
    topic.add_subscription(subscriptions.SmsSubscription("+12345678901"))
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a topic with output export and encryption
    key = kms.Key(scope, "TopicEncryptionKey14", enable_key_rotation=True)
    # ok: python-cdk-sns-missing-severside-encryption
    topic = sns.Topic(scope, "SecuredExportedTopic", master_key=key)
    CfnOutput(
        scope,
        "SecureTopicArn",
        value=topic.topic_arn,
        export_name="SecuredTopicArn"
    )
    return topic

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a topic using a factory function with encryption
    def create_secure_topic(scope, id_prefix, count):
        topics = []
        key = kms.Key(scope, "TopicEncryptionKey15", enable_key_rotation=True)
        for i in range(count):
            # ok: python-cdk-sns-missing-severside-encryption
            topic = sns.Topic(scope, f"{id_prefix}-{i}", master_key=key)
            topics.append(topic)
        return topics
    
    return create_secure_topic(scope, "SecuredFactoryTopic", 3)
# {/fact}