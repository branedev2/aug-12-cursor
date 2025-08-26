import aws_cdk as cdk
from aws_cdk import (
    aws_kinesis as kinesis,
    Stack,
    RemovalPolicy,
    Duration,
    aws_kms as kms
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1():
    # Creating a Kinesis stream without encryption
    # ruleid: python_cdk_kinesis_disabled_sse
    stream = kinesis.Stream(
        scope=Stack(None, "MyStack"),
        id="MyUnencryptedStream",
        stream_name="unencrypted-stream"
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2():
    # Creating a Kinesis stream with encryption explicitly disabled
    # ruleid: python_cdk_kinesis_disabled_sse
    stream = kinesis.Stream(
        scope=Stack(None, "MyStack"),
        id="MyUnencryptedStream",
        stream_name="explicitly-unencrypted-stream",
        encryption=kinesis.StreamEncryption.UNENCRYPTED
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3():
    # Creating a Kinesis stream with minimal configuration
    # ruleid: python_cdk_kinesis_disabled_sse
    class KinesisStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            kinesis.Stream(self, "SimpleStream")
    
    app = cdk.App()
    KinesisStack(app, "KinesisStack")
    return app

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4():
    # Creating a Kinesis stream with other configurations but no encryption
    # ruleid: python_cdk_kinesis_disabled_sse
    stream = kinesis.Stream(
        scope=Stack(None, "MyStack"),
        id="ConfiguredButUnencryptedStream",
        stream_name="configured-unencrypted-stream",
        shard_count=3,
        retention_period=Duration.days(7),
        stream_mode=kinesis.StreamMode.PROVISIONED
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5():
    # Creating multiple Kinesis streams, all unencrypted
    # ruleid: python_cdk_kinesis_disabled_sse
    class MultiKinesisStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            kinesis.Stream(self, "Stream1", stream_name="stream-1")
            kinesis.Stream(self, "Stream2", stream_name="stream-2")
            
    app = cdk.App()
    MultiKinesisStack(app, "MultiKinesisStack")
    return app

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6():
    # Creating a Kinesis stream with removal policy but no encryption
    # ruleid: python_cdk_kinesis_disabled_sse
    stream = kinesis.Stream(
        scope=Stack(None, "MyStack"),
        id="UnencryptedStreamWithRemovalPolicy",
        stream_name="unencrypted-with-policy",
        removal_policy=RemovalPolicy.DESTROY
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7():
    # Creating a Kinesis stream in a function that returns it
    # ruleid: python_cdk_kinesis_disabled_sse
    def create_stream(stack):
        return kinesis.Stream(
            scope=stack,
            id="FunctionCreatedStream",
            stream_name="function-created-stream"
        )
    
    stack = Stack(None, "MyStack")
    stream = create_stream(stack)
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8():
    # Creating a Kinesis stream with variable configuration
    # ruleid: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    stream_id = "DynamicStream"
    stream_name = "dynamic-stream"
    
    stream = kinesis.Stream(
        scope=stack,
        id=stream_id,
        stream_name=stream_name
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9():
    # Creating a Kinesis stream with conditional logic but no encryption
    # ruleid: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    is_production = True
    
    if is_production:
        shard_count = 5
        retention_days = 7
    else:
        shard_count = 1
        retention_days = 1
    
    stream = kinesis.Stream(
        scope=stack,
        id="ConditionalStream",
        stream_name="conditional-stream",
        shard_count=shard_count,
        retention_period=Duration.days(retention_days)
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10():
    # Creating a Kinesis stream with on-demand capacity but no encryption
    # ruleid: python_cdk_kinesis_disabled_sse
    stream = kinesis.Stream(
        scope=Stack(None, "MyStack"),
        id="OnDemandStream",
        stream_name="on-demand-stream",
        stream_mode=kinesis.StreamMode.ON_DEMAND
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11():
    # Creating a Kinesis stream with a dictionary of props
    # ruleid: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    props = {
        "id": "DictPropsStream",
        "stream_name": "dict-props-stream",
        "shard_count": 2
    }
    
    stream = kinesis.Stream(
        scope=stack,
        **props
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12():
    # Creating a Kinesis stream in a loop
    # ruleid: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    streams = []
    
    for i in range(3):
        stream = kinesis.Stream(
            scope=stack,
            id=f"LoopStream{i}",
            stream_name=f"loop-stream-{i}"
        )
        streams.append(stream)
    
    return streams

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13():
    # Creating a Kinesis stream with tags but no encryption
    # ruleid: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    stream = kinesis.Stream(
        scope=stack,
        id="TaggedStream",
        stream_name="tagged-stream"
    )
    
    cdk.Tags.of(stream).add("Environment", "Production")
    cdk.Tags.of(stream).add("Department", "Analytics")
    
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14():
    # Creating a Kinesis stream with a method chain
    # ruleid: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    stream = kinesis.Stream(
        scope=stack,
        id="ChainedStream",
        stream_name="chained-stream"
    )
    
    stream.node.add_dependency(cdk.CfnResource(stack, "SomeDependency", type="Custom::Dependency"))
    
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15():
    # Creating a Kinesis stream with a try-except block
    # ruleid: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    try:
        stream = kinesis.Stream(
            scope=stack,
            id="TryExceptStream",
            stream_name="try-except-stream"
        )
        return stream
    except Exception as e:
        print(f"Error creating stream: {e}")
        return None

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1():
    # Creating a Kinesis stream with KMS encryption using AWS managed key
    # ok: python_cdk_kinesis_disabled_sse
    stream = kinesis.Stream(
        scope=Stack(None, "MyStack"),
        id="MyEncryptedStream",
        stream_name="encrypted-stream",
        encryption=kinesis.StreamEncryption.KMS
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2():
    # Creating a Kinesis stream with KMS encryption using customer managed key
    # ok: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    key = kms.Key(stack, "MyKey", enable_key_rotation=True)
    
    stream = kinesis.Stream(
        scope=stack,
        id="CustomerKeyEncryptedStream",
        stream_name="customer-key-encrypted-stream",
        encryption=kinesis.StreamEncryption.KMS,
        encryption_key=key
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3():
    # Creating a Kinesis stream with KMS encryption in a stack class
    # ok: python_cdk_kinesis_disabled_sse
    class SecureKinesisStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            kinesis.Stream(
                self, 
                "SecureStream",
                stream_name="secure-stream-in-stack",
                encryption=kinesis.StreamEncryption.KMS
            )
    
    app = cdk.App()
    SecureKinesisStack(app, "SecureKinesisStack")
    return app

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4():
    # Creating a Kinesis stream with KMS encryption and other configurations
    # ok: python_cdk_kinesis_disabled_sse
    stream = kinesis.Stream(
        scope=Stack(None, "MyStack"),
        id="ConfiguredEncryptedStream",
        stream_name="configured-encrypted-stream",
        shard_count=3,
        retention_period=Duration.days(7),
        stream_mode=kinesis.StreamMode.PROVISIONED,
        encryption=kinesis.StreamEncryption.KMS
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5():
    # Creating multiple Kinesis streams, all encrypted
    # ok: python_cdk_kinesis_disabled_sse
    class MultiSecureKinesisStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            kinesis.Stream(
                self, 
                "Stream1", 
                stream_name="secure-stream-1",
                encryption=kinesis.StreamEncryption.KMS
            )
            
            kinesis.Stream(
                self, 
                "Stream2", 
                stream_name="secure-stream-2",
                encryption=kinesis.StreamEncryption.KMS
            )
            
    app = cdk.App()
    MultiSecureKinesisStack(app, "MultiSecureKinesisStack")
    return app

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6():
    # Creating a Kinesis stream with KMS encryption and removal policy
    # ok: python_cdk_kinesis_disabled_sse
    stream = kinesis.Stream(
        scope=Stack(None, "MyStack"),
        id="EncryptedStreamWithRemovalPolicy",
        stream_name="encrypted-with-policy",
        encryption=kinesis.StreamEncryption.KMS,
        removal_policy=RemovalPolicy.DESTROY
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7():
    # Creating a Kinesis stream with KMS encryption in a function that returns it
    # ok: python_cdk_kinesis_disabled_sse
    def create_secure_stream(stack):
        return kinesis.Stream(
            scope=stack,
            id="FunctionCreatedSecureStream",
            stream_name="function-created-secure-stream",
            encryption=kinesis.StreamEncryption.KMS
        )
    
    stack = Stack(None, "MyStack")
    stream = create_secure_stream(stack)
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8():
    # Creating a Kinesis stream with KMS encryption using variable configuration
    # ok: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    stream_id = "DynamicSecureStream"
    stream_name = "dynamic-secure-stream"
    
    stream = kinesis.Stream(
        scope=stack,
        id=stream_id,
        stream_name=stream_name,
        encryption=kinesis.StreamEncryption.KMS
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9():
    # Creating a Kinesis stream with KMS encryption using conditional logic
    # ok: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    is_production = True
    
    if is_production:
        shard_count = 5
        retention_days = 7
        key = kms.Key(stack, "ProductionKey", enable_key_rotation=True)
    else:
        shard_count = 1
        retention_days = 1
        key = None
    
    stream = kinesis.Stream(
        scope=stack,
        id="ConditionalSecureStream",
        stream_name="conditional-secure-stream",
        shard_count=shard_count,
        retention_period=Duration.days(retention_days),
        encryption=kinesis.StreamEncryption.KMS,
        encryption_key=key
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10():
    # Creating a Kinesis stream with KMS encryption and on-demand capacity
    # ok: python_cdk_kinesis_disabled_sse
    stream = kinesis.Stream(
        scope=Stack(None, "MyStack"),
        id="SecureOnDemandStream",
        stream_name="secure-on-demand-stream",
        stream_mode=kinesis.StreamMode.ON_DEMAND,
        encryption=kinesis.StreamEncryption.KMS
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11():
    # Creating a Kinesis stream with KMS encryption using a dictionary of props
    # ok: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    props = {
        "id": "SecureDictPropsStream",
        "stream_name": "secure-dict-props-stream",
        "shard_count": 2,
        "encryption": kinesis.StreamEncryption.KMS
    }
    
    stream = kinesis.Stream(
        scope=stack,
        **props
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12():
    # Creating Kinesis streams with KMS encryption in a loop
    # ok: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    streams = []
    
    for i in range(3):
        stream = kinesis.Stream(
            scope=stack,
            id=f"SecureLoopStream{i}",
            stream_name=f"secure-loop-stream-{i}",
            encryption=kinesis.StreamEncryption.KMS
        )
        streams.append(stream)
    
    return streams

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13():
    # Creating a Kinesis stream with KMS encryption and tags
    # ok: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    stream = kinesis.Stream(
        scope=stack,
        id="SecureTaggedStream",
        stream_name="secure-tagged-stream",
        encryption=kinesis.StreamEncryption.KMS
    )
    
    cdk.Tags.of(stream).add("Environment", "Production")
    cdk.Tags.of(stream).add("Department", "Analytics")
    
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14():
    # Creating a Kinesis stream with KMS encryption using imported key
    # ok: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    imported_key = kms.Key.from_key_arn(
        stack, 
        "ImportedKey", 
        "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    )
    
    stream = kinesis.Stream(
        scope=stack,
        id="ImportedKeyStream",
        stream_name="imported-key-stream",
        encryption=kinesis.StreamEncryption.KMS,
        encryption_key=imported_key
    )
    return stream

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15():
    # Creating a Kinesis stream with KMS encryption in a try-except block
    # ok: python_cdk_kinesis_disabled_sse
    stack = Stack(None, "MyStack")
    try:
        stream = kinesis.Stream(
            scope=stack,
            id="SecureTryExceptStream",
            stream_name="secure-try-except-stream",
            encryption=kinesis.StreamEncryption.KMS
        )
        return stream
    except Exception as e:
        print(f"Error creating stream: {e}")
        return None
# {/fact}