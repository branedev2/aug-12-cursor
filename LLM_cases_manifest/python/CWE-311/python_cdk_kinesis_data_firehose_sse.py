import aws_cdk as cdk
from aws_cdk import (
    aws_kinesisfirehose as firehose,
    aws_s3 as s3,
    aws_kms as kms,
    aws_iam as iam,
    Stack
)
from constructs import Construct

# True Positives (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1():
    """Kinesis Firehose without SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2():
    """Kinesis Firehose with extended S3 destination but no SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        extended_s3_destination_configuration=firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role",
            buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                interval_in_seconds=60,
                size_in_m_bs=5
            )
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3():
    """Kinesis Firehose with Redshift destination but no SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        redshift_destination_configuration=firehose.CfnDeliveryStream.RedshiftDestinationConfigurationProperty(
            cluster_jdbcurl="jdbc:redshift://redshift-cluster.example.region.redshift.amazonaws.com:5439/database",
            copy_command=firehose.CfnDeliveryStream.CopyCommandProperty(
                data_table_name="my_table",
                copy_options="JSON 'auto'"
            ),
            password="my-password",
            username="my-username",
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role",
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn="arn:aws:s3:::my-bucket",
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            )
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4():
    """Kinesis Firehose with Elasticsearch destination but no SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        elasticsearch_destination_configuration=firehose.CfnDeliveryStream.ElasticsearchDestinationConfigurationProperty(
            index_name="my-index",
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role",
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn="arn:aws:s3:::my-bucket",
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            ),
            domain_arn="arn:aws:es:region:account-id:domain/domain-name"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5():
    """Kinesis Firehose with Splunk destination but no SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        splunk_destination_configuration=firehose.CfnDeliveryStream.SplunkDestinationConfigurationProperty(
            hec_endpoint="https://splunk-endpoint.example.com:8088",
            hec_token="splunk-token",
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn="arn:aws:s3:::my-bucket",
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            )
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6():
    """Kinesis Firehose with HttpEndpoint destination but no SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        http_endpoint_destination_configuration=firehose.CfnDeliveryStream.HttpEndpointDestinationConfigurationProperty(
            endpoint_configuration=firehose.CfnDeliveryStream.HttpEndpointConfigurationProperty(
                url="https://api.example.com/endpoint"
            ),
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn="arn:aws:s3:::my-bucket",
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            )
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7():
    """Kinesis Firehose with SSE explicitly disabled"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
        ),
        delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="NONE"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8():
    """Kinesis Firehose with empty encryption configuration"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
        ),
        delivery_stream_encryption_configuration_input=None
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9():
    """Kinesis Firehose using L2 construct without SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    role = iam.Role(stack, "FirehoseRole", assumed_by=iam.ServicePrincipal("firehose.amazonaws.com"))
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn=role.role_arn,
            buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                interval_in_seconds=60,
                size_in_m_bs=5
            )
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10():
    """Kinesis Firehose with multiple destinations but no SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        delivery_stream_type="DirectPut",
        elasticsearch_destination_configuration=firehose.CfnDeliveryStream.ElasticsearchDestinationConfigurationProperty(
            index_name="my-index",
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role",
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn=bucket.bucket_arn,
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            ),
            domain_arn="arn:aws:es:region:account-id:domain/domain-name"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11():
    """Kinesis Firehose with conditional creation but no SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    create_stream = True
    
    if create_stream:
        # ruleid: python_cdk_kinesis_data_firehose_sse
        delivery_stream = firehose.CfnDeliveryStream(
            stack,
            "MyDeliveryStream",
            s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn=bucket.bucket_arn,
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            )
        )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12():
    """Kinesis Firehose with variable configuration but no SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    s3_config = firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
        bucket_arn=bucket.bucket_arn,
        role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
    )
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        s3_destination_configuration=s3_config
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13():
    """Kinesis Firehose with dictionary configuration but no SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        **{
            "s3_destination_configuration": firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn=bucket.bucket_arn,
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            )
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14():
    """Kinesis Firehose with Amazon OpenSearch Service destination but no SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        amazon_opensearch_service_destination_configuration=firehose.CfnDeliveryStream.AmazonopensearchserviceDestinationConfigurationProperty(
            index_name="my-index",
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role",
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn="arn:aws:s3:::my-bucket",
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            ),
            domain_arn="arn:aws:es:region:account-id:domain/domain-name"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15():
    """Kinesis Firehose with MSK source but no SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    # ruleid: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        delivery_stream_type="KafkaSourceConfiguration",
        kinesis_stream_source_configuration=firehose.CfnDeliveryStream.KinesisStreamSourceConfigurationProperty(
            kinesis_stream_arn="arn:aws:kinesis:region:account-id:stream/stream-name",
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
        ),
        s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
        )
    )

# True Negatives (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1():
    """Kinesis Firehose with SSE using AWS managed key"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
        ),
        delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="AWS_OWNED_CMK"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2():
    """Kinesis Firehose with SSE using customer managed key"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    key = kms.Key(stack, "FirehoseKey", enable_key_rotation=True)
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
        ),
        delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="CUSTOMER_MANAGED_CMK",
            key_arn=key.key_arn
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3():
    """Kinesis Firehose with extended S3 destination and SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        extended_s3_destination_configuration=firehose.CfnDeliveryStream.ExtendedS3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role",
            buffering_hints=firehose.CfnDeliveryStream.BufferingHintsProperty(
                interval_in_seconds=60,
                size_in_m_bs=5
            )
        ),
        delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="AWS_OWNED_CMK"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4():
    """Kinesis Firehose with Redshift destination and SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        redshift_destination_configuration=firehose.CfnDeliveryStream.RedshiftDestinationConfigurationProperty(
            cluster_jdbcurl="jdbc:redshift://redshift-cluster.example.region.redshift.amazonaws.com:5439/database",
            copy_command=firehose.CfnDeliveryStream.CopyCommandProperty(
                data_table_name="my_table",
                copy_options="JSON 'auto'"
            ),
            password="my-password",
            username="my-username",
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role",
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn="arn:aws:s3:::my-bucket",
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            )
        ),
        delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="AWS_OWNED_CMK"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5():
    """Kinesis Firehose with Elasticsearch destination and SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        elasticsearch_destination_configuration=firehose.CfnDeliveryStream.ElasticsearchDestinationConfigurationProperty(
            index_name="my-index",
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role",
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn="arn:aws:s3:::my-bucket",
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            ),
            domain_arn="arn:aws:es:region:account-id:domain/domain-name"
        ),
        delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="CUSTOMER_MANAGED_CMK",
            key_arn="arn:aws:kms:region:account-id:key/key-id"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6():
    """Kinesis Firehose with Splunk destination and SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        splunk_destination_configuration=firehose.CfnDeliveryStream.SplunkDestinationConfigurationProperty(
            hec_endpoint="https://splunk-endpoint.example.com:8088",
            hec_token="splunk-token",
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn="arn:aws:s3:::my-bucket",
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            )
        ),
        delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="AWS_OWNED_CMK"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7():
    """Kinesis Firehose with HttpEndpoint destination and SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        http_endpoint_destination_configuration=firehose.CfnDeliveryStream.HttpEndpointDestinationConfigurationProperty(
            endpoint_configuration=firehose.CfnDeliveryStream.HttpEndpointConfigurationProperty(
                url="https://api.example.com/endpoint"
            ),
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn="arn:aws:s3:::my-bucket",
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            )
        ),
        delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="AWS_OWNED_CMK"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8():
    """Kinesis Firehose with SSE using variable configuration"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    encryption_config = firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
        key_type="AWS_OWNED_CMK"
    )
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
        ),
        delivery_stream_encryption_configuration_input=encryption_config
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9():
    """Kinesis Firehose with SSE using dictionary configuration"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        **{
            "s3_destination_configuration": firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn=bucket.bucket_arn,
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            ),
            "delivery_stream_encryption_configuration_input": firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
                key_type="AWS_OWNED_CMK"
            )
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10():
    """Kinesis Firehose with conditional creation and SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    create_stream = True
    
    if create_stream:
        # ok: python_cdk_kinesis_data_firehose_sse
        delivery_stream = firehose.CfnDeliveryStream(
            stack,
            "MyDeliveryStream",
            s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn=bucket.bucket_arn,
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            ),
            delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
                key_type="AWS_OWNED_CMK"
            )
        )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11():
    """Kinesis Firehose with Amazon OpenSearch Service destination and SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        amazon_opensearch_service_destination_configuration=firehose.CfnDeliveryStream.AmazonopensearchserviceDestinationConfigurationProperty(
            index_name="my-index",
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role",
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn="arn:aws:s3:::my-bucket",
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            ),
            domain_arn="arn:aws:es:region:account-id:domain/domain-name"
        ),
        delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="AWS_OWNED_CMK"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12():
    """Kinesis Firehose with MSK source and SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        delivery_stream_type="KafkaSourceConfiguration",
        kinesis_stream_source_configuration=firehose.CfnDeliveryStream.KinesisStreamSourceConfigurationProperty(
            kinesis_stream_arn="arn:aws:kinesis:region:account-id:stream/stream-name",
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
        ),
        s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
        ),
        delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="AWS_OWNED_CMK"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13():
    """Kinesis Firehose with multiple destinations and SSE"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        delivery_stream_type="DirectPut",
        elasticsearch_destination_configuration=firehose.CfnDeliveryStream.ElasticsearchDestinationConfigurationProperty(
            index_name="my-index",
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role",
            s3_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn=bucket.bucket_arn,
                role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
            ),
            domain_arn="arn:aws:es:region:account-id:domain/domain-name"
        ),
        delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="AWS_OWNED_CMK"
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14():
    """Kinesis Firehose with SSE using imported KMS key"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    imported_key = kms.Key.from_key_arn(stack, "ImportedKey", "arn:aws:kms:region:account-id:key/key-id")
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
        ),
        delivery_stream_encryption_configuration_input=firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="CUSTOMER_MANAGED_CMK",
            key_arn=imported_key.key_arn
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15():
    """Kinesis Firehose with SSE using dynamic configuration"""
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    bucket = s3.Bucket(stack, "DestinationBucket")
    use_customer_key = False
    
    encryption_config = None
    if use_customer_key:
        key = kms.Key(stack, "FirehoseKey", enable_key_rotation=True)
        encryption_config = firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="CUSTOMER_MANAGED_CMK",
            key_arn=key.key_arn
        )
    else:
        encryption_config = firehose.CfnDeliveryStream.DeliveryStreamEncryptionConfigurationInputProperty(
            key_type="AWS_OWNED_CMK"
        )
    
    # ok: python_cdk_kinesis_data_firehose_sse
    delivery_stream = firehose.CfnDeliveryStream(
        stack,
        "MyDeliveryStream",
        s3_destination_configuration=firehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn=bucket.bucket_arn,
            role_arn="arn:aws:iam::123456789012:role/firehose-delivery-role"
        ),
        delivery_stream_encryption_configuration_input=encryption_config
    )
# {/fact}