import aws_cdk as cdk
from aws_cdk import (
    aws_lex as lex,
    aws_kms as kms,
    aws_logs as logs,
    aws_s3 as s3,
    aws_iam as iam,
    Stack
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Missing encryption for conversation logs
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn="arn:aws:logs:us-west-2:123456789012:log-group:/aws/lex/TestBot:*",
                            log_prefix="TestBot"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Audio logs without encryption
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bucket = s3.Bucket(scope, "ConversationLogBucket")
    
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Both text and audio logs without encryption
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bucket = s3.Bucket(scope, "ConversationLogBucket")
    log_group = logs.LogGroup(scope, "LexLogGroup")
    
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group.log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ],
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Using default encryption for S3 (not CMK)
    bucket = s3.Bucket(scope, "ConversationLogBucket", 
                      encryption=s3.BucketEncryption.S3_MANAGED)
    
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Using default encryption for CloudWatch Logs (not CMK)
    log_group = logs.LogGroup(scope, "LexLogGroup", 
                             retention=logs.RetentionDays.ONE_WEEK)
    
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group.log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Using AWS managed key instead of customer managed key for S3
    aws_managed_key = kms.Key.from_lookup(scope, "AWSManagedKey", alias_name="alias/aws/s3")
    bucket = s3.Bucket(scope, "ConversationLogBucket", 
                      encryption=s3.BucketEncryption.KMS,
                      encryption_key=aws_managed_key)
    
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Explicitly setting encryption to None for S3
    bucket = s3.Bucket(scope, "ConversationLogBucket", 
                      encryption=s3.BucketEncryption.UNENCRYPTED)
    
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Using imported resources without encryption
    imported_bucket = s3.Bucket.from_bucket_name(scope, "ImportedBucket", "existing-bucket")
    imported_log_group = logs.LogGroup.from_log_group_name(scope, "ImportedLogGroup", "existing-log-group")
    
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=imported_log_group.log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ],
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=imported_bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating bot alias with minimal configuration
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="MinimalAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn="arn:aws:logs:us-west-2:123456789012:log-group:/aws/lex/MinimalBot:*",
                            log_prefix="minimal"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Using a bucket with default encryption but not CMK
    bucket = s3.Bucket(scope, "ConversationLogBucket")
    
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Using multiple log settings but none with CMK
    log_group1 = logs.LogGroup(scope, "LexLogGroup1")
    log_group2 = logs.LogGroup(scope, "LexLogGroup2")
    
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group1.log_group_arn,
                            log_prefix="text-logs-1"
                        )
                    ),
                    enabled=True
                ),
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group2.log_group_arn,
                            log_prefix="text-logs-2"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Using a mix of enabled and disabled logs, but enabled ones aren't encrypted
    bucket = s3.Bucket(scope, "ConversationLogBucket")
    log_group = logs.LogGroup(scope, "LexLogGroup")
    
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group.log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ],
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=False
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Using a stack parameter for log group but no encryption
    log_group_arn = cdk.CfnParameter(scope, "LogGroupArn", 
                                    type="String",
                                    description="ARN of the CloudWatch Log Group")
    
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group_arn.value_as_string,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Using a condition to determine if logs are enabled, but no encryption
    bucket = s3.Bucket(scope, "ConversationLogBucket")
    enable_logs = cdk.CfnParameter(scope, "EnableLogs", 
                                  type="String",
                                  default="true",
                                  allowed_values=["true", "false"])
    
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=cdk.Fn.condition_equals(enable_logs.value_as_string, "true")
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Using a custom resource to create the log group but no encryption
    bucket_name = "conversation-logs-bucket"
    log_group_name = "/aws/lex/CustomBot"
    
    # ruleid: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=f"arn:aws:logs:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:log-group:{log_group_name}:*",
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ],
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=f"arn:aws:s3:::{bucket_name}",
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Using CMK for CloudWatch Logs
    cmk = kms.Key(scope, "LexLogKey", 
                 enable_key_rotation=True,
                 description="KMS key for Lex conversation logs")
    
    log_group = logs.LogGroup(scope, "LexLogGroup", 
                             encryption_key=cmk)
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group.log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Using CMK for S3 bucket
    cmk = kms.Key(scope, "LexS3Key", 
                 enable_key_rotation=True,
                 description="KMS key for Lex audio logs")
    
    bucket = s3.Bucket(scope, "ConversationLogBucket",
                      encryption=s3.BucketEncryption.KMS,
                      encryption_key=cmk)
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Using CMK for both CloudWatch Logs and S3
    log_key = kms.Key(scope, "LexLogKey", 
                     enable_key_rotation=True,
                     description="KMS key for Lex text logs")
    
    s3_key = kms.Key(scope, "LexS3Key", 
                    enable_key_rotation=True,
                    description="KMS key for Lex audio logs")
    
    log_group = logs.LogGroup(scope, "LexLogGroup", 
                             encryption_key=log_key)
    
    bucket = s3.Bucket(scope, "ConversationLogBucket",
                      encryption=s3.BucketEncryption.KMS,
                      encryption_key=s3_key)
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group.log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ],
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Using a shared CMK for both resources
    shared_key = kms.Key(scope, "SharedLexKey", 
                        enable_key_rotation=True,
                        description="Shared KMS key for Lex conversation logs")
    
    log_group = logs.LogGroup(scope, "LexLogGroup", 
                             encryption_key=shared_key)
    
    bucket = s3.Bucket(scope, "ConversationLogBucket",
                      encryption=s3.BucketEncryption.KMS,
                      encryption_key=shared_key)
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group.log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ],
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Using imported CMK for CloudWatch Logs
    imported_key = kms.Key.from_key_arn(
        scope, 
        "ImportedKey", 
        "arn:aws:kms:us-west-2:123456789012:key/abcd1234-5678-90ab-cdef-11111EXAMPLE"
    )
    
    log_group = logs.LogGroup(scope, "LexLogGroup", 
                             encryption_key=imported_key)
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group.log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Using CMK with specific key policy
    key_policy = iam.PolicyDocument(
        statements=[
            iam.PolicyStatement(
                actions=["kms:Decrypt", "kms:GenerateDataKey*"],
                resources=["*"],
                principals=[iam.ServicePrincipal("logs.amazonaws.com")]
            )
        ]
    )
    
    cmk = kms.Key(scope, "LexLogKey", 
                 enable_key_rotation=True,
                 description="KMS key for Lex conversation logs",
                 policy=key_policy)
    
    log_group = logs.LogGroup(scope, "LexLogGroup", 
                             encryption_key=cmk)
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group.log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Using CMK with alias
    cmk = kms.Key(scope, "LexLogKey", 
                 enable_key_rotation=True,
                 description="KMS key for Lex conversation logs")
    
    kms.Alias(scope, "LexLogKeyAlias",
             alias_name="alias/lex-conversation-logs",
             target_key=cmk)
    
    bucket = s3.Bucket(scope, "ConversationLogBucket",
                      encryption=s3.BucketEncryption.KMS,
                      encryption_key=cmk)
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Using CMK with multiple log settings
    cmk = kms.Key(scope, "LexLogKey", 
                 enable_key_rotation=True,
                 description="KMS key for Lex conversation logs")
    
    log_group1 = logs.LogGroup(scope, "LexLogGroup1", 
                              encryption_key=cmk)
    
    log_group2 = logs.LogGroup(scope, "LexLogGroup2", 
                              encryption_key=cmk)
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group1.log_group_arn,
                            log_prefix="text-logs-1"
                        )
                    ),
                    enabled=True
                ),
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group2.log_group_arn,
                            log_prefix="text-logs-2"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Using CMK with mix of enabled and disabled logs
    cmk = kms.Key(scope, "LexLogKey", 
                 enable_key_rotation=True,
                 description="KMS key for Lex conversation logs")
    
    s3_key = kms.Key(scope, "LexS3Key", 
                    enable_key_rotation=True,
                    description="KMS key for Lex audio logs")
    
    log_group = logs.LogGroup(scope, "LexLogGroup", 
                             encryption_key=cmk)
    
    bucket = s3.Bucket(scope, "ConversationLogBucket",
                      encryption=s3.BucketEncryption.KMS,
                      encryption_key=s3_key)
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group.log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ],
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=False
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Using a stack parameter for log group with CMK
    cmk = kms.Key(scope, "LexLogKey", 
                 enable_key_rotation=True,
                 description="KMS key for Lex conversation logs")
    
    log_group = logs.LogGroup(scope, "LexLogGroup", 
                             encryption_key=cmk)
    
    log_group_arn = cdk.CfnParameter(scope, "LogGroupArn", 
                                    type="String",
                                    default=log_group.log_group_arn,
                                    description="ARN of the CloudWatch Log Group")
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group_arn.value_as_string,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Using a condition to determine if logs are enabled with CMK
    cmk = kms.Key(scope, "LexS3Key", 
                 enable_key_rotation=True,
                 description="KMS key for Lex audio logs")
    
    bucket = s3.Bucket(scope, "ConversationLogBucket",
                      encryption=s3.BucketEncryption.KMS,
                      encryption_key=cmk)
    
    enable_logs = cdk.CfnParameter(scope, "EnableLogs", 
                                  type="String",
                                  default="true",
                                  allowed_values=["true", "false"])
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=cdk.Fn.condition_equals(enable_logs.value_as_string, "true")
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Using a custom resource to create the log group with CMK
    cmk = kms.Key(scope, "LexLogKey", 
                 enable_key_rotation=True,
                 description="KMS key for Lex conversation logs")
    
    # Create log group with encryption using custom resource
    custom_log_group = cdk.CustomResource(
        scope,
        "CustomLogGroup",
        service_token="arn:aws:lambda:us-west-2:123456789012:function:CreateLogGroup",
        properties={
            "LogGroupName": "/aws/lex/CustomBot",
            "KmsKeyId": cmk.key_id
        }
    )
    
    log_group_arn = cdk.Fn.join("", [
        "arn:aws:logs:",
        cdk.Aws.REGION,
        ":",
        cdk.Aws.ACCOUNT_ID,
        ":log-group:/aws/lex/CustomBot:*"
    ])
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Using a CMK with specific key rotation period
    cmk = kms.Key(scope, "LexLogKey", 
                 enable_key_rotation=True,
                 rotation_period=cdk.Duration.days(90),
                 description="KMS key for Lex conversation logs")
    
    log_group = logs.LogGroup(scope, "LexLogGroup", 
                             encryption_key=cmk)
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group.log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Using a CMK with multi-region capability
    cmk = kms.Key(scope, "LexLogKey", 
                 enable_key_rotation=True,
                 multi_region=True,
                 description="Multi-region KMS key for Lex conversation logs")
    
    bucket = s3.Bucket(scope, "ConversationLogBucket",
                      encryption=s3.BucketEncryption.KMS,
                      encryption_key=cmk)
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Using a CMK with tags
    cmk = kms.Key(scope, "LexLogKey", 
                 enable_key_rotation=True,
                 description="KMS key for Lex conversation logs")
    
    cdk.Tags.of(cmk).add("Purpose", "LexConversationLogs")
    cdk.Tags.of(cmk).add("Environment", "Production")
    
    log_group = logs.LogGroup(scope, "LexLogGroup", 
                             encryption_key=cmk)
    
    bucket = s3.Bucket(scope, "ConversationLogBucket",
                      encryption=s3.BucketEncryption.KMS,
                      encryption_key=cmk)
    
    # ok: python-cdk-lex-bot-alias-encrypted-conversation-logs
    bot_alias = lex.CfnBotAlias(
        scope,
        "BotAlias",
        bot_alias_name="TestAlias",
        bot_id="BOTID",
        conversation_log_settings=lex.CfnBotAlias.ConversationLogSettingsProperty(
            text_log_settings=[
                lex.CfnBotAlias.TextLogSettingProperty(
                    destination=lex.CfnBotAlias.TextLogDestinationProperty(
                        cloud_watch=lex.CfnBotAlias.CloudWatchLogGroupLogDestinationProperty(
                            cloud_watch_log_group_arn=log_group.log_group_arn,
                            log_prefix="text-logs"
                        )
                    ),
                    enabled=True
                )
            ],
            audio_log_settings=[
                lex.CfnBotAlias.AudioLogSettingProperty(
                    destination=lex.CfnBotAlias.AudioLogDestinationProperty(
                        s3_bucket=lex.CfnBotAlias.S3BucketLogDestinationProperty(
                            s3_bucket_arn=bucket.bucket_arn,
                            log_prefix="audio-logs"
                        )
                    ),
                    enabled=True
                )
            ]
        )
    )
    return bot_alias

# {/fact}

class LexBotStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs):
        super().__init__(scope, id, **kwargs)
        
        # Examples of using the functions
        bad_case_1(self, "BadCase1")
        good_case_1(self, "GoodCase1")