import aws_cdk as cdk
from aws_cdk import (
    aws_emr as emr,
    aws_ec2 as ec2,
    aws_iam as iam,
    Stack,
    CfnOutput,
    RemovalPolicy,
    Duration,
    aws_s3 as s3
)
from constructs import Construct

# True Positives (Vulnerable code - Missing log_uri)

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # EMR cluster without log_uri property
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "EMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-12345"
        ),
        name="MyEMRCluster",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.2.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # EMR cluster with empty configurations but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterNoLogs",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-abcdef"
        ),
        name="DataProcessingCluster",
        applications=[
            emr.CfnCluster.ApplicationProperty(name="Spark"),
            emr.CfnCluster.ApplicationProperty(name="Hive")
        ],
        configurations=[],
        release_label="emr-6.3.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # EMR cluster with tags but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "TaggedEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=3,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-123456"
        ),
        name="ProductionEMRCluster",
        tags=[
            cdk.CfnTag(key="Environment", value="Production"),
            cdk.CfnTag(key="Department", value="DataScience")
        ],
        release_label="emr-6.4.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # EMR cluster with bootstrap actions but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "BootstrapEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-abcdef"
        ),
        bootstrap_actions=[
            emr.CfnCluster.BootstrapActionConfigProperty(
                name="InstallDependencies",
                script_bootstrap_action=emr.CfnCluster.ScriptBootstrapActionConfigProperty(
                    path="s3://mybucket/bootstrap-script.sh"
                )
            )
        ],
        name="BootstrapCluster",
        release_label="emr-6.2.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # EMR cluster with applications but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "ApplicationsEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=4,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-123abc"
        ),
        applications=[
            emr.CfnCluster.ApplicationProperty(name="Hadoop"),
            emr.CfnCluster.ApplicationProperty(name="Spark"),
            emr.CfnCluster.ApplicationProperty(name="Hive"),
            emr.CfnCluster.ApplicationProperty(name="Pig")
        ],
        name="BigDataCluster",
        release_label="emr-6.5.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # EMR cluster with configurations but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "ConfiguredEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-xyz123"
        ),
        configurations=[
            emr.CfnCluster.ConfigurationProperty(
                classification="spark-defaults",
                configuration_properties={
                    "spark.executor.memory": "4g",
                    "spark.driver.memory": "2g"
                }
            )
        ],
        name="SparkCluster",
        release_label="emr-6.3.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # EMR cluster with steps but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "StepsEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-123456"
        ),
        steps=[
            emr.CfnCluster.StepConfigProperty(
                name="ProcessData",
                action_on_failure="CONTINUE",
                hadoop_jar_step=emr.CfnCluster.HadoopJarStepConfigProperty(
                    jar="command-runner.jar",
                    args=["spark-submit", "--class", "com.example.Main", "s3://mybucket/app.jar"]
                )
            )
        ],
        name="DataProcessingCluster",
        release_label="emr-6.4.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # EMR cluster with auto-termination but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "AutoTerminateEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-abcdef",
            keep_job_flow_alive_when_no_steps=False
        ),
        name="TemporaryCluster",
        release_label="emr-6.2.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # EMR cluster with security configuration but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "SecureEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=3,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-123abc"
        ),
        security_configuration="MySecurityConfig",
        name="SecureDataCluster",
        release_label="emr-6.5.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # EMR cluster with visible_to_all_users but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "VisibleEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-abcdef"
        ),
        visible_to_all_users=True,
        name="SharedCluster",
        release_label="emr-6.3.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # EMR cluster with custom AMI but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "CustomAMIEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-123456",
            custom_ami_id="ami-12345678"
        ),
        name="CustomImageCluster",
        release_label="emr-6.4.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # EMR cluster with scaling rules but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "ScalingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.xlarge",
                auto_scaling_policy=emr.CfnCluster.AutoScalingPolicyProperty(
                    constraints=emr.CfnCluster.ScalingConstraintsProperty(
                        min_capacity=2,
                        max_capacity=10
                    ),
                    rules=[
                        emr.CfnCluster.ScalingRuleProperty(
                            name="ScaleUpRule",
                            action=emr.CfnCluster.ScalingActionProperty(
                                simple_scaling_policy_configuration=emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                                    scaling_adjustment=1,
                                    adjustment_type="CHANGE_IN_CAPACITY",
                                    cool_down=300
                                )
                            ),
                            trigger=emr.CfnCluster.ScalingTriggerProperty(
                                cloud_watch_alarm_definition=emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                                    comparison_operator="GREATER_THAN",
                                    evaluation_periods=1,
                                    metric_name="YARNMemoryAvailablePercentage",
                                    namespace="AWS/ElasticMapReduce",
                                    period=300,
                                    threshold=15,
                                    statistic="AVERAGE"
                                )
                            )
                        )
                    ]
                )
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-abcdef"
        ),
        name="ScalableCluster",
        release_label="emr-6.5.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # EMR cluster with kerberos configuration but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "KerberosEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=3,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-123abc"
        ),
        kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
            realm="EC2.INTERNAL",
            kdc_admin_password="SecretPassword123",
            cross_realm_trust_principal_password="AnotherSecret456"
        ),
        name="SecureKerberosCluster",
        release_label="emr-6.3.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # EMR cluster with service role specified but no log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    service_role = iam.Role(
        scope, 
        "EMRServiceRole",
        assumed_by=iam.ServicePrincipal("elasticmapreduce.amazonaws.com"),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonEMRServicePolicy")
        ]
    )
    
    job_flow_role = iam.Role(
        scope, 
        "EMRJobFlowRole",
        assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonElasticMapReduceforEC2Role")
        ]
    )
    
    cluster = emr.CfnCluster(
        scope,
        "CustomRoleEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-123456"
        ),
        name="CustomRoleCluster",
        service_role=service_role.role_name,
        job_flow_role=job_flow_role.role_name,
        release_label="emr-6.4.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # EMR cluster with null log_uri
    # ruleid: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "NullLogURIEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-abcdef"
        ),
        log_uri=None,
        name="NullLogCluster",
        release_label="emr-6.2.0"
    )
    return cluster

# True Negatives (Secure code - With log_uri)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # EMR cluster with log_uri property
    # ok: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "LoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-12345"
        ),
        name="MyEMRCluster",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.2.0",
        log_uri="s3://my-emr-logs-bucket/logs/"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # EMR cluster with log_uri and bucket created in the same stack
    # ok: python-cdk-emrs-3-access-logging
    log_bucket = s3.Bucket(
        scope,
        "EMRLogBucket",
        removal_policy=RemovalPolicy.RETAIN,
        lifecycle_rules=[
            s3.LifecycleRule(
                expiration=Duration.days(365),
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.INTELLIGENT_TIERING,
                        transition_after=Duration.days(30)
                    )
                ]
            )
        ]
    )
    
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithBucket",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-abcdef"
        ),
        name="DataProcessingCluster",
        applications=[
            emr.CfnCluster.ApplicationProperty(name="Spark"),
            emr.CfnCluster.ApplicationProperty(name="Hive")
        ],
        log_uri=f"s3://{log_bucket.bucket_name}/emr-logs/",
        release_label="emr-6.3.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # EMR cluster with log_uri and tags
    # ok: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "TaggedLoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=3,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-123456"
        ),
        name="ProductionEMRCluster",
        tags=[
            cdk.CfnTag(key="Environment", value="Production"),
            cdk.CfnTag(key="Department", value="DataScience")
        ],
        log_uri="s3://production-logs/emr/",
        release_label="emr-6.4.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # EMR cluster with log_uri and bootstrap actions
    # ok: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "BootstrapLoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-abcdef"
        ),
        bootstrap_actions=[
            emr.CfnCluster.BootstrapActionConfigProperty(
                name="InstallDependencies",
                script_bootstrap_action=emr.CfnCluster.ScriptBootstrapActionConfigProperty(
                    path="s3://mybucket/bootstrap-script.sh"
                )
            )
        ],
        name="BootstrapCluster",
        log_uri="s3://emr-logs-bucket/bootstrap-cluster/",
        release_label="emr-6.2.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # EMR cluster with log_uri and applications
    # ok: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "ApplicationsLoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=4,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-123abc"
        ),
        applications=[
            emr.CfnCluster.ApplicationProperty(name="Hadoop"),
            emr.CfnCluster.ApplicationProperty(name="Spark"),
            emr.CfnCluster.ApplicationProperty(name="Hive"),
            emr.CfnCluster.ApplicationProperty(name="Pig")
        ],
        name="BigDataCluster",
        log_uri="s3://analytics-logs/emr-big-data/",
        release_label="emr-6.5.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # EMR cluster with log_uri and configurations
    # ok: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "ConfiguredLoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-xyz123"
        ),
        configurations=[
            emr.CfnCluster.ConfigurationProperty(
                classification="spark-defaults",
                configuration_properties={
                    "spark.executor.memory": "4g",
                    "spark.driver.memory": "2g"
                }
            )
        ],
        name="SparkCluster",
        log_uri="s3://spark-cluster-logs/emr/",
        release_label="emr-6.3.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # EMR cluster with log_uri and steps
    # ok: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "StepsLoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-123456"
        ),
        steps=[
            emr.CfnCluster.StepConfigProperty(
                name="ProcessData",
                action_on_failure="CONTINUE",
                hadoop_jar_step=emr.CfnCluster.HadoopJarStepConfigProperty(
                    jar="command-runner.jar",
                    args=["spark-submit", "--class", "com.example.Main", "s3://mybucket/app.jar"]
                )
            )
        ],
        name="DataProcessingCluster",
        log_uri="s3://data-processing-logs/emr/",
        release_label="emr-6.4.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # EMR cluster with log_uri and auto-termination
    # ok: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "AutoTerminateLoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-abcdef",
            keep_job_flow_alive_when_no_steps=False
        ),
        name="TemporaryCluster",
        log_uri="s3://temp-cluster-logs/emr/",
        release_label="emr-6.2.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # EMR cluster with log_uri and security configuration
    # ok: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "SecureLoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=3,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-123abc"
        ),
        security_configuration="MySecurityConfig",
        name="SecureDataCluster",
        log_uri="s3://secure-cluster-logs/emr/",
        release_label="emr-6.5.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # EMR cluster with log_uri and visible_to_all_users
    # ok: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "VisibleLoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-abcdef"
        ),
        visible_to_all_users=True,
        name="SharedCluster",
        log_uri="s3://shared-cluster-logs/emr/",
        release_label="emr-6.3.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # EMR cluster with log_uri and custom AMI
    # ok: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "CustomAMILoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-123456",
            custom_ami_id="ami-12345678"
        ),
        name="CustomImageCluster",
        log_uri="s3://custom-ami-logs/emr/",
        release_label="emr-6.4.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # EMR cluster with log_uri and scaling rules
    # ok: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "ScalingLoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.xlarge",
                auto_scaling_policy=emr.CfnCluster.AutoScalingPolicyProperty(
                    constraints=emr.CfnCluster.ScalingConstraintsProperty(
                        min_capacity=2,
                        max_capacity=10
                    ),
                    rules=[
                        emr.CfnCluster.ScalingRuleProperty(
                            name="ScaleUpRule",
                            action=emr.CfnCluster.ScalingActionProperty(
                                simple_scaling_policy_configuration=emr.CfnCluster.SimpleScalingPolicyConfigurationProperty(
                                    scaling_adjustment=1,
                                    adjustment_type="CHANGE_IN_CAPACITY",
                                    cool_down=300
                                )
                            ),
                            trigger=emr.CfnCluster.ScalingTriggerProperty(
                                cloud_watch_alarm_definition=emr.CfnCluster.CloudWatchAlarmDefinitionProperty(
                                    comparison_operator="GREATER_THAN",
                                    evaluation_periods=1,
                                    metric_name="YARNMemoryAvailablePercentage",
                                    namespace="AWS/ElasticMapReduce",
                                    period=300,
                                    threshold=15,
                                    statistic="AVERAGE"
                                )
                            )
                        )
                    ]
                )
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-abcdef"
        ),
        name="ScalableCluster",
        log_uri="s3://scalable-cluster-logs/emr/",
        release_label="emr-6.5.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # EMR cluster with log_uri and kerberos configuration
    # ok: python-cdk-emrs-3-access-logging
    cluster = emr.CfnCluster(
        scope,
        "KerberosLoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=3,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-123abc"
        ),
        kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
            realm="EC2.INTERNAL",
            kdc_admin_password="SecretPassword123",
            cross_realm_trust_principal_password="AnotherSecret456"
        ),
        name="SecureKerberosCluster",
        log_uri="s3://kerberos-cluster-logs/emr/",
        release_label="emr-6.3.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # EMR cluster with log_uri and custom service roles
    # ok: python-cdk-emrs-3-access-logging
    service_role = iam.Role(
        scope, 
        "EMRServiceRoleWithLogs",
        assumed_by=iam.ServicePrincipal("elasticmapreduce.amazonaws.com"),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonEMRServicePolicy")
        ]
    )
    
    job_flow_role = iam.Role(
        scope, 
        "EMRJobFlowRoleWithLogs",
        assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AmazonElasticMapReduceforEC2Role")
        ]
    )
    
    cluster = emr.CfnCluster(
        scope,
        "CustomRoleLoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.xlarge"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.xlarge"
            ),
            ec2_subnet_id="subnet-123456"
        ),
        name="CustomRoleCluster",
        service_role=service_role.role_name,
        job_flow_role=job_flow_role.role_name,
        log_uri="s3://custom-role-logs/emr/",
        release_label="emr-6.4.0"
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # EMR cluster with log_uri using variable
    # ok: python-cdk-emrs-3-access-logging
    log_bucket_name = "my-centralized-logging-bucket"
    log_path = f"s3://{log_bucket_name}/emr-logs/cluster-{cdk.Aws.ACCOUNT_ID}/"
    
    cluster = emr.CfnCluster(
        scope,
        "DynamicLoggingEMRCluster",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            core_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=2,
                instance_type="m5.large"
            ),
            master_instance_group=emr.CfnCluster.InstanceGroupConfigProperty(
                instance_count=1,
                instance_type="m5.large"
            ),
            ec2_subnet_id="subnet-abcdef"
        ),
        name="DynamicLogCluster",
        log_uri=log_path,
        release_label="emr-6.2.0"
    )
    return cluster
# {/fact}