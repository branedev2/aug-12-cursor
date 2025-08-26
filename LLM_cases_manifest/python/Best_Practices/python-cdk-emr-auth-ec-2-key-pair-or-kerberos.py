import aws_cdk as cdk
from aws_cdk import (
    aws_emr as emr,
    Stack,
    aws_ec2 as ec2,
    aws_iam as iam
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # EMR cluster with no authentication mechanism
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterNoAuth",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterWithNoAuth",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-5.33.0",
        applications=[
            emr.CfnCluster.ApplicationProperty(name="Spark"),
            emr.CfnCluster.ApplicationProperty(name="Hive")
        ]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # EMR cluster with empty configurations
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterEmptyConfig",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            ec2_key_name=""  # Empty key name
        ),
        name="EMRClusterWithEmptyConfig",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.2.0",
        applications=[
            emr.CfnCluster.ApplicationProperty(name="Spark")
        ]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # EMR cluster with configurations but no auth
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithConfigs",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        configurations=[
            emr.CfnCluster.ConfigurationProperty(
                classification="spark-defaults",
                configuration_properties={
                    "spark.executor.memory": "2G"
                }
            )
        ],
        name="EMRClusterWithConfigs",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.3.0"
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # EMR cluster with null key name
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    key_name = None
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterNullKey",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            ec2_key_name=key_name
        ),
        name="EMRClusterWithNullKey",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.4.0"
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # EMR cluster with commented out key name
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterCommentedKey",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            # ec2_key_name="my-key-pair"
        ),
        name="EMRClusterWithCommentedKey",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.5.0"
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # EMR cluster with old version and no Kerberos
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterOldVersion",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterOldVersion",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-5.20.0"  # Version supports Kerberos but not configured
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # EMR cluster with newer version but no auth
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterNewerVersion",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterNewerVersion",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.0.0"  # Newer version but no auth
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # EMR cluster with incomplete Kerberos config
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterIncompleteKerberos",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterIncompleteKerberos",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.1.0",
        kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
            # Missing required attributes
        )
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # EMR cluster with empty Kerberos realm
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterEmptyKerberosRealm",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterEmptyKerberosRealm",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.2.0",
        kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
            realm=""  # Empty realm
        )
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # EMR cluster with step but no auth
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithSteps",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterWithSteps",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.3.0",
        steps=[
            emr.CfnCluster.StepConfigProperty(
                name="SparkStep",
                action_on_failure="CONTINUE",
                hadoop_jar_step=emr.CfnCluster.HadoopJarStepConfigProperty(
                    jar="command-runner.jar",
                    args=["spark-submit", "--class", "org.example.Main", "s3://bucket/app.jar"]
                )
            )
        ]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # EMR cluster with bootstrap actions but no auth
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithBootstrap",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterWithBootstrap",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.4.0",
        bootstrap_actions=[
            emr.CfnCluster.BootstrapActionConfigProperty(
                name="InstallPackages",
                script_bootstrap_action=emr.CfnCluster.ScriptBootstrapActionConfigProperty(
                    path="s3://bucket/bootstrap.sh",
                    args=["arg1", "arg2"]
                )
            )
        ]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # EMR cluster with auto-termination but no auth
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithAutoTermination",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            keep_job_flow_alive_when_no_steps=False
        ),
        name="EMRClusterWithAutoTermination",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.5.0"
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # EMR cluster with tags but no auth
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithTags",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterWithTags",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.0.0",
        tags=[
            cdk.CfnTag(key="Environment", value="Development"),
            cdk.CfnTag(key="Project", value="DataAnalytics")
        ]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # EMR cluster with applications but no auth
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithApps",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterWithApps",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.1.0",
        applications=[
            emr.CfnCluster.ApplicationProperty(name="Spark"),
            emr.CfnCluster.ApplicationProperty(name="Hive"),
            emr.CfnCluster.ApplicationProperty(name="Hadoop"),
            emr.CfnCluster.ApplicationProperty(name="Pig")
        ]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # EMR cluster with log URI but no auth
    # ruleid: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithLogURI",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterWithLogURI",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.2.0",
        log_uri="s3://my-bucket/logs/"
    )

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # EMR cluster with EC2 key pair authentication
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKeyPair",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            ec2_key_name="my-key-pair"  # Proper EC2 key pair
        ),
        name="EMRClusterWithKeyPair",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.0.0"
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # EMR cluster with Kerberos authentication
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKerberos",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterWithKerberos",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.0.0",
        kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
            realm="EC2.INTERNAL",
            kdc_admin_password="SecurePassword123"
        )
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # EMR cluster with both EC2 key pair and Kerberos
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithBothAuth",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            ec2_key_name="my-key-pair"
        ),
        name="EMRClusterWithBothAuth",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.1.0",
        kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
            realm="EC2.INTERNAL",
            kdc_admin_password="SecurePassword123"
        )
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # EMR cluster with EC2 key pair from parameter
    key_name = "my-production-key"
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKeyFromParam",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            ec2_key_name=key_name
        ),
        name="EMRClusterWithKeyFromParam",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.2.0"
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # EMR cluster with Kerberos and advanced configuration
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithAdvancedKerberos",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterWithAdvancedKerberos",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.3.0",
        kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
            realm="EC2.INTERNAL",
            kdc_admin_password="SecurePassword123",
            ad_domain_join_user="admin",
            ad_domain_join_password="SecureDomainPassword"
        )
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # EMR cluster with EC2 key pair and steps
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKeyAndSteps",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            ec2_key_name="my-key-pair"
        ),
        name="EMRClusterWithKeyAndSteps",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.4.0",
        steps=[
            emr.CfnCluster.StepConfigProperty(
                name="SparkStep",
                action_on_failure="CONTINUE",
                hadoop_jar_step=emr.CfnCluster.HadoopJarStepConfigProperty(
                    jar="command-runner.jar",
                    args=["spark-submit", "--class", "org.example.Main", "s3://bucket/app.jar"]
                )
            )
        ]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # EMR cluster with Kerberos and bootstrap actions
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKerberosAndBootstrap",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterWithKerberosAndBootstrap",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.5.0",
        kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
            realm="EC2.INTERNAL",
            kdc_admin_password="SecurePassword123"
        ),
        bootstrap_actions=[
            emr.CfnCluster.BootstrapActionConfigProperty(
                name="InstallPackages",
                script_bootstrap_action=emr.CfnCluster.ScriptBootstrapActionConfigProperty(
                    path="s3://bucket/bootstrap.sh",
                    args=["arg1", "arg2"]
                )
            )
        ]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # EMR cluster with EC2 key pair and configurations
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKeyAndConfigs",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            ec2_key_name="my-key-pair"
        ),
        name="EMRClusterWithKeyAndConfigs",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.0.0",
        configurations=[
            emr.CfnCluster.ConfigurationProperty(
                classification="spark-defaults",
                configuration_properties={
                    "spark.executor.memory": "2G"
                }
            )
        ]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # EMR cluster with Kerberos and auto-termination
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKerberosAndAutoTermination",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            keep_job_flow_alive_when_no_steps=False
        ),
        name="EMRClusterWithKerberosAndAutoTermination",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.1.0",
        kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
            realm="EC2.INTERNAL",
            kdc_admin_password="SecurePassword123"
        )
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # EMR cluster with EC2 key pair and tags
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKeyAndTags",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            ec2_key_name="my-key-pair"
        ),
        name="EMRClusterWithKeyAndTags",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.2.0",
        tags=[
            cdk.CfnTag(key="Environment", value="Production"),
            cdk.CfnTag(key="Project", value="DataAnalytics")
        ]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # EMR cluster with Kerberos and applications
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKerberosAndApps",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterWithKerberosAndApps",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.3.0",
        kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
            realm="EC2.INTERNAL",
            kdc_admin_password="SecurePassword123"
        ),
        applications=[
            emr.CfnCluster.ApplicationProperty(name="Spark"),
            emr.CfnCluster.ApplicationProperty(name="Hive"),
            emr.CfnCluster.ApplicationProperty(name="Hadoop"),
            emr.CfnCluster.ApplicationProperty(name="Pig")
        ]
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # EMR cluster with EC2 key pair and log URI
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKeyAndLogURI",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            ec2_key_name="my-key-pair"
        ),
        name="EMRClusterWithKeyAndLogURI",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.4.0",
        log_uri="s3://my-bucket/logs/"
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # EMR cluster with Kerberos and custom security configuration
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKerberosAndSecurity",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterWithKerberosAndSecurity",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.5.0",
        kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
            realm="EC2.INTERNAL",
            kdc_admin_password="SecurePassword123"
        ),
        security_configuration="MySecurityConfig"
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # EMR cluster with EC2 key pair from SSM parameter
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    key_name = cdk.Fn.import_value("EMRKeyPairName")
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKeyFromSSM",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large",
            ec2_key_name=key_name
        ),
        name="EMRClusterWithKeyFromSSM",
        service_role="EMR_DefaultRole",
        job_flow_role="EMR_EC2_DefaultRole",
        release_label="emr-6.0.0"
    )

# {/fact}

# {fact rule=guru-cfn-lint@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # EMR cluster with Kerberos and custom IAM roles
    # ok: python-cdk-emr-auth-ec-2-key-pair-or-kerberos
    service_role = iam.Role(scope, "EMRServiceRole", 
                           assumed_by=iam.ServicePrincipal("elasticmapreduce.amazonaws.com"))
    job_flow_role = iam.Role(scope, "EMRJobFlowRole",
                            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"))
    
    cluster = emr.CfnCluster(
        scope,
        "EMRClusterWithKerberosAndCustomRoles",
        instances=emr.CfnCluster.JobFlowInstancesConfigProperty(
            instance_count=3,
            master_instance_type="m5.xlarge",
            slave_instance_type="m5.large"
        ),
        name="EMRClusterWithKerberosAndCustomRoles",
        service_role=service_role.role_name,
        job_flow_role=job_flow_role.role_name,
        release_label="emr-6.1.0",
        kerberos_attributes=emr.CfnCluster.KerberosAttributesProperty(
            realm="EC2.INTERNAL",
            kdc_admin_password="SecurePassword123"
        )
    )
# {/fact}