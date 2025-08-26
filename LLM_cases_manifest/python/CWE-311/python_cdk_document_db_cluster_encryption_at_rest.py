import aws_cdk as cdk
from aws_cdk import (
    aws_docdb as docdb,
    Stack,
    RemovalPolicy,
    Duration,
    CfnOutput,
    aws_ec2 as ec2,
    aws_kms as kms,
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a DocumentDB cluster without encryption
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster",
        master_user=docdb.Login(
            username="myuser"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=ec2.Vpc(scope, "VPC"),
        removal_policy=RemovalPolicy.DESTROY,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Explicitly setting storage_encrypted to False
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "MyDocDBCluster",
        master_user=docdb.Login(
            username="admin",
            password=cdk.SecretValue.unsafe_plain_text("password123")
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM
        ),
        vpc=vpc,
        storage_encrypted=False,
        instances=2,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a cluster with minimal configuration, no encryption specified
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "MinimalDocDBCluster",
        master_user=docdb.Login(
            username="dbadmin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a cluster with backup configuration but no encryption
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "BackupDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        backup=docdb.BackupProps(
            retention=Duration.days(7),
            preferred_window="01:00-02:00"
        ),
        storage_encrypted=False,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a cluster with parameter group but no encryption
    vpc = ec2.Vpc(scope, "VPC")
    parameter_group = docdb.ClusterParameterGroup(
        scope, "DocDBParams",
        description="Custom parameter group",
        parameters={
            "tls": "enabled",
            "ttl_monitor": "enabled"
        }
    )
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "ParamDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        parameter_group=parameter_group,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a cluster with multiple instances but no encryption
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "MultiInstanceDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        instances=3,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a cluster with removal policy but no encryption
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "RemovalPolicyDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        removal_policy=RemovalPolicy.SNAPSHOT,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a cluster with port configuration but no encryption
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "PortDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        port=27018,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a cluster with security group but no encryption
    vpc = ec2.Vpc(scope, "VPC")
    security_group = ec2.SecurityGroup(scope, "DocDBSecurityGroup", vpc=vpc)
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "SecGroupDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        security_group=security_group,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a cluster with preferred maintenance window but no encryption
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "MaintenanceDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        preferred_maintenance_window="sat:22:00-sat:23:00",
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a cluster with database name but no encryption
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "DBNameDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        db_cluster_name="my-docdb-cluster",
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a cluster with subnet group but no encryption
    vpc = ec2.Vpc(scope, "VPC")
    subnet_group = docdb.SubnetGroup(
        scope, "DocDBSubnetGroup",
        description="DocDB subnet group",
        vpc=vpc,
    )
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "SubnetGroupDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        subnet_group=subnet_group,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a cluster with engine version but no encryption
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "EngineVersionDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        engine_version="4.0.0",
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a cluster with CloudWatch logs export but no encryption
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "LogExportDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        cloud_watch_logs_exports=["audit", "profiler"],
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a cluster with deletion protection but no encryption
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "DeletionProtectionDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        deletion_protection=True,
    )
    return cluster

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption enabled
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "EncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and custom KMS key
    vpc = ec2.Vpc(scope, "VPC")
    encryption_key = kms.Key(scope, "DocDBEncryptionKey",
        enable_key_rotation=True,
        description="KMS key for DocumentDB encryption"
    )
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "CustomKeyDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        kms_key=encryption_key,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and multiple instances
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "MultiInstanceEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        instances=3,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and backup configuration
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "BackupEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        backup=docdb.BackupProps(
            retention=Duration.days(14),
            preferred_window="03:00-04:00"
        ),
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and parameter group
    vpc = ec2.Vpc(scope, "VPC")
    parameter_group = docdb.ClusterParameterGroup(
        scope, "EncryptedDocDBParams",
        description="Custom parameter group for encrypted cluster",
        parameters={
            "tls": "enabled",
            "ttl_monitor": "enabled"
        }
    )
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "ParamEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        parameter_group=parameter_group,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and removal policy
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "RemovalPolicyEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        removal_policy=RemovalPolicy.SNAPSHOT,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and custom port
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "PortEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        port=27018,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and security group
    vpc = ec2.Vpc(scope, "VPC")
    security_group = ec2.SecurityGroup(scope, "EncryptedDocDBSecurityGroup", vpc=vpc)
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "SecGroupEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        security_group=security_group,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and maintenance window
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "MaintenanceEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        preferred_maintenance_window="sun:02:00-sun:03:00",
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and database name
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "DBNameEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        db_cluster_name="my-encrypted-docdb-cluster",
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and subnet group
    vpc = ec2.Vpc(scope, "VPC")
    subnet_group = docdb.SubnetGroup(
        scope, "EncryptedDocDBSubnetGroup",
        description="DocDB subnet group for encrypted cluster",
        vpc=vpc,
    )
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "SubnetGroupEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        subnet_group=subnet_group,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and engine version
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "EngineVersionEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        engine_version="4.0.0",
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and CloudWatch logs export
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "LogExportEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        cloud_watch_logs_exports=["audit", "profiler"],
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and deletion protection
    vpc = ec2.Vpc(scope, "VPC")
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "DeletionProtectionEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        deletion_protection=True,
    )
    return cluster

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a DocumentDB cluster with encryption and multiple configurations
    vpc = ec2.Vpc(scope, "VPC")
    encryption_key = kms.Key(scope, "CompleteDocDBEncryptionKey",
        enable_key_rotation=True,
        description="KMS key for DocumentDB encryption"
    )
    parameter_group = docdb.ClusterParameterGroup(
        scope, "CompleteDocDBParams",
        description="Complete parameter group",
        parameters={
            "tls": "enabled",
            "ttl_monitor": "enabled"
        }
    )
    security_group = ec2.SecurityGroup(scope, "CompleteDocDBSecurityGroup", vpc=vpc)
    # ok: python_cdk_document_db_cluster_encryption_at_rest
    cluster = docdb.DatabaseCluster(
        scope, "CompleteEncryptedDocDBCluster",
        master_user=docdb.Login(
            username="admin"
        ),
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.R5, ec2.InstanceSize.LARGE
        ),
        vpc=vpc,
        storage_encrypted=True,
        kms_key=encryption_key,
        instances=3,
        parameter_group=parameter_group,
        security_group=security_group,
        backup=docdb.BackupProps(
            retention=Duration.days(30),
            preferred_window="02:00-03:00"
        ),
        preferred_maintenance_window="sun:04:00-sun:05:00",
        deletion_protection=True,
        db_cluster_name="complete-encrypted-docdb",
        cloud_watch_logs_exports=["audit", "profiler"],
        engine_version="4.0.0",
        port=27017,
        removal_policy=RemovalPolicy.SNAPSHOT,
    )
    return cluster
# {/fact}