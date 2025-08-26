import aws_cdk as cdk
from aws_cdk import (
    aws_docdb as docdb,
    aws_secretsmanager as secretsmanager,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy
)
from constructs import Construct
import os
import json
from typing import Dict, Any

# True Positive Examples (Vulnerable Code)

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "MyDocDB",
        master_user=docdb.Login(
            username="admin",
            password=cdk.SecretValue.plain_text("hardcoded_password")
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials in a variable
    password = "super_secret_password123"
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocDBCluster",
        master_user=docdb.Login(
            username="dbadmin",
            password=cdk.SecretValue.plain_text(password)
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.R5, docdb.InstanceSize.LARGE),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials using string concatenation
    username = "root"
    password_part1 = "pass"
    password_part2 = "word123"
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocumentDBCluster",
        master_user=docdb.Login(
            username=username,
            password=cdk.SecretValue.plain_text(password_part1 + password_part2)
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials from a config dictionary
    config = {
        "username": "admin",
        "password": "complex_password_2023",
        "instance_class": docdb.InstanceClass.R5,
        "instance_size": docdb.InstanceSize.LARGE
    }
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocDB",
        master_user=docdb.Login(
            username=config["username"],
            password=cdk.SecretValue.plain_text(config["password"])
        ),
        instance_type=docdb.InstanceType.of(config["instance_class"], config["instance_size"]),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials using a function
    def get_password():
        return "generated_password_456"
    
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocumentDB",
        master_user=docdb.Login(
            username="dbuser",
            password=cdk.SecretValue.plain_text(get_password())
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials using string formatting
    username = "admin"
    password_template = "pwd_{0}"
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocDBInstance",
        master_user=docdb.Login(
            username=username,
            password=cdk.SecretValue.plain_text(password_template.format("secret123"))
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.R5, docdb.InstanceSize.LARGE),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials in a class
    class DBConfig:
        def __init__(self):
            self.username = "dbadmin"
            self.password = "secure_password_789"
    
    config = DBConfig()
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocumentDBCluster",
        master_user=docdb.Login(
            username=config.username,
            password=cdk.SecretValue.plain_text(config.password)
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials from a JSON string
    config_json = '{"username": "admin", "password": "json_password_123"}'
    config = json.loads(config_json)
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocDBCluster",
        master_user=docdb.Login(
            username=config["username"],
            password=cdk.SecretValue.plain_text(config["password"])
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.R5, docdb.InstanceSize.LARGE),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials using f-strings
    username_prefix = "admin"
    password_suffix = "2023"
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocumentDB",
        master_user=docdb.Login(
            username=f"{username_prefix}_user",
            password=cdk.SecretValue.plain_text(f"secret_password_{password_suffix}")
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials using a dictionary lookup
    credentials = {
        "dev": {"username": "dev_user", "password": "dev_password"},
        "prod": {"username": "prod_user", "password": "prod_password"}
    }
    env = "dev"
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocDBCluster",
        master_user=docdb.Login(
            username=credentials[env]["username"],
            password=cdk.SecretValue.plain_text(credentials[env]["password"])
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.R5, docdb.InstanceSize.LARGE),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials using a conditional expression
    is_dev = True
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocumentDB",
        master_user=docdb.Login(
            username="admin",
            password=cdk.SecretValue.plain_text("dev_password" if is_dev else "prod_password")
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials using a list
    credentials_list = ["admin", "list_password_123"]
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocDBCluster",
        master_user=docdb.Login(
            username=credentials_list[0],
            password=cdk.SecretValue.plain_text(credentials_list[1])
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.R5, docdb.InstanceSize.LARGE),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials using string operations
    password_base = "password"
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocumentDB",
        master_user=docdb.Login(
            username="dbadmin",
            password=cdk.SecretValue.plain_text(password_base.replace("word", "phrase") + "123")
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials using a tuple
    credentials = ("admin_user", "tuple_password_456")
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocDBCluster",
        master_user=docdb.Login(
            username=credentials[0],
            password=cdk.SecretValue.plain_text(credentials[1])
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.R5, docdb.InstanceSize.LARGE),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a DocumentDB cluster with hardcoded credentials using multiple variables
    username_part1 = "admin"
    username_part2 = "_user"
    password_part1 = "complex"
    password_part2 = "_password"
    password_part3 = "_789"
    # ruleid: python-cdk-documentdb-open-credentials
    cluster = docdb.DatabaseCluster(scope, "DocumentDB",
        master_user=docdb.Login(
            username=username_part1 + username_part2,
            password=cdk.SecretValue.plain_text(password_part1 + password_part2 + password_part3)
        ),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from Secrets Manager
    # ok: python-cdk-documentdb-open-credentials
    secret = secretsmanager.Secret(scope, "DocDBSecret",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "admin"}),
            generate_string_key="password"
        )
    )
    
    cluster = docdb.DatabaseCluster(scope, "MyDocDB",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from an existing secret
    # ok: python-cdk-documentdb-open-credentials
    existing_secret = secretsmanager.Secret.from_secret_name_v2(
        scope, "ImportedSecret", "docdb/credentials"
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocDBCluster",
        master_user=docdb.Login.from_secret(existing_secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.R5, docdb.InstanceSize.LARGE),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a new secret with custom username
    # ok: python-cdk-documentdb-open-credentials
    secret = secretsmanager.Secret(scope, "DocumentDBSecret",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "dbadmin"}),
            generate_string_key="password",
            exclude_characters="\"@/\\"
        )
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocumentDBCluster",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a secret with rotation
    # ok: python-cdk-documentdb-open-credentials
    secret = secretsmanager.Secret(scope, "DocDBSecret",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "admin"}),
            generate_string_key="password"
        )
    )
    
    # Set up rotation for the secret
    secret.add_rotation_schedule("RotationSchedule",
        automatically_after=Duration.days(30)
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocDB",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.R5, docdb.InstanceSize.LARGE),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a secret with custom description
    # ok: python-cdk-documentdb-open-credentials
    secret = secretsmanager.Secret(scope, "DocumentDBSecret",
        description="Secret for DocumentDB credentials",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "dbuser"}),
            generate_string_key="password",
            password_length=32
        )
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocumentDB",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a secret with tags
    # ok: python-cdk-documentdb-open-credentials
    secret = secretsmanager.Secret(scope, "DocDBSecret",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "admin"}),
            generate_string_key="password"
        )
    )
    
    cdk.Tags.of(secret).add("Environment", "Production")
    cdk.Tags.of(secret).add("Service", "DocumentDB")
    
    cluster = docdb.DatabaseCluster(scope, "DocDBInstance",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.R5, docdb.InstanceSize.LARGE),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a secret with custom name
    # ok: python-cdk-documentdb-open-credentials
    secret = secretsmanager.Secret(scope, "DocumentDBSecret",
        secret_name="prod/documentdb/credentials",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "dbadmin"}),
            generate_string_key="password"
        )
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocumentDBCluster",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a secret with encryption key
    # ok: python-cdk-documentdb-open-credentials
    encryption_key = cdk.aws_kms.Key(scope, "DocDBSecretKey",
        enable_key_rotation=True
    )
    
    secret = secretsmanager.Secret(scope, "DocDBSecret",
        encryption_key=encryption_key,
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "admin"}),
            generate_string_key="password"
        )
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocDBCluster",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.R5, docdb.InstanceSize.LARGE),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a secret with custom policy
    # ok: python-cdk-documentdb-open-credentials
    secret = secretsmanager.Secret(scope, "DocumentDBSecret",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "dbuser"}),
            generate_string_key="password"
        )
    )
    
    # Add resource policy to the secret
    secret.add_to_resource_policy(
        cdk.aws_iam.PolicyStatement(
            actions=["secretsmanager:GetSecretValue"],
            resources=["*"],
            principals=[cdk.aws_iam.ServicePrincipal("docdb.amazonaws.com")]
        )
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocumentDB",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a secret with replica regions
    # ok: python-cdk-documentdb-open-credentials
    secret = secretsmanager.Secret(scope, "DocDBSecret",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "admin"}),
            generate_string_key="password"
        ),
        replica_regions=[
            secretsmanager.ReplicaRegion(region="us-west-2")
        ]
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocDBCluster",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.R5, docdb.InstanceSize.LARGE),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a secret with removal policy
    # ok: python-cdk-documentdb-open-credentials
    secret = secretsmanager.Secret(scope, "DocumentDBSecret",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "dbadmin"}),
            generate_string_key="password"
        ),
        removal_policy=RemovalPolicy.RETAIN
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocumentDB",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a secret and exporting outputs
    # ok: python-cdk-documentdb-open-credentials
    secret = secretsmanager.Secret(scope, "DocDBSecret",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "admin"}),
            generate_string_key="password"
        )
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocDBCluster",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.R5, docdb.InstanceSize.LARGE),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    
    # Export outputs
    CfnOutput(scope, "DocDBEndpoint", value=cluster.cluster_endpoint.hostname)
    CfnOutput(scope, "DocDBSecretArn", value=secret.secret_arn)
    
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a secret with complex configuration
    # ok: python-cdk-documentdb-open-credentials
    vpc = cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    
    security_group = cdk.aws_ec2.SecurityGroup(scope, "DocDBSecurityGroup",
        vpc=vpc,
        description="Security group for DocumentDB"
    )
    
    secret = secretsmanager.Secret(scope, "DocumentDBSecret",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "dbuser"}),
            generate_string_key="password",
            exclude_punctuation=True
        )
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocumentDB",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc=vpc,
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        security_group=security_group,
        instances=2,
        backup=docdb.BackupProps(
            retention=Duration.days(7)
        )
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a secret with conditional creation
    # ok: python-cdk-documentdb-open-credentials
    is_prod = True
    
    secret_name = "prod-docdb-credentials" if is_prod else "dev-docdb-credentials"
    
    secret = secretsmanager.Secret(scope, "DocDBSecret",
        secret_name=secret_name,
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps({"username": "admin"}),
            generate_string_key="password"
        )
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocDBCluster",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(
            docdb.InstanceClass.R5 if is_prod else docdb.InstanceClass.T3,
            docdb.InstanceSize.LARGE if is_prod else docdb.InstanceSize.MEDIUM
        ),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC")
    )
    return cluster

# {/fact}

# {fact rule=hardcoded-credentials@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a DocumentDB cluster with credentials from a secret with custom template
    # ok: python-cdk-documentdb-open-credentials
    template = {
        "username": "dbadmin",
        "engine": "docdb",
        "port": 27017,
        "dbClusterIdentifier": "my-docdb-cluster"
    }
    
    secret = secretsmanager.Secret(scope, "DocumentDBSecret",
        generate_secret_string=secretsmanager.SecretStringGenerator(
            secret_string_template=json.dumps(template),
            generate_string_key="password",
            exclude_characters="\"@/\\",
            password_length=24
        )
    )
    
    cluster = docdb.DatabaseCluster(scope, "DocumentDB",
        master_user=docdb.Login.from_secret(secret),
        instance_type=docdb.InstanceType.of(docdb.InstanceClass.T3, docdb.InstanceSize.MEDIUM),
        vpc_subnets={"subnet_type": cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS},
        vpc=cdk.aws_ec2.Vpc(scope, "DocDBVPC"),
        db_cluster_name="my-docdb-cluster"
    )
    return cluster
# {/fact}