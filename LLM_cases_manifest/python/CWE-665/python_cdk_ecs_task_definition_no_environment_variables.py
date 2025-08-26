import aws_cdk as cdk
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_ssm as ssm
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    container = task_definition.add_container(
        "WebContainer",
        image=ecs.ContainerImage.from_registry("amazon/amazon-ecs-sample"),
        # ruleid: python_cdk_ecs_task_definition_no_environment_variables
        environment={
            "API_KEY": "1234567890abcdef",
            "DATABASE_PASSWORD": "supersecretpassword"
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables including sensitive info
    task_definition = ecs.TaskDefinition(
        scope, 
        "TaskDef",
        compatibility=ecs.Compatibility.FARGATE,
        cpu="256",
        memory_mib="512"
    )
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "ApiContainer",
        image=ecs.ContainerImage.from_registry("my-api-image"),
        environment={
            "STRIPE_SECRET_KEY": "sk_test_PLACEHOLDER_KEY",
            "JWT_SECRET": "my-super-secret-jwt-token-string"
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a task definition with mixed plaintext and non-sensitive environment variables
    task_definition = ecs.Ec2TaskDefinition(scope, "TaskDef")
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "BackendContainer",
        image=ecs.ContainerImage.from_registry("backend-image"),
        environment={
            "DEBUG": "true",
            "LOG_LEVEL": "info",
            "ADMIN_PASSWORD": "admin123",
            "DB_CONNECTION_STRING": "postgresql://user:password@localhost:5432/db"
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables in a different pattern
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    env_vars = {
        "AWS_ACCESS_KEY": "AKIA_PLACEHOLDER_ACCESS_KEY",
        "AWS_SECRET_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
    
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "S3Container",
        image=ecs.ContainerImage.from_registry("s3-uploader"),
        environment=env_vars
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables added incrementally
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    container = task_definition.add_container(
        "WebContainer",
        image=ecs.ContainerImage.from_registry("web-app")
    )
    
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    container.add_environment("API_ENDPOINT", "https://api.example.com")
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    container.add_environment("API_KEY", "1234567890abcdef")

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables in a loop
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    container = task_definition.add_container(
        "AppContainer",
        image=ecs.ContainerImage.from_registry("app-image")
    )
    
    env_vars = [
        ("DB_HOST", "db.example.com"),
        ("DB_USER", "admin"),
        ("DB_PASSWORD", "secretpassword"),
        ("REDIS_URL", "redis://cache.example.com:6379")
    ]
    
    for key, value in env_vars:
        # ruleid: python_cdk_ecs_task_definition_no_environment_variables
        container.add_environment(key, value)

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating multiple containers with plaintext environment variables
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    app_container = task_definition.add_container(
        "AppContainer",
        image=ecs.ContainerImage.from_registry("app-image"),
        environment={
            "APP_ENV": "production",
            "APP_SECRET": "app-secret-key-123"
        }
    )
    
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    sidecar_container = task_definition.add_container(
        "SidecarContainer",
        image=ecs.ContainerImage.from_registry("sidecar-image"),
        environment={
            "METRICS_TOKEN": "metrics-token-456"
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables using string interpolation
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    env_prefix = "prod"
    secret_key = "actual-secret-value"
    
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "WebContainer",
        image=ecs.ContainerImage.from_registry("web-app"),
        environment={
            "ENV": f"{env_prefix}_environment",
            "SECRET_KEY": f"{env_prefix}_{secret_key}"
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables from a configuration object
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    config = {
        "database": {
            "host": "db.internal",
            "user": "dbuser",
            "password": "dbpassword"
        },
        "api": {
            "url": "https://api.internal",
            "key": "apikey123"
        }
    }
    
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "AppContainer",
        image=ecs.ContainerImage.from_registry("app-image"),
        environment={
            "DB_HOST": config["database"]["host"],
            "DB_USER": config["database"]["user"],
            "DB_PASSWORD": config["database"]["password"],
            "API_URL": config["api"]["url"],
            "API_KEY": config["api"]["key"]
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables mixed with other properties
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "AppContainer",
        image=ecs.ContainerImage.from_registry("app-image"),
        cpu=256,
        memory_limit_mib=512,
        essential=True,
        environment={
            "LOG_LEVEL": "info",
            "ADMIN_TOKEN": "admin-token-xyz"
        },
        logging=ecs.LogDrivers.aws_logs(stream_prefix="app-container")
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables in a stack class
    class MyStack(cdk.Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            task_definition = ecs.FargateTaskDefinition(self, "TaskDef")
            
            # ruleid: python_cdk_ecs_task_definition_no_environment_variables
            container = task_definition.add_container(
                "AppContainer",
                image=ecs.ContainerImage.from_registry("app-image"),
                environment={
                    "GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz",
                    "NPM_TOKEN": "npm_abcdefghijklmnopqrstuvwxyz"
                }
            )
    
    app = cdk.App()
    MyStack(app, "MyStack")

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables for a specific service
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "PaymentProcessor",
        image=ecs.ContainerImage.from_registry("payment-processor"),
        environment={
            "STRIPE_PUBLIC_KEY": "pk_test_PLACEHOLDER_KEY",
            "STRIPE_SECRET_KEY": "sk_test_PLACEHOLDER_KEY",
            "PAYMENT_GATEWAY_URL": "https://payment.example.com/api/v1"
        }
    )
    
    service = ecs.FargateService(
        scope,
        "PaymentService",
        task_definition=task_definition,
        desired_count=2
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables and command overrides
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "MigrationContainer",
        image=ecs.ContainerImage.from_registry("migration-tool"),
        environment={
            "DB_HOST": "db.example.com",
            "DB_USER": "migration_user",
            "DB_PASSWORD": "migration_password",
            "MIGRATION_VERSION": "v2"
        },
        command=["./run-migrations.sh", "--force"]
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables for a scheduled task
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "BackupContainer",
        image=ecs.ContainerImage.from_registry("backup-tool"),
        environment={
            "BACKUP_BUCKET": "my-backup-bucket",
            "AWS_REGION": "us-west-2",
            "BACKUP_ENCRYPTION_KEY": "backup-encryption-key-123"
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a task definition with plaintext environment variables using a helper function
    def get_environment_config():
        return {
            "APP_ENV": "production",
            "CACHE_TTL": "3600",
            "API_TOKEN": "prod-api-token-123",
            "MONITORING_ENDPOINT": "https://monitoring.example.com"
        }
    
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    # ruleid: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "AppContainer",
        image=ecs.ContainerImage.from_registry("app-image"),
        environment=get_environment_config()
    )

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Using AWS Secrets Manager for sensitive environment variables
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    db_secret = secretsmanager.Secret(scope, "DBSecret")
    api_secret = secretsmanager.Secret(scope, "ApiSecret")
    
    container = task_definition.add_container(
        "WebContainer",
        image=ecs.ContainerImage.from_registry("amazon/amazon-ecs-sample"),
        # ok: python_cdk_ecs_task_definition_no_environment_variables
        secrets={
            "DATABASE_PASSWORD": ecs.Secret.from_secrets_manager(db_secret),
            "API_KEY": ecs.Secret.from_secrets_manager(api_secret)
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Using AWS Systems Manager Parameter Store for environment variables
    task_definition = ecs.TaskDefinition(
        scope, 
        "TaskDef",
        compatibility=ecs.Compatibility.FARGATE,
        cpu="256",
        memory_mib="512"
    )
    
    # ok: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "ApiContainer",
        image=ecs.ContainerImage.from_registry("my-api-image"),
        secrets={
            "STRIPE_SECRET_KEY": ecs.Secret.from_ssm_parameter(
                ssm.StringParameter.from_string_parameter_name(
                    scope, "StripeKey", "stripe-secret-key"
                )
            ),
            "JWT_SECRET": ecs.Secret.from_ssm_parameter(
                ssm.StringParameter.from_string_parameter_name(
                    scope, "JwtSecret", "jwt-secret"
                )
            )
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Using a mix of non-sensitive environment variables and secrets for sensitive data
    task_definition = ecs.Ec2TaskDefinition(scope, "TaskDef")
    
    db_secret = secretsmanager.Secret(scope, "DBSecret")
    
    container = task_definition.add_container(
        "BackendContainer",
        image=ecs.ContainerImage.from_registry("backend-image"),
        # ok: python_cdk_ecs_task_definition_no_environment_variables
        environment={
            "DEBUG": "true",
            "LOG_LEVEL": "info"
        },
        secrets={
            "ADMIN_PASSWORD": ecs.Secret.from_secrets_manager(db_secret, "admin_password"),
            "DB_CONNECTION_STRING": ecs.Secret.from_secrets_manager(db_secret, "connection_string")
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Using AWS Secrets Manager with JSON field extraction
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    aws_credentials = secretsmanager.Secret(scope, "AwsCredentials")
    
    # ok: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "S3Container",
        image=ecs.ContainerImage.from_registry("s3-uploader"),
        secrets={
            "AWS_ACCESS_KEY": ecs.Secret.from_secrets_manager(aws_credentials, "access_key"),
            "AWS_SECRET_KEY": ecs.Secret.from_secrets_manager(aws_credentials, "secret_key")
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Adding secrets incrementally instead of environment variables
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    api_secret = secretsmanager.Secret(scope, "ApiSecret")
    
    container = task_definition.add_container(
        "WebContainer",
        image=ecs.ContainerImage.from_registry("web-app")
    )
    
    # Non-sensitive environment variable is ok
    container.add_environment("API_ENDPOINT", "https://api.example.com")
    
    # ok: python_cdk_ecs_task_definition_no_environment_variables
    container.add_secret("API_KEY", ecs.Secret.from_secrets_manager(api_secret))

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Adding secrets in a loop instead of environment variables
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    db_secret = secretsmanager.Secret(scope, "DbSecret")
    redis_secret = secretsmanager.Secret(scope, "RedisSecret")
    
    container = task_definition.add_container(
        "AppContainer",
        image=ecs.ContainerImage.from_registry("app-image")
    )
    
    secrets = [
        ("DB_HOST", ecs.Secret.from_secrets_manager(db_secret, "host")),
        ("DB_USER", ecs.Secret.from_secrets_manager(db_secret, "user")),
        ("DB_PASSWORD", ecs.Secret.from_secrets_manager(db_secret, "password")),
        ("REDIS_URL", ecs.Secret.from_secrets_manager(redis_secret, "url"))
    ]
    
    for key, secret in secrets:
        # ok: python_cdk_ecs_task_definition_no_environment_variables
        container.add_secret(key, secret)

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Multiple containers with secrets instead of environment variables
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    app_secret = secretsmanager.Secret(scope, "AppSecret")
    metrics_secret = secretsmanager.Secret(scope, "MetricsSecret")
    
    # ok: python_cdk_ecs_task_definition_no_environment_variables
    app_container = task_definition.add_container(
        "AppContainer",
        image=ecs.ContainerImage.from_registry("app-image"),
        environment={
            "APP_ENV": "production"  # Non-sensitive is ok
        },
        secrets={
            "APP_SECRET": ecs.Secret.from_secrets_manager(app_secret)
        }
    )
    
    # ok: python_cdk_ecs_task_definition_no_environment_variables
    sidecar_container = task_definition.add_container(
        "SidecarContainer",
        image=ecs.ContainerImage.from_registry("sidecar-image"),
        secrets={
            "METRICS_TOKEN": ecs.Secret.from_secrets_manager(metrics_secret)
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Using SSM Parameter Store with string interpolation for parameter names
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    env_prefix = "prod"
    
    # ok: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "WebContainer",
        image=ecs.ContainerImage.from_registry("web-app"),
        environment={
            "ENV": f"{env_prefix}_environment"  # Non-sensitive is ok
        },
        secrets={
            "SECRET_KEY": ecs.Secret.from_ssm_parameter(
                ssm.StringParameter.from_string_parameter_name(
                    scope, "SecretKey", f"/{env_prefix}/secret-key"
                )
            )
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Using Secrets Manager for database credentials from a configuration object
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    config = {
        "database": {
            "secret_arn": "arn:aws:secretsmanager:region:account:secret:database-ABC123",
        },
        "api": {
            "secret_arn": "arn:aws:secretsmanager:region:account:secret:api-XYZ789",
        }
    }
    
    db_secret = secretsmanager.Secret.from_secret_complete_arn(
        scope, "DbSecret", config["database"]["secret_arn"]
    )
    
    api_secret = secretsmanager.Secret.from_secret_complete_arn(
        scope, "ApiSecret", config["api"]["secret_arn"]
    )
    
    # ok: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "AppContainer",
        image=ecs.ContainerImage.from_registry("app-image"),
        secrets={
            "DB_HOST": ecs.Secret.from_secrets_manager(db_secret, "host"),
            "DB_USER": ecs.Secret.from_secrets_manager(db_secret, "user"),
            "DB_PASSWORD": ecs.Secret.from_secrets_manager(db_secret, "password"),
            "API_URL": ecs.Secret.from_secrets_manager(api_secret, "url"),
            "API_KEY": ecs.Secret.from_secrets_manager(api_secret, "key")
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Using Secrets Manager with other container properties
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    admin_secret = secretsmanager.Secret(scope, "AdminSecret")
    
    # ok: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "AppContainer",
        image=ecs.ContainerImage.from_registry("app-image"),
        cpu=256,
        memory_limit_mib=512,
        essential=True,
        environment={
            "LOG_LEVEL": "info"  # Non-sensitive is ok
        },
        secrets={
            "ADMIN_TOKEN": ecs.Secret.from_secrets_manager(admin_secret)
        },
        logging=ecs.LogDrivers.aws_logs(stream_prefix="app-container")
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Using Secrets Manager in a stack class
    class MyStack(cdk.Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            task_definition = ecs.FargateTaskDefinition(self, "TaskDef")
            
            github_token = secretsmanager.Secret(self, "GithubToken")
            npm_token = secretsmanager.Secret(self, "NpmToken")
            
            # ok: python_cdk_ecs_task_definition_no_environment_variables
            container = task_definition.add_container(
                "AppContainer",
                image=ecs.ContainerImage.from_registry("app-image"),
                secrets={
                    "GITHUB_TOKEN": ecs.Secret.from_secrets_manager(github_token),
                    "NPM_TOKEN": ecs.Secret.from_secrets_manager(npm_token)
                }
            )
    
    app = cdk.App()
    MyStack(app, "MyStack")

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Using Secrets Manager for a specific service
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    stripe_secret = secretsmanager.Secret(scope, "StripeSecret")
    
    # ok: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "PaymentProcessor",
        image=ecs.ContainerImage.from_registry("payment-processor"),
        environment={
            "PAYMENT_GATEWAY_URL": "https://payment.example.com/api/v1"  # Non-sensitive is ok
        },
        secrets={
            "STRIPE_PUBLIC_KEY": ecs.Secret.from_secrets_manager(stripe_secret, "public_key"),
            "STRIPE_SECRET_KEY": ecs.Secret.from_secrets_manager(stripe_secret, "secret_key")
        }
    )
    
    service = ecs.FargateService(
        scope,
        "PaymentService",
        task_definition=task_definition,
        desired_count=2
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Using Secrets Manager with command overrides
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    db_secret = secretsmanager.Secret(scope, "DbSecret")
    
    # ok: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "MigrationContainer",
        image=ecs.ContainerImage.from_registry("migration-tool"),
        environment={
            "MIGRATION_VERSION": "v2"  # Non-sensitive is ok
        },
        secrets={
            "DB_HOST": ecs.Secret.from_secrets_manager(db_secret, "host"),
            "DB_USER": ecs.Secret.from_secrets_manager(db_secret, "user"),
            "DB_PASSWORD": ecs.Secret.from_secrets_manager(db_secret, "password")
        },
        command=["./run-migrations.sh", "--force"]
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Using Secrets Manager for a scheduled task
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    backup_secret = secretsmanager.Secret(scope, "BackupSecret")
    
    # ok: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "BackupContainer",
        image=ecs.ContainerImage.from_registry("backup-tool"),
        environment={
            "BACKUP_BUCKET": "my-backup-bucket",
            "AWS_REGION": "us-west-2"  # Non-sensitive is ok
        },
        secrets={
            "BACKUP_ENCRYPTION_KEY": ecs.Secret.from_secrets_manager(backup_secret, "encryption_key")
        }
    )

# {/fact}

# {fact rule=improper-initialization@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Using a helper function to configure secrets
    def get_secrets_config(scope: Construct):
        api_secret = secretsmanager.Secret(scope, "ApiSecret")
        monitoring_secret = secretsmanager.Secret(scope, "MonitoringSecret")
        
        return {
            "API_TOKEN": ecs.Secret.from_secrets_manager(api_secret),
            "MONITORING_ENDPOINT": ecs.Secret.from_secrets_manager(monitoring_secret, "endpoint")
        }
    
    task_definition = ecs.FargateTaskDefinition(scope, "TaskDef")
    
    # ok: python_cdk_ecs_task_definition_no_environment_variables
    container = task_definition.add_container(
        "AppContainer",
        image=ecs.ContainerImage.from_registry("app-image"),
        environment={
            "APP_ENV": "production",
            "CACHE_TTL": "3600"  # Non-sensitive is ok
        },
        secrets=get_secrets_config(scope)
    )
# {/fact}