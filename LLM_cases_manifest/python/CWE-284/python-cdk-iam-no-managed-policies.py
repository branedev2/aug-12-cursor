import aws_cdk as cdk
from aws_cdk import (
    aws_iam as iam,
    Stack,
    CfnOutput,
    aws_s3 as s3,
    aws_lambda as lambda_,
    aws_dynamodb as dynamodb
)
from constructs import Construct

# True Positives (Vulnerable Code Examples)

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a role with AWS managed policy
    role = iam.Role(
        scope, 
        "MyRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com")
    )
    # ruleid: python-cdk-iam-no-managed-policies
    role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3FullAccess"))
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating a user with AWS managed policy
    user = iam.User(scope, "AdminUser")
    # ruleid: python-cdk-iam-no-managed-policies
    user.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AdministratorAccess"))
    
    return user

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a group with AWS managed policy
    group = iam.Group(scope, "DevelopersGroup")
    # ruleid: python-cdk-iam-no-managed-policies
    group.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonDynamoDBFullAccess"))
    
    return group

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a role with multiple AWS managed policies
    role = iam.Role(
        scope,
        "DataProcessingRole",
        assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
    )
    # ruleid: python-cdk-iam-no-managed-policies
    role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonS3ReadOnlyAccess"))
    # ruleid: python-cdk-iam-no-managed-policies
    role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSQSFullAccess"))
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a role with AWS managed policy in constructor
    # ruleid: python-cdk-iam-no-managed-policies
    role = iam.Role(
        scope,
        "ApiGatewayRole",
        assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonAPIGatewayAdministrator")
        ]
    )
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a user with multiple AWS managed policies in constructor
    # ruleid: python-cdk-iam-no-managed-policies
    user = iam.User(
        scope,
        "PowerUser",
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name("PowerUserAccess"),
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonRDSFullAccess")
        ]
    )
    
    return user

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a group with AWS managed policy in constructor
    # ruleid: python-cdk-iam-no-managed-policies
    group = iam.Group(
        scope,
        "CloudOpsTeam",
        managed_policies=[
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2FullAccess")
        ]
    )
    
    return group

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a role for Lambda with AWS managed policy
    lambda_role = iam.Role(
        scope,
        "LambdaExecutionRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com")
    )
    # ruleid: python-cdk-iam-no-managed-policies
    lambda_role.add_managed_policy(
        iam.ManagedPolicy.from_aws_managed_policy_name("AWSLambdaBasicExecutionRole")
    )
    
    # Using the role in a Lambda function
    lambda_fn = lambda_.Function(
        scope,
        "MyFunction",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_inline("def handler(event, context): return {'statusCode': 200}"),
        role=lambda_role
    )
    
    return lambda_fn

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a role with AWS managed policy using variable
    policy_name = "AmazonECR-FullAccess"
    role = iam.Role(
        scope,
        "ContainerRole",
        assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com")
    )
    # ruleid: python-cdk-iam-no-managed-policies
    role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name(policy_name))
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a role with AWS managed policy in a conditional block
    role = iam.Role(
        scope,
        "ConditionalRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com")
    )
    
    is_prod = True
    if is_prod:
        # ruleid: python-cdk-iam-no-managed-policies
        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSNSFullAccess"))
    else:
        # ruleid: python-cdk-iam-no-managed-policies
        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSNSReadOnlyAccess"))
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a role with AWS managed policy in a loop
    role = iam.Role(
        scope,
        "MultiServiceRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com")
    )
    
    policies = ["AmazonS3FullAccess", "AmazonDynamoDBFullAccess", "AmazonSQSFullAccess"]
    for policy in policies:
        # ruleid: python-cdk-iam-no-managed-policies
        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name(policy))
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a role and attaching AWS managed policy via a function
    role = iam.Role(
        scope,
        "HelperRole",
        assumed_by=iam.ServicePrincipal("glue.amazonaws.com")
    )
    
    def attach_policy(role, policy_name):
        # ruleid: python-cdk-iam-no-managed-policies
        role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name(policy_name))
    
    attach_policy(role, "AWSGlueServiceRole")
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a role with AWS managed policy for ECS task
    task_role = iam.Role(
        scope,
        "ECSTaskRole",
        assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com")
    )
    # ruleid: python-cdk-iam-no-managed-policies
    task_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonECS-FullAccess"))
    
    return task_role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a user with AWS managed policy using a different method
    user = iam.User(scope, "DatabaseUser")
    policy = iam.ManagedPolicy.from_aws_managed_policy_name("AmazonRDSFullAccess")
    # ruleid: python-cdk-iam-no-managed-policies
    user.add_managed_policy(policy)
    
    return user

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a role with AWS managed policy for CloudWatch
    monitoring_role = iam.Role(
        scope,
        "MonitoringRole",
        assumed_by=iam.ServicePrincipal("cloudwatch.amazonaws.com")
    )
    # ruleid: python-cdk-iam-no-managed-policies
    monitoring_role.add_managed_policy(
        iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchFullAccess")
    )
    
    return monitoring_role

# True Negatives (Secure Code Examples)

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a role with customer-managed policy
    role = iam.Role(
        scope,
        "MySecureRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com")
    )
    # ok: python-cdk-iam-no-managed-policies
    policy = iam.ManagedPolicy(
        scope,
        "CustomS3Policy",
        statements=[
            iam.PolicyStatement(
                actions=["s3:GetObject", "s3:ListBucket"],
                resources=["arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket"]
            )
        ]
    )
    role.add_managed_policy(policy)
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating a user with inline policy
    user = iam.User(scope, "RestrictedUser")
    # ok: python-cdk-iam-no-managed-policies
    user.add_to_policy(
        iam.PolicyStatement(
            actions=["s3:GetObject"],
            resources=["arn:aws:s3:::specific-bucket/specific-path/*"]
        )
    )
    
    return user

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating a group with customer-managed policy
    group = iam.Group(scope, "DevGroup")
    # ok: python-cdk-iam-no-managed-policies
    policy = iam.ManagedPolicy(
        scope,
        "DevDynamoDBPolicy",
        statements=[
            iam.PolicyStatement(
                actions=["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"],
                resources=["arn:aws:dynamodb:*:*:table/dev-*"]
            )
        ]
    )
    group.add_managed_policy(policy)
    
    return group

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a role with multiple inline policies
    role = iam.Role(
        scope,
        "MultiPolicyRole",
        assumed_by=iam.ServicePrincipal("ec2.amazonaws.com")
    )
    # ok: python-cdk-iam-no-managed-policies
    role.add_to_policy(
        iam.PolicyStatement(
            actions=["s3:GetObject", "s3:ListBucket"],
            resources=["arn:aws:s3:::app-bucket/*", "arn:aws:s3:::app-bucket"]
        )
    )
    # ok: python-cdk-iam-no-managed-policies
    role.add_to_policy(
        iam.PolicyStatement(
            actions=["sqs:SendMessage", "sqs:ReceiveMessage"],
            resources=["arn:aws:sqs:*:*:app-queue"]
        )
    )
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a role with customer-managed policy in constructor
    # ok: python-cdk-iam-no-managed-policies
    custom_policy = iam.ManagedPolicy(
        scope,
        "ApiGatewayCustomPolicy",
        statements=[
            iam.PolicyStatement(
                actions=["apigateway:GET", "apigateway:POST"],
                resources=["arn:aws:apigateway:*::/apis/*"]
            )
        ]
    )
    
    role = iam.Role(
        scope,
        "ApiGatewayRole",
        assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
        managed_policies=[custom_policy]
    )
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a user with customer-managed policies
    # ok: python-cdk-iam-no-managed-policies
    rds_policy = iam.ManagedPolicy(
        scope,
        "CustomRDSPolicy",
        statements=[
            iam.PolicyStatement(
                actions=["rds:DescribeDBInstances", "rds:DescribeDBClusters"],
                resources=["*"]
            )
        ]
    )
    
    user = iam.User(
        scope,
        "DBUser",
        managed_policies=[rds_policy]
    )
    
    return user

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a group with inline policy
    group = iam.Group(scope, "OpsGroup")
    # ok: python-cdk-iam-no-managed-policies
    group.add_to_policy(
        iam.PolicyStatement(
            actions=[
                "ec2:DescribeInstances",
                "ec2:StartInstances",
                "ec2:StopInstances"
            ],
            resources=["*"],
            conditions={"StringEquals": {"aws:ResourceTag/Environment": "Production"}}
        )
    )
    
    return group

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a role for Lambda with customer-managed policy
    # ok: python-cdk-iam-no-managed-policies
    lambda_policy = iam.ManagedPolicy(
        scope,
        "LambdaCustomPolicy",
        statements=[
            iam.PolicyStatement(
                actions=["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                resources=["arn:aws:logs:*:*:*"]
            )
        ]
    )
    
    lambda_role = iam.Role(
        scope,
        "LambdaExecutionRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        managed_policies=[lambda_policy]
    )
    
    lambda_fn = lambda_.Function(
        scope,
        "MyFunction",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_inline("def handler(event, context): return {'statusCode': 200}"),
        role=lambda_role
    )
    
    return lambda_fn

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a role with customer-managed policy using variable
    role = iam.Role(
        scope,
        "ContainerRole",
        assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com")
    )
    
    # ok: python-cdk-iam-no-managed-policies
    ecr_actions = ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "ecr:BatchCheckLayerAvailability"]
    role.add_to_policy(
        iam.PolicyStatement(
            actions=ecr_actions,
            resources=["arn:aws:ecr:*:*:repository/app-repo"]
        )
    )
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a role with conditional inline policies
    role = iam.Role(
        scope,
        "ConditionalRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com")
    )
    
    is_prod = True
    if is_prod:
        # ok: python-cdk-iam-no-managed-policies
        role.add_to_policy(
            iam.PolicyStatement(
                actions=["sns:Publish"],
                resources=["arn:aws:sns:*:*:prod-topic"]
            )
        )
    else:
        # ok: python-cdk-iam-no-managed-policies
        role.add_to_policy(
            iam.PolicyStatement(
                actions=["sns:GetTopicAttributes"],
                resources=["arn:aws:sns:*:*:dev-topic"]
            )
        )
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a role with inline policies in a loop
    role = iam.Role(
        scope,
        "MultiServiceRole",
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com")
    )
    
    services = [
        {"service": "s3", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::app-bucket/*"]},
        {"service": "dynamodb", "actions": ["dynamodb:GetItem"], "resources": ["arn:aws:dynamodb:*:*:table/app-table"]},
        {"service": "sqs", "actions": ["sqs:SendMessage"], "resources": ["arn:aws:sqs:*:*:app-queue"]}
    ]
    
    for svc in services:
        # ok: python-cdk-iam-no-managed-policies
        role.add_to_policy(
            iam.PolicyStatement(
                actions=svc["actions"],
                resources=svc["resources"]
            )
        )
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a role and attaching inline policy via a function
    role = iam.Role(
        scope,
        "HelperRole",
        assumed_by=iam.ServicePrincipal("glue.amazonaws.com")
    )
    
    def attach_inline_policy(role, actions, resources):
        # ok: python-cdk-iam-no-managed-policies
        role.add_to_policy(
            iam.PolicyStatement(
                actions=actions,
                resources=resources
            )
        )
    
    attach_inline_policy(
        role,
        ["glue:CreateJob", "glue:GetJob", "glue:StartJobRun"],
        ["arn:aws:glue:*:*:job/app-*"]
    )
    
    return role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a role with customer-managed policy for ECS task
    # ok: python-cdk-iam-no-managed-policies
    task_policy = iam.ManagedPolicy(
        scope,
        "ECSTaskCustomPolicy",
        statements=[
            iam.PolicyStatement(
                actions=[
                    "ecs:DescribeTasks",
                    "ecs:ListTasks"
                ],
                resources=["*"]
            )
        ]
    )
    
    task_role = iam.Role(
        scope,
        "ECSTaskRole",
        assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
        managed_policies=[task_policy]
    )
    
    return task_role

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a user with inline policy using a different method
    user = iam.User(scope, "DatabaseUser")
    
    # ok: python-cdk-iam-no-managed-policies
    policy_document = iam.PolicyDocument(
        statements=[
            iam.PolicyStatement(
                actions=["rds:DescribeDBInstances"],
                resources=["*"]
            ),
            iam.PolicyStatement(
                actions=["rds:ModifyDBInstance"],
                resources=["arn:aws:rds:*:*:db:app-*"],
                conditions={"StringEquals": {"aws:ResourceTag/Owner": "${aws:username}"}}
            )
        ]
    )
    
    iam.Policy(
        scope,
        "UserInlinePolicy",
        policy_document=policy_document,
        users=[user]
    )
    
    return user

# {/fact}

# {fact rule=check-mutable-property-in-handler-class@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a role with customer-managed policy for CloudWatch
    # ok: python-cdk-iam-no-managed-policies
    monitoring_policy = iam.ManagedPolicy(
        scope,
        "CustomMonitoringPolicy",
        statements=[
            iam.PolicyStatement(
                actions=[
                    "cloudwatch:PutMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics"
                ],
                resources=["*"]
            ),
            iam.PolicyStatement(
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                resources=["arn:aws:logs:*:*:log-group:app-*"]
            )
        ]
    )
    
    monitoring_role = iam.Role(
        scope,
        "MonitoringRole",
        assumed_by=iam.ServicePrincipal("cloudwatch.amazonaws.com"),
        managed_policies=[monitoring_policy]
    )
    
    return monitoring_role

# {/fact}

class ExampleStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Examples can be used here
        bad_case_1(self, "BadCase1")
        good_case_1(self, "GoodCase1")

app = cdk.App()
ExampleStack(app, "ExampleStack")
app.synth()