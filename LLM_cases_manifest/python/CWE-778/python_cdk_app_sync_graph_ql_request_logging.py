# Import necessary libraries
import aws_cdk as cdk
from aws_cdk import (
    aws_appsync as appsync,
    aws_lambda as lambda_,
    aws_dynamodb as dynamodb,
    aws_logs as logs,
    Stack,
    CfnOutput,
    Duration,
    RemovalPolicy
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_1(self):
    # Creating an AppSync GraphQL API without any logging configuration
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql")
    )
    
    # Add a DynamoDB table as a data source
    demo_table = dynamodb.Table(
        self, "DemoTable",
        partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING)
    )
    
    # Add the table as a data source
    demo_table_ds = api.add_dynamo_db_data_source("DemoTableDataSource", demo_table)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_2(self):
    # Creating an AppSync GraphQL API with explicitly disabled logging
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.NONE
        )
    )
    
    # Add a Lambda function as a data source
    demo_function = lambda_.Function(
        self, "DemoFunction",
        runtime=lambda_.Runtime.NODEJS_14_X,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # Add the Lambda function as a data source
    demo_function_ds = api.add_lambda_data_source("DemoFunctionDataSource", demo_function)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_3(self):
    # Creating an AppSync GraphQL API with log config but with NONE field log level
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.NONE,
            exclude_verbose_content=False
        )
    )
    
    # Add resolvers
    api.create_resolver(
        type_name="Query",
        field_name="getDemos",
        data_source=api.add_none_data_source("NoneDataSource")
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_4(self):
    # Creating an AppSync GraphQL API with log config but without specifying field log level (defaults to NONE)
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    log_group = logs.LogGroup(self, "ApiLogs")
    
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        log_config=appsync.LogConfig(
            cloud_watch_logs_role=None,
            cloud_watch_logs_group=log_group
        )
    )
    
    # Add HTTP data source
    http_ds = api.add_http_data_source(
        "HttpDataSource",
        endpoint="https://api.example.com",
        authorization_config=appsync.AwsIamConfig()
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_5(self):
    # Creating an AppSync GraphQL API with authorization but no logging
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        authorization_config=appsync.AuthorizationConfig(
            default_authorization=appsync.AuthorizationMode(
                authorization_type=appsync.AuthorizationType.API_KEY,
                api_key_config=appsync.ApiKeyConfig(
                    expires=cdk.Expiration.after(Duration.days(365))
                )
            )
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_6(self):
    # Creating multiple AppSync GraphQL APIs, all without logging
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api1 = appsync.GraphqlApi(
        self, "Api1",
        name="demo-api-1",
        schema=appsync.SchemaFile.from_asset("schema1.graphql")
    )
    
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api2 = appsync.GraphqlApi(
        self, "Api2",
        name="demo-api-2",
        schema=appsync.SchemaFile.from_asset("schema2.graphql")
    )
    
    # Output the GraphQL API URLs
    CfnOutput(self, "GraphQLAPI1URL", value=api1.graphql_url)
    CfnOutput(self, "GraphQLAPI2URL", value=api2.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_7(self):
    # Creating an AppSync GraphQL API with xray enabled but no logging
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        xray_enabled=True
    )
    
    # Add a DynamoDB table as a data source
    demo_table = dynamodb.Table(
        self, "DemoTable",
        partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
        billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST
    )
    
    # Add the table as a data source
    demo_table_ds = api.add_dynamo_db_data_source("DemoTableDataSource", demo_table)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_8(self):
    # Creating an AppSync GraphQL API with custom domain but no logging
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        domain_name=appsync.DomainOptions(
            certificate=None,  # Certificate would be provided in real code
            domain_name="api.example.com"
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_9(self):
    # Creating an AppSync GraphQL API with IAM authorization but no logging
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        authorization_config=appsync.AuthorizationConfig(
            default_authorization=appsync.AuthorizationMode(
                authorization_type=appsync.AuthorizationType.IAM
            )
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_10(self):
    # Creating an AppSync GraphQL API with Cognito user pool authorization but no logging
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        authorization_config=appsync.AuthorizationConfig(
            default_authorization=appsync.AuthorizationMode(
                authorization_type=appsync.AuthorizationType.USER_POOL,
                user_pool_config=appsync.UserPoolConfig(
                    user_pool=None  # User pool would be provided in real code
                )
            )
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_11(self):
    # Creating an AppSync GraphQL API with OpenID Connect authorization but no logging
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        authorization_config=appsync.AuthorizationConfig(
            default_authorization=appsync.AuthorizationMode(
                authorization_type=appsync.AuthorizationType.OIDC,
                openid_connect_config=appsync.OpenIdConnectConfig(
                    issuer="https://auth.example.com"
                )
            )
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_12(self):
    # Creating an AppSync GraphQL API with Lambda authorization but no logging
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    auth_function = lambda_.Function(
        self, "AuthFunction",
        runtime=lambda_.Runtime.NODEJS_14_X,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda-auth")
    )
    
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        authorization_config=appsync.AuthorizationConfig(
            default_authorization=appsync.AuthorizationMode(
                authorization_type=appsync.AuthorizationType.LAMBDA,
                lambda_authorizer_config=appsync.LambdaAuthorizerConfig(
                    handler=auth_function
                )
            )
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_13(self):
    # Creating an AppSync GraphQL API with multiple authorization modes but no logging
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        authorization_config=appsync.AuthorizationConfig(
            default_authorization=appsync.AuthorizationMode(
                authorization_type=appsync.AuthorizationType.API_KEY,
                api_key_config=appsync.ApiKeyConfig(
                    expires=cdk.Expiration.after(Duration.days(365))
                )
            ),
            additional_authorization_modes=[
                appsync.AuthorizationMode(
                    authorization_type=appsync.AuthorizationType.IAM
                )
            ]
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_14(self):
    # Creating an AppSync GraphQL API with schema definition in code but no logging
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.Schema(
            definition="""
            type Query {
                getDemos: [Demo]
            }
            
            type Demo {
                id: ID!
                name: String!
            }
            """
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_15(self):
    # Creating an AppSync GraphQL API with introspection disabled but no logging
    # ruleid: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        introspection_enabled=False
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_1(self):
    # Creating an AppSync GraphQL API with ERROR level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.ERROR
        )
    )
    
    # Add a DynamoDB table as a data source
    demo_table = dynamodb.Table(
        self, "DemoTable",
        partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING)
    )
    
    # Add the table as a data source
    demo_table_ds = api.add_dynamo_db_data_source("DemoTableDataSource", demo_table)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_2(self):
    # Creating an AppSync GraphQL API with INFO level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.INFO
        )
    )
    
    # Add a Lambda function as a data source
    demo_function = lambda_.Function(
        self, "DemoFunction",
        runtime=lambda_.Runtime.NODEJS_14_X,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # Add the Lambda function as a data source
    demo_function_ds = api.add_lambda_data_source("DemoFunctionDataSource", demo_function)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_3(self):
    # Creating an AppSync GraphQL API with ALL level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.ALL
        )
    )
    
    # Add resolvers
    api.create_resolver(
        type_name="Query",
        field_name="getDemos",
        data_source=api.add_none_data_source("NoneDataSource")
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_4(self):
    # Creating an AppSync GraphQL API with ERROR level logging and custom log group
    # ok: python_cdk_app_sync_graph_ql_request_logging
    log_group = logs.LogGroup(
        self, "ApiLogs",
        retention=logs.RetentionDays.ONE_WEEK,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.ERROR,
            cloud_watch_logs_group=log_group
        )
    )
    
    # Add HTTP data source
    http_ds = api.add_http_data_source(
        "HttpDataSource",
        endpoint="https://api.example.com",
        authorization_config=appsync.AwsIamConfig()
    )

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_5(self):
    # Creating an AppSync GraphQL API with API key authorization and INFO level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        authorization_config=appsync.AuthorizationConfig(
            default_authorization=appsync.AuthorizationMode(
                authorization_type=appsync.AuthorizationType.API_KEY,
                api_key_config=appsync.ApiKeyConfig(
                    expires=cdk.Expiration.after(Duration.days(365))
                )
            )
        ),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.INFO
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_6(self):
    # Creating multiple AppSync GraphQL APIs, all with logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api1 = appsync.GraphqlApi(
        self, "Api1",
        name="demo-api-1",
        schema=appsync.SchemaFile.from_asset("schema1.graphql"),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.ERROR
        )
    )
    
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api2 = appsync.GraphqlApi(
        self, "Api2",
        name="demo-api-2",
        schema=appsync.SchemaFile.from_asset("schema2.graphql"),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.ALL
        )
    )
    
    # Output the GraphQL API URLs
    CfnOutput(self, "GraphQLAPI1URL", value=api1.graphql_url)
    CfnOutput(self, "GraphQLAPI2URL", value=api2.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_7(self):
    # Creating an AppSync GraphQL API with xray enabled and ERROR level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        xray_enabled=True,
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.ERROR
        )
    )
    
    # Add a DynamoDB table as a data source
    demo_table = dynamodb.Table(
        self, "DemoTable",
        partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.STRING),
        billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST
    )
    
    # Add the table as a data source
    demo_table_ds = api.add_dynamo_db_data_source("DemoTableDataSource", demo_table)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_8(self):
    # Creating an AppSync GraphQL API with custom domain and ALL level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        domain_name=appsync.DomainOptions(
            certificate=None,  # Certificate would be provided in real code
            domain_name="api.example.com"
        ),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.ALL
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_9(self):
    # Creating an AppSync GraphQL API with IAM authorization and INFO level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        authorization_config=appsync.AuthorizationConfig(
            default_authorization=appsync.AuthorizationMode(
                authorization_type=appsync.AuthorizationType.IAM
            )
        ),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.INFO
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_10(self):
    # Creating an AppSync GraphQL API with Cognito user pool authorization and ERROR level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        authorization_config=appsync.AuthorizationConfig(
            default_authorization=appsync.AuthorizationMode(
                authorization_type=appsync.AuthorizationType.USER_POOL,
                user_pool_config=appsync.UserPoolConfig(
                    user_pool=None  # User pool would be provided in real code
                )
            )
        ),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.ERROR
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_11(self):
    # Creating an AppSync GraphQL API with OpenID Connect authorization and ALL level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        authorization_config=appsync.AuthorizationConfig(
            default_authorization=appsync.AuthorizationMode(
                authorization_type=appsync.AuthorizationType.OIDC,
                openid_connect_config=appsync.OpenIdConnectConfig(
                    issuer="https://auth.example.com"
                )
            )
        ),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.ALL
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_12(self):
    # Creating an AppSync GraphQL API with Lambda authorization and INFO level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    auth_function = lambda_.Function(
        self, "AuthFunction",
        runtime=lambda_.Runtime.NODEJS_14_X,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda-auth")
    )
    
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        authorization_config=appsync.AuthorizationConfig(
            default_authorization=appsync.AuthorizationMode(
                authorization_type=appsync.AuthorizationType.LAMBDA,
                lambda_authorizer_config=appsync.LambdaAuthorizerConfig(
                    handler=auth_function
                )
            )
        ),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.INFO
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_13(self):
    # Creating an AppSync GraphQL API with multiple authorization modes and ERROR level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        authorization_config=appsync.AuthorizationConfig(
            default_authorization=appsync.AuthorizationMode(
                authorization_type=appsync.AuthorizationType.API_KEY,
                api_key_config=appsync.ApiKeyConfig(
                    expires=cdk.Expiration.after(Duration.days(365))
                )
            ),
            additional_authorization_modes=[
                appsync.AuthorizationMode(
                    authorization_type=appsync.AuthorizationType.IAM
                )
            ]
        ),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.ERROR
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_14(self):
    # Creating an AppSync GraphQL API with schema definition in code and ALL level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.Schema(
            definition="""
            type Query {
                getDemos: [Demo]
            }
            
            type Demo {
                id: ID!
                name: String!
            }
            """
        ),
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.ALL
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_15(self):
    # Creating an AppSync GraphQL API with introspection disabled and INFO level logging
    # ok: python_cdk_app_sync_graph_ql_request_logging
    api = appsync.GraphqlApi(
        self, "Api",
        name="demo-api",
        schema=appsync.SchemaFile.from_asset("schema.graphql"),
        introspection_enabled=False,
        log_config=appsync.LogConfig(
            field_log_level=appsync.FieldLogLevel.INFO
        )
    )
    
    # Output the GraphQL API URL
    CfnOutput(self, "GraphQLAPIURL", value=api.graphql_url)
# {/fact}