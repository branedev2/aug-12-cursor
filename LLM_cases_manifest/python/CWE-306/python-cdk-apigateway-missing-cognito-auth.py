import aws_cdk as cdk
from aws_cdk import (
    aws_apigateway as apigateway,
    aws_cognito as cognito,
    aws_lambda as lambda_,
    Stack
)
from constructs import Construct

# True Positives (Vulnerable Code Examples)

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating an API without any authorization
    api = apigateway.RestApi(scope, "MyApi")
    
    # Creating a Lambda function for backend
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Creating a method without Cognito authorization
    api.root.add_method("GET", apigateway.LambdaIntegration(backend))

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating an API with no authorization
    api = apigateway.RestApi(scope, "MySecureApi")
    
    # Creating a resource
    items = api.root.add_resource("items")
    
    # Creating a Lambda function
    get_items = lambda_.Function(scope, "GetItems",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Using NONE as authorization type
    items.add_method("GET", apigateway.LambdaIntegration(get_items), 
                    authorization_type=apigateway.AuthorizationType.NONE)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating API with a resource
    api = apigateway.RestApi(scope, "UserApi")
    users = api.root.add_resource("users")
    
    # Lambda function
    user_function = lambda_.Function(scope, "UserFunction",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Using IAM authorization instead of Cognito
    users.add_method("POST", apigateway.LambdaIntegration(user_function),
                    authorization_type=apigateway.AuthorizationType.IAM)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating API with multiple resources
    api = apigateway.RestApi(scope, "ProductApi")
    products = api.root.add_resource("products")
    product = products.add_resource("{id}")
    
    # Lambda function
    get_product = lambda_.Function(scope, "GetProduct",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # No authorization specified (defaults to NONE)
    product.add_method("GET", apigateway.LambdaIntegration(get_product))

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating API with custom domain
    api = apigateway.RestApi(scope, "CustomDomainApi",
        domain_name=apigateway.DomainNameOptions(
            domain_name="api.example.com",
            certificate=None  # Certificate would be defined in real code
        )
    )
    
    # Lambda function
    lambda_backend = lambda_.Function(scope, "LambdaBackend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Using custom authorizer instead of Cognito
    custom_auth = apigateway.RequestAuthorizer(scope, "CustomAuthorizer",
        handler=lambda_backend,
        identity_sources=[apigateway.IdentitySource.header("Authorization")]
    )
    
    api.root.add_method("GET", apigateway.LambdaIntegration(lambda_backend),
                       authorizer=custom_auth)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating API with Lambda proxy integration
    api = apigateway.RestApi(scope, "ProxyApi")
    
    # Lambda function
    proxy_function = lambda_.Function(scope, "ProxyFunction",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Using proxy integration without authorization
    api.root.add_proxy(
        default_integration=apigateway.LambdaIntegration(proxy_function)
    )

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating API with mock integration
    api = apigateway.RestApi(scope, "MockApi")
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Using mock integration without authorization
    api.root.add_method("GET", 
        apigateway.MockIntegration(
            integration_responses=[{
                'statusCode': '200',
                'responseTemplates': {
                    'application/json': '{"message": "Hello, world!"}'
                }
            }]
        )
    )

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating API with HTTP integration
    api = apigateway.RestApi(scope, "HttpIntegrationApi")
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Using HTTP integration without authorization
    api.root.add_method("GET", 
        apigateway.HttpIntegration("https://api.example.com",
            http_method="GET"
        )
    )

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating API with AWS integration
    api = apigateway.RestApi(scope, "AwsIntegrationApi")
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Using AWS service integration without authorization
    api.root.add_method("GET", 
        apigateway.AwsIntegration(
            service="dynamodb",
            action="GetItem",
            options=apigateway.IntegrationOptions(
                credentials_role=None  # Role would be defined in real code
            )
        )
    )

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating API with multiple methods
    api = apigateway.RestApi(scope, "MultiMethodApi")
    resource = api.root.add_resource("resource")
    
    # Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Adding multiple methods without authorization
    resource.add_method("GET", apigateway.LambdaIntegration(backend))
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    resource.add_method("POST", apigateway.LambdaIntegration(backend))

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating API with options method
    api = apigateway.RestApi(scope, "OptionsApi")
    
    # Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Adding OPTIONS method without authorization
    api.root.add_method("OPTIONS", apigateway.LambdaIntegration(backend))

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating API with CORS
    api = apigateway.RestApi(scope, "CorsApi")
    
    # Adding CORS options
    resource = api.root.add_resource("resource")
    resource.add_cors_preflight(
        allow_origins=["*"],
        allow_methods=["GET", "POST"]
    )
    
    # Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Adding method without authorization
    resource.add_method("GET", apigateway.LambdaIntegration(backend))

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating API with API key
    api = apigateway.RestApi(scope, "ApiKeyApi")
    
    # Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Using API key instead of Cognito
    api.root.add_method("GET", apigateway.LambdaIntegration(backend),
                       api_key_required=True)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating API with stage options
    api = apigateway.RestApi(scope, "StageApi")
    
    # Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Adding method without authorization
    api.root.add_method("GET", apigateway.LambdaIntegration(backend))
    
    # Deployment with stage
    deployment = apigateway.Deployment(scope, "Deployment", api=api)
    apigateway.Stage(scope, "Stage",
        deployment=deployment,
        stage_name="prod",
        logging_level=apigateway.MethodLoggingLevel.INFO
    )

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating API with method options
    api = apigateway.RestApi(scope, "MethodOptionsApi")
    
    # Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ruleid: python-cdk-apigateway-missing-cognito-auth
    # Adding method with options but no authorization
    api.root.add_method("GET", apigateway.LambdaIntegration(backend),
                       method_responses=[
                           apigateway.MethodResponse(
                               status_code="200",
                               response_models={
                                   "application/json": apigateway.Model.EMPTY_MODEL
                               }
                           )
                       ])

# True Negatives (Secure Code Examples)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating API with Cognito authorizer
    api = apigateway.RestApi(scope, "SecureApi")
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a user pool client
    user_pool_client = cognito.UserPoolClient(scope, "UserPoolClient",
        user_pool=user_pool
    )
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # Creating a Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization
    api.root.add_method("GET", apigateway.LambdaIntegration(backend),
                       authorizer=auth,
                       authorization_type=apigateway.AuthorizationType.COGNITO)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating API with Cognito authorizer for a resource
    api = apigateway.RestApi(scope, "ResourceSecureApi")
    
    # Creating a resource
    items = api.root.add_resource("items")
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # Creating a Lambda function
    get_items = lambda_.Function(scope, "GetItems",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization for resource method
    items.add_method("GET", apigateway.LambdaIntegration(get_items),
                    authorizer=auth,
                    authorization_type=apigateway.AuthorizationType.COGNITO)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating API with Cognito authorizer for multiple methods
    api = apigateway.RestApi(scope, "MultiMethodSecureApi")
    
    # Creating a resource
    users = api.root.add_resource("users")
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # Creating Lambda functions
    get_users = lambda_.Function(scope, "GetUsers",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    create_user = lambda_.Function(scope, "CreateUser",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization for GET method
    users.add_method("GET", apigateway.LambdaIntegration(get_users),
                    authorizer=auth,
                    authorization_type=apigateway.AuthorizationType.COGNITO)
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization for POST method
    users.add_method("POST", apigateway.LambdaIntegration(create_user),
                    authorizer=auth,
                    authorization_type=apigateway.AuthorizationType.COGNITO)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating API with Cognito authorizer for nested resources
    api = apigateway.RestApi(scope, "NestedResourceApi")
    
    # Creating nested resources
    products = api.root.add_resource("products")
    product = products.add_resource("{id}")
    reviews = product.add_resource("reviews")
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # Creating a Lambda function
    get_reviews = lambda_.Function(scope, "GetReviews",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization for nested resource
    reviews.add_method("GET", apigateway.LambdaIntegration(get_reviews),
                      authorizer=auth,
                      authorization_type=apigateway.AuthorizationType.COGNITO)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating API with Cognito authorizer and custom domain
    api = apigateway.RestApi(scope, "CustomDomainSecureApi",
        domain_name=apigateway.DomainNameOptions(
            domain_name="api.example.com",
            certificate=None  # Certificate would be defined in real code
        )
    )
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # Creating a Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization with custom domain
    api.root.add_method("GET", apigateway.LambdaIntegration(backend),
                       authorizer=auth,
                       authorization_type=apigateway.AuthorizationType.COGNITO)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating API with Cognito authorizer and method options
    api = apigateway.RestApi(scope, "MethodOptionsSecureApi")
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # Creating a Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization with method options
    api.root.add_method("GET", apigateway.LambdaIntegration(backend),
                       authorizer=auth,
                       authorization_type=apigateway.AuthorizationType.COGNITO,
                       method_responses=[
                           apigateway.MethodResponse(
                               status_code="200",
                               response_models={
                                   "application/json": apigateway.Model.EMPTY_MODEL
                               }
                           )
                       ])

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating API with Cognito authorizer and deployment stage
    api = apigateway.RestApi(scope, "StageSecureApi")
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # Creating a Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization
    api.root.add_method("GET", apigateway.LambdaIntegration(backend),
                       authorizer=auth,
                       authorization_type=apigateway.AuthorizationType.COGNITO)
    
    # Deployment with stage
    deployment = apigateway.Deployment(scope, "Deployment", api=api)
    apigateway.Stage(scope, "Stage",
        deployment=deployment,
        stage_name="prod",
        logging_level=apigateway.MethodLoggingLevel.INFO
    )

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating API with Cognito authorizer and CORS
    api = apigateway.RestApi(scope, "CorsSecureApi")
    
    # Creating a resource
    resource = api.root.add_resource("resource")
    
    # Adding CORS options
    resource.add_cors_preflight(
        allow_origins=["https://example.com"],
        allow_methods=["GET", "POST"]
    )
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # Creating a Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization with CORS
    resource.add_method("GET", apigateway.LambdaIntegration(backend),
                       authorizer=auth,
                       authorization_type=apigateway.AuthorizationType.COGNITO)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating API with Cognito authorizer and multiple user pools
    api = apigateway.RestApi(scope, "MultiPoolApi")
    
    # Creating user pools
    user_pool1 = cognito.UserPool(scope, "UserPool1")
    user_pool2 = cognito.UserPool(scope, "UserPool2")
    
    # Creating a Cognito authorizer with multiple pools
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool1, user_pool2]
    )
    
    # Creating a Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization with multiple pools
    api.root.add_method("GET", apigateway.LambdaIntegration(backend),
                       authorizer=auth,
                       authorization_type=apigateway.AuthorizationType.COGNITO)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating API with Cognito authorizer and HTTP integration
    api = apigateway.RestApi(scope, "HttpIntegrationSecureApi")
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization with HTTP integration
    api.root.add_method("GET", 
        apigateway.HttpIntegration("https://api.example.com",
            http_method="GET"
        ),
        authorizer=auth,
        authorization_type=apigateway.AuthorizationType.COGNITO
    )

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating API with Cognito authorizer and AWS integration
    api = apigateway.RestApi(scope, "AwsIntegrationSecureApi")
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization with AWS integration
    api.root.add_method("GET", 
        apigateway.AwsIntegration(
            service="dynamodb",
            action="GetItem",
            options=apigateway.IntegrationOptions(
                credentials_role=None  # Role would be defined in real code
            )
        ),
        authorizer=auth,
        authorization_type=apigateway.AuthorizationType.COGNITO
    )

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating API with Cognito authorizer and mock integration
    api = apigateway.RestApi(scope, "MockIntegrationSecureApi")
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization with mock integration
    api.root.add_method("GET", 
        apigateway.MockIntegration(
            integration_responses=[{
                'statusCode': '200',
                'responseTemplates': {
                    'application/json': '{"message": "Hello, world!"}'
                }
            }]
        ),
        authorizer=auth,
        authorization_type=apigateway.AuthorizationType.COGNITO
    )

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating API with Cognito authorizer and API key
    api = apigateway.RestApi(scope, "ApiKeySecureApi")
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # Creating a Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization with API key
    api.root.add_method("GET", apigateway.LambdaIntegration(backend),
                       authorizer=auth,
                       authorization_type=apigateway.AuthorizationType.COGNITO,
                       api_key_required=True)

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating API with Cognito authorizer and custom authorizer scopes
    api = apigateway.RestApi(scope, "ScopesSecureApi")
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer with scopes
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # Creating a Lambda function
    backend = lambda_.Function(scope, "Backend",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization with authorization scopes
    api.root.add_method("GET", apigateway.LambdaIntegration(backend),
                       authorizer=auth,
                       authorization_type=apigateway.AuthorizationType.COGNITO,
                       authorization_scopes=["read:items", "write:items"])

# {/fact}

# {fact rule=check-eagle-handler-and-authn-handler-ordering@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating API with Cognito authorizer and proxy integration
    api = apigateway.RestApi(scope, "ProxySecureApi")
    
    # Creating a user pool
    user_pool = cognito.UserPool(scope, "UserPool")
    
    # Creating a Cognito authorizer
    auth = apigateway.CognitoUserPoolsAuthorizer(scope, "CognitoAuthorizer",
        cognito_user_pools=[user_pool]
    )
    
    # Creating a Lambda function
    proxy_function = lambda_.Function(scope, "ProxyFunction",
        runtime=lambda_.Runtime.PYTHON_3_9,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    # Creating a resource
    resource = api.root.add_resource("{proxy+}")
    
    # ok: python-cdk-apigateway-missing-cognito-auth
    # Using Cognito authorization with proxy integration
    resource.add_method("ANY", apigateway.LambdaIntegration(proxy_function),
                      authorizer=auth,
                      authorization_type=apigateway.AuthorizationType.COGNITO)
# {/fact}