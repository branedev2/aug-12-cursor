import aws_cdk as cdk
from aws_cdk import aws_apigateway as apigateway
from aws_cdk import aws_lambda as lambda_
from aws_cdk import Stack
from constructs import Construct

# True Positives (Vulnerable Code)

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_1():
    # Creating API Gateway without request validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    lambda_backend = lambda_.Function(stack, "MyFunction", 
                                     runtime=lambda_.Runtime.PYTHON_3_9,
                                     handler="index.handler",
                                     code=lambda_.Code.from_asset("lambda"))
    
    api.root.add_resource("items").add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_backend)
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_2():
    # Creating API Gateway with validation explicitly disabled
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    resource = api.root.add_resource("users")
    
    resource.add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "UserFunction", 
                                                     runtime=lambda_.Runtime.PYTHON_3_9,
                                                     handler="index.handler",
                                                     code=lambda_.Code.from_asset("lambda"))),
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=False,
            validate_request_parameters=False
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_3():
    # Creating API Gateway with only parameter validation but not body validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    resource = api.root.add_resource("products")
    
    resource.add_method(
        "PUT", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "ProductFunction", 
                                                     runtime=lambda_.Runtime.PYTHON_3_9,
                                                     handler="index.handler",
                                                     code=lambda_.Code.from_asset("lambda"))),
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=False,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_4():
    # Creating API Gateway with only body validation but not parameter validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    resource = api.root.add_resource("orders")
    
    resource.add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "OrderFunction", 
                                                     runtime=lambda_.Runtime.PYTHON_3_9,
                                                     handler="index.handler",
                                                     code=lambda_.Code.from_asset("lambda"))),
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=False
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_5():
    # Creating multiple resources without validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    lambda_func = lambda_.Function(stack, "BackendFunction", 
                                  runtime=lambda_.Runtime.PYTHON_3_9,
                                  handler="index.handler",
                                  code=lambda_.Code.from_asset("lambda"))
    
    users = api.root.add_resource("users")
    users.add_method("GET", apigateway.LambdaIntegration(lambda_func))
    users.add_method("POST", apigateway.LambdaIntegration(lambda_func))

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_6():
    # Creating API Gateway with request models but no validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    model = api.add_model("UserModel", 
        content_type="application/json",
        model_name="UserModel",
        schema=apigateway.JsonSchema(
            type=apigateway.JsonSchemaType.OBJECT,
            properties={
                "name": apigateway.JsonSchema(type=apigateway.JsonSchemaType.STRING),
                "email": apigateway.JsonSchema(type=apigateway.JsonSchemaType.STRING)
            },
            required=["name", "email"]
        )
    )
    
    api.root.add_resource("users").add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "UserFunction", 
                                                     runtime=lambda_.Runtime.PYTHON_3_9,
                                                     handler="index.handler",
                                                     code=lambda_.Code.from_asset("lambda"))),
        request_models={"application/json": model}
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_7():
    # Creating API Gateway with proxy integration but no validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    lambda_func = lambda_.Function(stack, "ProxyFunction", 
                                  runtime=lambda_.Runtime.PYTHON_3_9,
                                  handler="index.handler",
                                  code=lambda_.Code.from_asset("lambda"))
    
    api.root.add_proxy(
        default_integration=apigateway.LambdaIntegration(lambda_func),
        any_method=True
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_8():
    # Creating API Gateway with custom domain but no validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        domain_name=apigateway.DomainNameOptions(
            domain_name="api.example.com",
            certificate=apigateway.Certificate.from_certificate_arn(
                stack, "Cert", "arn:aws:acm:us-east-1:123456789012:certificate/my-cert"
            )
        ),
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    lambda_func = lambda_.Function(stack, "ApiFunction", 
                                  runtime=lambda_.Runtime.PYTHON_3_9,
                                  handler="index.handler",
                                  code=lambda_.Code.from_asset("lambda"))
    
    api.root.add_resource("data").add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_func)
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_9():
    # Creating API Gateway with authorization but no validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    authorizer = apigateway.RequestAuthorizer(
        stack, "ApiAuthorizer",
        handler=lambda_.Function(stack, "AuthFunction", 
                               runtime=lambda_.Runtime.PYTHON_3_9,
                               handler="index.handler",
                               code=lambda_.Code.from_asset("lambda")),
        identity_sources=["method.request.header.Authorization"]
    )
    
    api.root.add_resource("secure").add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "SecureFunction", 
                                                    runtime=lambda_.Runtime.PYTHON_3_9,
                                                    handler="index.handler",
                                                    code=lambda_.Code.from_asset("lambda"))),
        authorizer=authorizer
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_10():
    # Creating API Gateway with CORS but no validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    resource = api.root.add_resource("cors-enabled")
    resource.add_cors_preflight(
        allow_origins=["*"],
        allow_methods=["GET", "POST", "PUT"],
        allow_headers=["Content-Type", "Authorization"]
    )
    
    resource.add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "CorsFunction", 
                                                    runtime=lambda_.Runtime.PYTHON_3_9,
                                                    handler="index.handler",
                                                    code=lambda_.Code.from_asset("lambda")))
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_11():
    # Creating API Gateway with API key but no validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    plan = api.add_usage_plan("UsagePlan",
        name="Standard",
        throttle=apigateway.ThrottleSettings(
            rate_limit=10,
            burst_limit=2
        )
    )
    
    key = api.add_api_key("ApiKey")
    plan.add_api_key(key)
    
    api.root.add_resource("protected").add_method(
        "GET", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "ProtectedFunction", 
                                                    runtime=lambda_.Runtime.PYTHON_3_9,
                                                    handler="index.handler",
                                                    code=lambda_.Code.from_asset("lambda"))),
        api_key_required=True
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_12():
    # Creating API Gateway with method responses but no request validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    resource = api.root.add_resource("responses")
    
    resource.add_method(
        "POST", 
        apigateway.LambdaIntegration(
            lambda_.Function(stack, "ResponseFunction", 
                           runtime=lambda_.Runtime.PYTHON_3_9,
                           handler="index.handler",
                           code=lambda_.Code.from_asset("lambda")),
            integration_responses=[
                apigateway.IntegrationResponse(
                    status_code="200",
                    response_templates={"application/json": ""}
                ),
                apigateway.IntegrationResponse(
                    status_code="400",
                    selection_pattern=".*Error.*",
                    response_templates={"application/json": "{'error': $input.path('$.errorMessage')}"}
                )
            ]
        ),
        method_responses=[
            apigateway.MethodResponse(status_code="200"),
            apigateway.MethodResponse(status_code="400")
        ]
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_13():
    # Creating API Gateway with request parameters but no validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    resource = api.root.add_resource("search")
    
    resource.add_method(
        "GET", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "SearchFunction", 
                                                    runtime=lambda_.Runtime.PYTHON_3_9,
                                                    handler="index.handler",
                                                    code=lambda_.Code.from_asset("lambda"))),
        request_parameters={
            "method.request.querystring.query": True,
            "method.request.querystring.limit": False
        }
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_14():
    # Creating API Gateway with mock integration but no validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    mock_integration = apigateway.MockIntegration(
        integration_responses=[{
            "statusCode": "200",
            "responseTemplates": {
                "application/json": '{"status": "ok"}'
            }
        }]
    )
    
    api.root.add_resource("mock").add_method(
        "GET", 
        mock_integration,
        method_responses=[{
            "statusCode": "200",
            "responseModels": {
                "application/json": apigateway.Model.EMPTY_MODEL
            }
        }]
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_15():
    # Creating API Gateway with HTTP integration but no validation
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ruleid: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    http_integration = apigateway.HttpIntegration(
        "https://api.example.com/data",
        http_method="GET",
        options=apigateway.IntegrationOptions(
            request_parameters={
                "integration.request.header.Content-Type": "'application/json'"
            }
        )
    )
    
    api.root.add_resource("external").add_method(
        "GET", 
        http_integration
    )

# True Negatives (Secure Code)

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_1():
    # Creating API Gateway with both request validations enabled
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    resource = api.root.add_resource("items")
    
    resource.add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "ItemFunction", 
                                                    runtime=lambda_.Runtime.PYTHON_3_9,
                                                    handler="index.handler",
                                                    code=lambda_.Code.from_asset("lambda"))),
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_2():
    # Creating API Gateway with validation and request models
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    model = api.add_model("UserModel", 
        content_type="application/json",
        model_name="UserModel",
        schema=apigateway.JsonSchema(
            type=apigateway.JsonSchemaType.OBJECT,
            properties={
                "name": apigateway.JsonSchema(type=apigateway.JsonSchemaType.STRING),
                "email": apigateway.JsonSchema(type=apigateway.JsonSchemaType.STRING)
            },
            required=["name", "email"]
        )
    )
    
    api.root.add_resource("users").add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "UserFunction", 
                                                    runtime=lambda_.Runtime.PYTHON_3_9,
                                                    handler="index.handler",
                                                    code=lambda_.Code.from_asset("lambda"))),
        request_models={"application/json": model},
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_3():
    # Creating API Gateway with validation and request parameters
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    resource = api.root.add_resource("search")
    
    resource.add_method(
        "GET", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "SearchFunction", 
                                                    runtime=lambda_.Runtime.PYTHON_3_9,
                                                    handler="index.handler",
                                                    code=lambda_.Code.from_asset("lambda"))),
        request_parameters={
            "method.request.querystring.query": True,
            "method.request.querystring.limit": False
        },
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_4():
    # Creating API Gateway with validation and authorization
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    authorizer = apigateway.RequestAuthorizer(
        stack, "ApiAuthorizer",
        handler=lambda_.Function(stack, "AuthFunction", 
                               runtime=lambda_.Runtime.PYTHON_3_9,
                               handler="index.handler",
                               code=lambda_.Code.from_asset("lambda")),
        identity_sources=["method.request.header.Authorization"]
    )
    
    api.root.add_resource("secure").add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "SecureFunction", 
                                                    runtime=lambda_.Runtime.PYTHON_3_9,
                                                    handler="index.handler",
                                                    code=lambda_.Code.from_asset("lambda"))),
        authorizer=authorizer,
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_5():
    # Creating API Gateway with validation and CORS
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    resource = api.root.add_resource("cors-enabled")
    resource.add_cors_preflight(
        allow_origins=["*"],
        allow_methods=["GET", "POST", "PUT"],
        allow_headers=["Content-Type", "Authorization"]
    )
    
    resource.add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "CorsFunction", 
                                                    runtime=lambda_.Runtime.PYTHON_3_9,
                                                    handler="index.handler",
                                                    code=lambda_.Code.from_asset("lambda"))),
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_6():
    # Creating API Gateway with validation and API key
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    plan = api.add_usage_plan("UsagePlan",
        name="Standard",
        throttle=apigateway.ThrottleSettings(
            rate_limit=10,
            burst_limit=2
        )
    )
    
    key = api.add_api_key("ApiKey")
    plan.add_api_key(key)
    
    api.root.add_resource("protected").add_method(
        "GET", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "ProtectedFunction", 
                                                    runtime=lambda_.Runtime.PYTHON_3_9,
                                                    handler="index.handler",
                                                    code=lambda_.Code.from_asset("lambda"))),
        api_key_required=True,
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_7():
    # Creating API Gateway with validation and method responses
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    resource = api.root.add_resource("responses")
    
    resource.add_method(
        "POST", 
        apigateway.LambdaIntegration(
            lambda_.Function(stack, "ResponseFunction", 
                           runtime=lambda_.Runtime.PYTHON_3_9,
                           handler="index.handler",
                           code=lambda_.Code.from_asset("lambda")),
            integration_responses=[
                apigateway.IntegrationResponse(
                    status_code="200",
                    response_templates={"application/json": ""}
                ),
                apigateway.IntegrationResponse(
                    status_code="400",
                    selection_pattern=".*Error.*",
                    response_templates={"application/json": "{'error': $input.path('$.errorMessage')}"}
                )
            ]
        ),
        method_responses=[
            apigateway.MethodResponse(status_code="200"),
            apigateway.MethodResponse(status_code="400")
        ],
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_8():
    # Creating API Gateway with validation and multiple methods
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    lambda_func = lambda_.Function(stack, "BackendFunction", 
                                  runtime=lambda_.Runtime.PYTHON_3_9,
                                  handler="index.handler",
                                  code=lambda_.Code.from_asset("lambda"))
    
    users = api.root.add_resource("users")
    
    validator_options = apigateway.RequestValidatorOptions(
        validate_request_body=True,
        validate_request_parameters=True
    )
    
    users.add_method("GET", apigateway.LambdaIntegration(lambda_func), 
                    request_validator_options=validator_options)
    users.add_method("POST", apigateway.LambdaIntegration(lambda_func), 
                    request_validator_options=validator_options)

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_9():
    # Creating API Gateway with validation and custom domain
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        domain_name=apigateway.DomainNameOptions(
            domain_name="api.example.com",
            certificate=apigateway.Certificate.from_certificate_arn(
                stack, "Cert", "arn:aws:acm:us-east-1:123456789012:certificate/my-cert"
            )
        ),
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    lambda_func = lambda_.Function(stack, "ApiFunction", 
                                  runtime=lambda_.Runtime.PYTHON_3_9,
                                  handler="index.handler",
                                  code=lambda_.Code.from_asset("lambda"))
    
    api.root.add_resource("data").add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_func),
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_10():
    # Creating API Gateway with validation and mock integration
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    mock_integration = apigateway.MockIntegration(
        integration_responses=[{
            "statusCode": "200",
            "responseTemplates": {
                "application/json": '{"status": "ok"}'
            }
        }]
    )
    
    api.root.add_resource("mock").add_method(
        "GET", 
        mock_integration,
        method_responses=[{
            "statusCode": "200",
            "responseModels": {
                "application/json": apigateway.Model.EMPTY_MODEL
            }
        }],
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_11():
    # Creating API Gateway with validation and HTTP integration
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    http_integration = apigateway.HttpIntegration(
        "https://api.example.com/data",
        http_method="GET",
        options=apigateway.IntegrationOptions(
            request_parameters={
                "integration.request.header.Content-Type": "'application/json'"
            }
        )
    )
    
    api.root.add_resource("external").add_method(
        "GET", 
        http_integration,
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_12():
    # Creating API Gateway with validation and request models for multiple content types
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    json_model = api.add_model("JsonModel", 
        content_type="application/json",
        model_name="JsonModel",
        schema=apigateway.JsonSchema(
            type=apigateway.JsonSchemaType.OBJECT,
            properties={
                "name": apigateway.JsonSchema(type=apigateway.JsonSchemaType.STRING),
                "age": apigateway.JsonSchema(type=apigateway.JsonSchemaType.INTEGER)
            }
        )
    )
    
    xml_model = api.add_model("XmlModel", 
        content_type="application/xml",
        model_name="XmlModel",
        schema=apigateway.JsonSchema(
            type=apigateway.JsonSchemaType.OBJECT,
            properties={
                "user": apigateway.JsonSchema(type=apigateway.JsonSchemaType.STRING)
            }
        )
    )
    
    api.root.add_resource("multi-format").add_method(
        "POST", 
        apigateway.LambdaIntegration(lambda_.Function(stack, "MultiFormatFunction", 
                                                    runtime=lambda_.Runtime.PYTHON_3_9,
                                                    handler="index.handler",
                                                    code=lambda_.Code.from_asset("lambda"))),
        request_models={
            "application/json": json_model,
            "application/xml": xml_model
        },
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_13():
    # Creating API Gateway with validation and nested resources
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    lambda_func = lambda_.Function(stack, "NestedFunction", 
                                  runtime=lambda_.Runtime.PYTHON_3_9,
                                  handler="index.handler",
                                  code=lambda_.Code.from_asset("lambda"))
    
    validator_options = apigateway.RequestValidatorOptions(
        validate_request_body=True,
        validate_request_parameters=True
    )
    
    users = api.root.add_resource("users")
    user_id = users.add_resource("{userId}")
    orders = user_id.add_resource("orders")
    
    orders.add_method(
        "GET", 
        apigateway.LambdaIntegration(lambda_func),
        request_parameters={
            "method.request.path.userId": True
        },
        request_validator_options=validator_options
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_14():
    # Creating API Gateway with validation and integration request templates
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    integration = apigateway.LambdaIntegration(
        lambda_.Function(stack, "TemplateFunction", 
                       runtime=lambda_.Runtime.PYTHON_3_9,
                       handler="index.handler",
                       code=lambda_.Code.from_asset("lambda")),
        request_templates={
            "application/json": '{"action": "create", "body": $input.json("$")}'
        }
    )
    
    api.root.add_resource("transform").add_method(
        "POST", 
        integration,
        request_validator_options=apigateway.RequestValidatorOptions(
            validate_request_body=True,
            validate_request_parameters=True
        )
    )

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_15():
    # Creating API Gateway with validation and proxy resource
    app = cdk.App()
    stack = Stack(app, "MyStack")
    
    # ok: python-cdk-apigateway-missingreq-validation-enabled
    api = apigateway.RestApi(
        stack, 
        "MyApi",
        deploy_options=apigateway.StageOptions(
            stage_name="prod"
        )
    )
    
    lambda_func = lambda_.Function(stack, "ProxyFunction", 
                                  runtime=lambda_.Runtime.PYTHON_3_9,
                                  handler="index.handler",
                                  code=lambda_.Code.from_asset("lambda"))
    
    validator_options = apigateway.RequestValidatorOptions(
        validate_request_body=True,
        validate_request_parameters=True
    )
    
    # Add a specific resource with validation
    api_resource = api.root.add_resource("api")
    
    # Add proxy resource with validation
    proxy = api_resource.add_resource("{proxy+}")
    proxy.add_method(
        "ANY", 
        apigateway.LambdaIntegration(lambda_func),
        request_validator_options=validator_options
    )
# {/fact}