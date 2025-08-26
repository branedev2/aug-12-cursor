import aws_cdk as cdk
from aws_cdk import (
    aws_lambda as lambda_,
    Stack,
    Duration,
    CfnOutput
)
from constructs import Construct

# True Positives (Vulnerable Code - Using outdated Lambda runtimes)

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction1",
        runtime=lambda_.Runtime.PYTHON_3_7,  # Using outdated Python 3.7 runtime
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda"),
        timeout=Duration.seconds(30)
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction2",
        runtime=lambda_.Runtime.NODEJS_12_X,  # Using outdated Node.js 12.x runtime
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda"),
        memory_size=512
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction3",
        runtime=lambda_.Runtime.JAVA_8,  # Using outdated Java 8 runtime
        handler="com.example.Handler",
        code=lambda_.Code.from_asset("lambda.jar"),
        environment={
            "ENV": "production"
        }
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction4",
        runtime=lambda_.Runtime.DOTNET_CORE_3_1,  # Using outdated .NET Core 3.1 runtime
        handler="MyFunction::Function.Handler",
        code=lambda_.Code.from_asset("lambda"),
        timeout=Duration.minutes(5)
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction5",
        runtime=lambda_.Runtime.GO_1_X,  # Using outdated Go 1.x runtime
        handler="main",
        code=lambda_.Code.from_asset("lambda"),
        memory_size=1024
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a Lambda function with hardcoded outdated runtime
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction6",
        runtime=lambda_.Runtime.RUBY_2_7,  # Using outdated Ruby 2.7 runtime
        handler="app.handler",
        code=lambda_.Code.from_asset("lambda"),
        timeout=Duration.seconds(60)
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    props = {
        "runtime": lambda_.Runtime.PYTHON_3_8,  # Using outdated Python 3.8 runtime
        "handler": "index.handler",
        "code": lambda_.Code.from_asset("lambda")
    }
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction7",
        **props
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    runtime_version = lambda_.Runtime.NODEJS_14_X  # Using outdated Node.js 14.x runtime
    
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction8",
        runtime=runtime_version,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda"),
        timeout=Duration.seconds(30)
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.DockerImageFunction(
        scope,
        "MyDockerFunction1",
        code=lambda_.DockerImageCode.from_image_asset("./docker-image"),
        timeout=Duration.seconds(30),
        memory_size=512,
        architecture=lambda_.Architecture.X86_64,
        runtime_management_mode=lambda_.RuntimeManagementMode.FUNCTION_UPDATE,
        environment={"RUNTIME": "python3.7"}  # Indicating outdated runtime in environment
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Using a function alias with an outdated runtime
    fn = lambda_.Function(
        scope,
        "VersionedFunction",
        runtime=lambda_.Runtime.PYTHON_3_7,  # Using outdated Python 3.7 runtime
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda"),
    )
    
    # ruleid: python-cdk-lambda-latest-version
    version = fn.current_version
    alias = lambda_.Alias(
        scope,
        "FunctionAlias",
        alias_name="prod",
        version=version
    )
    return alias

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a Lambda function with custom runtime but indicating outdated version
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction11",
        runtime=lambda_.Runtime.PROVIDED,
        handler="bootstrap",
        code=lambda_.Code.from_asset("lambda"),
        environment={
            "CUSTOM_RUNTIME_VERSION": "python3.7"  # Indicating outdated Python version
        }
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Using a Lambda Layer with an outdated runtime
    layer = lambda_.LayerVersion(
        scope,
        "MyLayer",
        code=lambda_.Code.from_asset("layer"),
        compatible_runtimes=[
            lambda_.Runtime.PYTHON_3_7,  # Outdated Python 3.7 runtime
            lambda_.Runtime.PYTHON_3_8   # Outdated Python 3.8 runtime
        ]
    )
    
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope,
        "MyFunction12",
        runtime=lambda_.Runtime.PYTHON_3_7,  # Using outdated Python 3.7 runtime
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda"),
        layers=[layer]
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Using a Lambda function with event source mapping and outdated runtime
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope,
        "MyFunction13",
        runtime=lambda_.Runtime.NODEJS_10_X,  # Using very outdated Node.js 10.x runtime
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    event_source = lambda_.EventSourceMapping(
        scope,
        "MyEventSource",
        target=lambda_function,
        event_source_arn="arn:aws:dynamodb:region:account:table/my-table/stream/timestamp",
        starting_position=lambda_.StartingPosition.LATEST
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Using a Lambda function with URL and outdated runtime
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope,
        "MyFunction14",
        runtime=lambda_.Runtime.JAVA_8_CORRETTO,  # Using outdated Java 8 Corretto runtime
        handler="com.example.Handler",
        code=lambda_.Code.from_asset("lambda.jar")
    )
    
    function_url = lambda_function.add_function_url(
        auth_type=lambda_.FunctionUrlAuthType.NONE
    )
    
    CfnOutput(scope, "FunctionUrl", value=function_url.url)
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Using a Lambda function with provisioned concurrency and outdated runtime
    # ruleid: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope,
        "MyFunction15",
        runtime=lambda_.Runtime.DOTNET_6,  # Using outdated .NET 6 runtime
        handler="MyFunction::Function.Handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    version = lambda_function.current_version
    alias = lambda_.Alias(
        scope,
        "LiveAlias",
        alias_name="live",
        version=version,
        provisioned_concurrent_executions=10
    )
    return lambda_function

# True Negatives (Secure Code - Using latest Lambda runtimes)

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction1",
        runtime=lambda_.Runtime.PYTHON_3_12,  # Using latest Python runtime
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda"),
        timeout=Duration.seconds(30)
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction2",
        runtime=lambda_.Runtime.NODEJS_20_X,  # Using latest Node.js runtime
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda"),
        memory_size=512
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction3",
        runtime=lambda_.Runtime.JAVA_21,  # Using latest Java runtime
        handler="com.example.Handler",
        code=lambda_.Code.from_asset("lambda.jar"),
        environment={
            "ENV": "production"
        }
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction4",
        runtime=lambda_.Runtime.DOTNET_8,  # Using latest .NET runtime
        handler="MyFunction::Function.Handler",
        code=lambda_.Code.from_asset("lambda"),
        timeout=Duration.minutes(5)
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction5",
        runtime=lambda_.Runtime.GO_1_X,  # Using latest Go runtime (assuming GO_1_X is the latest available in CDK)
        handler="main",
        code=lambda_.Code.from_asset("lambda"),
        memory_size=1024
    )
    # Note: In a real implementation, we would use the latest Go runtime constant available in CDK
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction6",
        runtime=lambda_.Runtime.RUBY_3_2,  # Using latest Ruby runtime
        handler="app.handler",
        code=lambda_.Code.from_asset("lambda"),
        timeout=Duration.seconds(60)
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Using a variable to store the latest runtime
    latest_runtime = lambda_.Runtime.PYTHON_3_12  # Latest Python runtime
    
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction7",
        runtime=latest_runtime,
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda"),
        timeout=Duration.seconds(30)
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Using container image without specifying runtime (automatically uses latest)
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.DockerImageFunction(
        scope,
        "MyDockerFunction",
        code=lambda_.DockerImageCode.from_image_asset("./docker-image"),
        timeout=Duration.seconds(30),
        memory_size=512
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Using a function with the latest runtime and an alias
    # ok: python-cdk-lambda-latest-version
    fn = lambda_.Function(
        scope,
        "VersionedFunction",
        runtime=lambda_.Runtime.PYTHON_3_12,  # Latest Python runtime
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda"),
    )
    
    version = fn.current_version
    alias = lambda_.Alias(
        scope,
        "FunctionAlias",
        alias_name="prod",
        version=version
    )
    return alias

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Using a Lambda Layer with the latest runtimes
    layer = lambda_.LayerVersion(
        scope,
        "MyLayer",
        code=lambda_.Code.from_asset("layer"),
        compatible_runtimes=[
            lambda_.Runtime.PYTHON_3_12,  # Latest Python runtime
            lambda_.Runtime.NODEJS_20_X   # Latest Node.js runtime
        ]
    )
    
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope,
        "MyFunction10",
        runtime=lambda_.Runtime.PYTHON_3_12,  # Latest Python runtime
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda"),
        layers=[layer]
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Using a Lambda function with event source mapping and latest runtime
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope,
        "MyFunction11",
        runtime=lambda_.Runtime.NODEJS_20_X,  # Latest Node.js runtime
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    event_source = lambda_.EventSourceMapping(
        scope,
        "MyEventSource",
        target=lambda_function,
        event_source_arn="arn:aws:dynamodb:region:account:table/my-table/stream/timestamp",
        starting_position=lambda_.StartingPosition.LATEST
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Using a Lambda function with URL and latest runtime
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope,
        "MyFunction12",
        runtime=lambda_.Runtime.JAVA_21,  # Latest Java runtime
        handler="com.example.Handler",
        code=lambda_.Code.from_asset("lambda.jar")
    )
    
    function_url = lambda_function.add_function_url(
        auth_type=lambda_.FunctionUrlAuthType.NONE
    )
    
    CfnOutput(scope, "FunctionUrl", value=function_url.url)
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Using a Lambda function with provisioned concurrency and latest runtime
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope,
        "MyFunction13",
        runtime=lambda_.Runtime.DOTNET_8,  # Latest .NET runtime
        handler="MyFunction::Function.Handler",
        code=lambda_.Code.from_asset("lambda")
    )
    
    version = lambda_function.current_version
    alias = lambda_.Alias(
        scope,
        "LiveAlias",
        alias_name="live",
        version=version,
        provisioned_concurrent_executions=10
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Using a custom runtime with latest version indicated
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope, 
        "MyFunction14",
        runtime=lambda_.Runtime.PROVIDED_AL2023,  # Using latest Amazon Linux 2023 custom runtime
        handler="bootstrap",
        code=lambda_.Code.from_asset("lambda"),
        environment={
            "CUSTOM_RUNTIME_VERSION": "python3.12"  # Indicating latest Python version
        }
    )
    return lambda_function

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Using a function with dynamic runtime selection based on environment variable
    import os
    
    # Function to get the latest runtime based on language
    def get_latest_runtime(language: str):
        if language == "python":
            return lambda_.Runtime.PYTHON_3_12
        elif language == "node":
            return lambda_.Runtime.NODEJS_20_X
        elif language == "java":
            return lambda_.Runtime.JAVA_21
        else:
            return lambda_.Runtime.PYTHON_3_12  # Default to latest Python
    
    # Get runtime from environment or use latest Python
    runtime_language = os.environ.get("LAMBDA_LANGUAGE", "python")
    latest_runtime = get_latest_runtime(runtime_language)
    
    # ok: python-cdk-lambda-latest-version
    lambda_function = lambda_.Function(
        scope,
        "MyFunction15",
        runtime=latest_runtime,  # Using dynamically selected latest runtime
        handler="index.handler",
        code=lambda_.Code.from_asset("lambda")
    )
    return lambda_function
# {/fact}