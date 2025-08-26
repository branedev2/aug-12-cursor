import aws_cdk as cdk
from aws_cdk import (
    aws_ec2 as ec2,
    aws_elasticloadbalancing as elb,
    aws_elasticloadbalancingv2 as elbv2,
    Stack,
    App,
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-elb-logging-enabled
    lb = elb.LoadBalancer(
        scope,
        "LB1",
        vpc=vpc,
        internet_facing=True,
    )
    return lb

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-elb-logging-enabled
    lb = elbv2.ApplicationLoadBalancer(
        scope,
        "ALB1",
        vpc=vpc,
        internet_facing=True,
    )
    return lb

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-elb-logging-enabled
    lb = elbv2.NetworkLoadBalancer(
        scope,
        "NLB1",
        vpc=vpc,
        internet_facing=True,
    )
    return lb

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-elb-logging-enabled
    lb = elb.LoadBalancer(
        scope,
        "LB2",
        vpc=vpc,
        internet_facing=True,
        access_logging_policy=None,
    )
    return lb

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # ruleid: python-cdk-elb-logging-enabled
    lb = elbv2.ApplicationLoadBalancer(
        scope,
        "ALB2",
        vpc=vpc,
        internet_facing=True,
        access_logs=None,
    )
    return lb

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_6():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    # ruleid: python-cdk-elb-logging-enabled
    lb = elbv2.ApplicationLoadBalancer(
        stack,
        "ALB3",
        vpc=vpc,
        internet_facing=True,
    )
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_7():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    # ruleid: python-cdk-elb-logging-enabled
    lb = elbv2.NetworkLoadBalancer(
        stack,
        "NLB2",
        vpc=vpc,
        internet_facing=False,  # Even internal LBs should have logging
    )
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_8():
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            vpc = ec2.Vpc(self, "VPC")
            # ruleid: python-cdk-elb-logging-enabled
            lb = elb.LoadBalancer(
                self,
                "LB3",
                vpc=vpc,
                internet_facing=True,
            )
    
    app = App()
    MyStack(app, "MyStack")
    return app

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_9():
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            vpc = ec2.Vpc(self, "VPC")
            # ruleid: python-cdk-elb-logging-enabled
            lb = elbv2.ApplicationLoadBalancer(
                self,
                "ALB4",
                vpc=vpc,
                internet_facing=True,
            )
            
            # Adding a listener but still no logging
            lb.add_listener("Listener", port=80)
    
    app = App()
    MyStack(app, "MyStack")
    return app

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_10():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # Creating multiple load balancers without logging
    # ruleid: python-cdk-elb-logging-enabled
    alb = elbv2.ApplicationLoadBalancer(
        stack,
        "ALB5",
        vpc=vpc,
        internet_facing=True,
    )
    
    # ruleid: python-cdk-elb-logging-enabled
    nlb = elbv2.NetworkLoadBalancer(
        stack,
        "NLB3",
        vpc=vpc,
        internet_facing=True,
    )
    
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_11():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # Creating a load balancer with explicit disabled logging
    # ruleid: python-cdk-elb-logging-enabled
    lb = elbv2.ApplicationLoadBalancer(
        stack,
        "ALB6",
        vpc=vpc,
        internet_facing=True,
        access_logs=elbv2.LoggingAttributes(
            enabled=False,
            bucket=None,
            prefix=None,
        )
    )
    
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_12():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # Creating a load balancer with incomplete logging configuration
    # ruleid: python-cdk-elb-logging-enabled
    lb = elb.LoadBalancer(
        stack,
        "LB4",
        vpc=vpc,
        internet_facing=True,
        access_logging_policy=elb.AccessLoggingPolicy(
            enabled=False,
            s3_bucket_name=None,
            s3_bucket_prefix=None,
        )
    )
    
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_13():
    def create_load_balancer(stack, vpc):
        # ruleid: python-cdk-elb-logging-enabled
        return elbv2.ApplicationLoadBalancer(
            stack,
            "ALB7",
            vpc=vpc,
            internet_facing=True,
        )
    
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    lb = create_load_balancer(stack, vpc)
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_14():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # Creating a load balancer with conditional logging that defaults to none
    enable_logging = False
    
    # ruleid: python-cdk-elb-logging-enabled
    lb = elbv2.ApplicationLoadBalancer(
        stack,
        "ALB8",
        vpc=vpc,
        internet_facing=True,
        access_logs=elbv2.LoggingAttributes(
            enabled=enable_logging,
            bucket=None,
            prefix=None,
        ) if enable_logging else None
    )
    
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_15():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    lb_props = {
        "vpc": vpc,
        "internet_facing": True,
    }
    
    # ruleid: python-cdk-elb-logging-enabled
    lb = elbv2.ApplicationLoadBalancer(
        stack,
        "ALB9",
        **lb_props
    )
    
    return stack

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    bucket = cdk.aws_s3.Bucket(scope, "LogBucket")
    
    # ok: python-cdk-elb-logging-enabled
    lb = elb.LoadBalancer(
        scope,
        "LB1",
        vpc=vpc,
        internet_facing=True,
        access_logging_policy=elb.AccessLoggingPolicy(
            enabled=True,
            s3_bucket_name=bucket.bucket_name,
            s3_bucket_prefix="elb-logs",
        )
    )
    return lb

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    bucket = cdk.aws_s3.Bucket(scope, "LogBucket")
    
    # ok: python-cdk-elb-logging-enabled
    lb = elbv2.ApplicationLoadBalancer(
        scope,
        "ALB1",
        vpc=vpc,
        internet_facing=True,
        access_logs=elbv2.LoggingAttributes(
            enabled=True,
            bucket=bucket,
            prefix="alb-logs",
        )
    )
    return lb

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    bucket = cdk.aws_s3.Bucket(scope, "LogBucket")
    
    # ok: python-cdk-elb-logging-enabled
    lb = elbv2.NetworkLoadBalancer(
        scope,
        "NLB1",
        vpc=vpc,
        internet_facing=True,
        access_logs=elbv2.LoggingAttributes(
            enabled=True,
            bucket=bucket,
            prefix="nlb-logs",
        )
    )
    return lb

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_4():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    bucket = cdk.aws_s3.Bucket(stack, "LogBucket")
    
    # ok: python-cdk-elb-logging-enabled
    lb = elb.LoadBalancer(
        stack,
        "LB2",
        vpc=vpc,
        internet_facing=True,
        access_logging_policy=elb.AccessLoggingPolicy(
            enabled=True,
            s3_bucket_name=bucket.bucket_name,
            s3_bucket_prefix="elb-logs",
        )
    )
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_5():
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            vpc = ec2.Vpc(self, "VPC")
            bucket = cdk.aws_s3.Bucket(self, "LogBucket")
            
            # ok: python-cdk-elb-logging-enabled
            lb = elbv2.ApplicationLoadBalancer(
                self,
                "ALB2",
                vpc=vpc,
                internet_facing=True,
                access_logs=elbv2.LoggingAttributes(
                    enabled=True,
                    bucket=bucket,
                    prefix="alb-logs",
                )
            )
    
    app = App()
    MyStack(app, "MyStack")
    return app

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_6():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    bucket = cdk.aws_s3.Bucket(stack, "LogBucket")
    
    # Creating multiple load balancers with logging
    # ok: python-cdk-elb-logging-enabled
    alb = elbv2.ApplicationLoadBalancer(
        stack,
        "ALB3",
        vpc=vpc,
        internet_facing=True,
        access_logs=elbv2.LoggingAttributes(
            enabled=True,
            bucket=bucket,
            prefix="alb-logs",
        )
    )
    
    # ok: python-cdk-elb-logging-enabled
    nlb = elbv2.NetworkLoadBalancer(
        stack,
        "NLB2",
        vpc=vpc,
        internet_facing=True,
        access_logs=elbv2.LoggingAttributes(
            enabled=True,
            bucket=bucket,
            prefix="nlb-logs",
        )
    )
    
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_7():
    def create_load_balancer(stack, vpc):
        bucket = cdk.aws_s3.Bucket(stack, "LogBucket")
        
        # ok: python-cdk-elb-logging-enabled
        return elbv2.ApplicationLoadBalancer(
            stack,
            "ALB4",
            vpc=vpc,
            internet_facing=True,
            access_logs=elbv2.LoggingAttributes(
                enabled=True,
                bucket=bucket,
                prefix="alb-logs",
            )
        )
    
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    lb = create_load_balancer(stack, vpc)
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_8():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    bucket = cdk.aws_s3.Bucket(stack, "LogBucket")
    
    # Creating a load balancer with conditional logging that defaults to enabled
    enable_custom_prefix = False
    
    # ok: python-cdk-elb-logging-enabled
    lb = elbv2.ApplicationLoadBalancer(
        stack,
        "ALB5",
        vpc=vpc,
        internet_facing=True,
        access_logs=elbv2.LoggingAttributes(
            enabled=True,
            bucket=bucket,
            prefix="custom-prefix" if enable_custom_prefix else "default-prefix",
        )
    )
    
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_9():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    bucket = cdk.aws_s3.Bucket(stack, "LogBucket")
    
    lb_props = {
        "vpc": vpc,
        "internet_facing": True,
        "access_logs": elbv2.LoggingAttributes(
            enabled=True,
            bucket=bucket,
            prefix="alb-logs",
        )
    }
    
    # ok: python-cdk-elb-logging-enabled
    lb = elbv2.ApplicationLoadBalancer(
        stack,
        "ALB6",
        **lb_props
    )
    
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_10():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # Create bucket with specific settings for logs
    bucket = cdk.aws_s3.Bucket(
        stack,
        "LogBucket",
        encryption=cdk.aws_s3.BucketEncryption.S3_MANAGED,
        block_public_access=cdk.aws_s3.BlockPublicAccess.BLOCK_ALL,
        lifecycle_rules=[
            cdk.aws_s3.LifecycleRule(
                expiration=cdk.Duration.days(90),
                transitions=[
                    cdk.aws_s3.Transition(
                        storage_class=cdk.aws_s3.StorageClass.INFREQUENT_ACCESS,
                        transition_after=cdk.Duration.days(30)
                    )
                ]
            )
        ]
    )
    
    # ok: python-cdk-elb-logging-enabled
    lb = elbv2.ApplicationLoadBalancer(
        stack,
        "ALB7",
        vpc=vpc,
        internet_facing=True,
        access_logs=elbv2.LoggingAttributes(
            enabled=True,
            bucket=bucket,
            prefix="alb-logs",
        )
    )
    
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_11():
    class LoadBalancerStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            vpc = ec2.Vpc(self, "VPC")
            bucket = cdk.aws_s3.Bucket(self, "LogBucket")
            
            # ok: python-cdk-elb-logging-enabled
            self.lb = elbv2.ApplicationLoadBalancer(
                self,
                "ALB8",
                vpc=vpc,
                internet_facing=True,
                access_logs=elbv2.LoggingAttributes(
                    enabled=True,
                    bucket=bucket,
                    prefix="alb-logs",
                )
            )
            
            # Add listeners and target groups
            target_group = elbv2.ApplicationTargetGroup(
                self, "TargetGroup",
                vpc=vpc,
                port=80,
                protocol=elbv2.ApplicationProtocol.HTTP,
                target_type=elbv2.TargetType.INSTANCE
            )
            
            self.lb.add_listener(
                "Listener",
                port=80,
                default_target_groups=[target_group]
            )
    
    app = App()
    LoadBalancerStack(app, "LoadBalancerStack")
    return app

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_12():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    bucket = cdk.aws_s3.Bucket(stack, "LogBucket")
    
    # Using environment variables to configure logging
    import os
    log_prefix = os.environ.get("LOG_PREFIX", "default-logs")
    
    # ok: python-cdk-elb-logging-enabled
    lb = elbv2.ApplicationLoadBalancer(
        stack,
        "ALB9",
        vpc=vpc,
        internet_facing=True,
        access_logs=elbv2.LoggingAttributes(
            enabled=True,
            bucket=bucket,
            prefix=log_prefix,
        )
    )
    
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_13():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    bucket = cdk.aws_s3.Bucket(stack, "LogBucket")
    
    # ok: python-cdk-elb-logging-enabled
    classic_lb = elb.LoadBalancer(
        stack,
        "ClassicLB",
        vpc=vpc,
        internet_facing=True,
        access_logging_policy=elb.AccessLoggingPolicy(
            enabled=True,
            s3_bucket_name=bucket.bucket_name,
            s3_bucket_prefix="classic-elb-logs",
            emit_interval=5  # emit logs every 5 minutes
        )
    )
    
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_14():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # Create a bucket specifically for load balancer logs
    log_bucket = cdk.aws_s3.Bucket(
        stack, 
        "LBLogBucket",
        removal_policy=cdk.RemovalPolicy.RETAIN
    )
    
    # Grant permissions for ELB to write logs
    log_bucket.add_to_resource_policy(
        cdk.aws_iam.PolicyStatement(
            actions=["s3:PutObject"],
            resources=[f"{log_bucket.bucket_arn}/*"],
            principals=[cdk.aws_iam.ServicePrincipal("delivery.logs.amazonaws.com")]
        )
    )
    
    # ok: python-cdk-elb-logging-enabled
    lb = elbv2.ApplicationLoadBalancer(
        stack,
        "ALB10",
        vpc=vpc,
        internet_facing=True,
        access_logs=elbv2.LoggingAttributes(
            enabled=True,
            bucket=log_bucket,
            prefix="alb-logs",
        )
    )
    
    return stack

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_15():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    bucket = cdk.aws_s3.Bucket(stack, "LogBucket")
    
    # Create a network load balancer with logging in a specific subnet
    subnets = vpc.select_subnets(subnet_type=ec2.SubnetType.PUBLIC)
    
    # ok: python-cdk-elb-logging-enabled
    lb = elbv2.NetworkLoadBalancer(
        stack,
        "NLB3",
        vpc=vpc,
        internet_facing=True,
        vpc_subnets=subnets,
        access_logs=elbv2.LoggingAttributes(
            enabled=True,
            bucket=bucket,
            prefix="nlb-logs",
        )
    )
    
    return stack
# {/fact}