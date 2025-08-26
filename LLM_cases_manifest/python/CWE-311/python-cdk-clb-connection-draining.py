import aws_cdk as cdk
from aws_cdk import (
    aws_elasticloadbalancing as elb,
    Stack,
    Duration,
    CfnOutput
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1():
    """CLB created without connection draining"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, "MyLoadBalancer",
        vpc=cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True),
        internet_facing=True,
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2():
    """CLB with connection draining explicitly disabled"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, "MyLoadBalancer",
        vpc=cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True),
        internet_facing=True,
        connection_draining=False,
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3():
    """CLB with connection draining disabled and timeout set"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, "MyLoadBalancer",
        vpc=cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True),
        internet_facing=True,
        connection_draining=False,
        connection_draining_timeout=Duration.seconds(300),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4():
    """CLB created in a function without connection draining"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        internet_facing=True,
        cross_zone=True,
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5():
    """CLB created with variable configuration but no connection draining"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    lb_name = "MyLoadBalancer"
    is_internet_facing = True
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        lb_name,
        vpc=vpc,
        internet_facing=is_internet_facing,
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6():
    """CLB created with health check but no connection draining"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        health_check=elb.HealthCheck(
            port=80,
            protocol=elb.LoadBalancingProtocol.HTTP,
            path="/health",
            interval=Duration.seconds(30),
            timeout=Duration.seconds(5),
            healthy_threshold=2,
            unhealthy_threshold=2,
        ),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7():
    """CLB created with listeners but no connection draining"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        listeners=[
            elb.LoadBalancerListener(
                external_port=80,
                external_protocol=elb.LoadBalancingProtocol.HTTP,
                internal_port=8080,
                internal_protocol=elb.LoadBalancingProtocol.HTTP,
            )
        ],
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8():
    """CLB created in a class without connection draining"""
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            vpc = cdk.aws_ec2.Vpc.from_lookup(self, "VPC", is_default=True)
            
            # ruleid: python-cdk-clb-connection-draining
            self.load_balancer = elb.LoadBalancer(
                self, 
                "MyLoadBalancer",
                vpc=vpc,
                internet_facing=True,
            )
    
    app = cdk.App()
    stack = MyStack(app, "TestStack")
    return stack.load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9():
    """CLB created with security groups but no connection draining"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    security_group = cdk.aws_ec2.SecurityGroup(
        stack, "LBSecurityGroup", vpc=vpc, description="Load balancer security group"
    )
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        security_groups=[security_group],
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10():
    """CLB created with zero connection draining timeout"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        connection_draining=True,
        connection_draining_timeout=Duration.seconds(0),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11():
    """CLB created with conditional configuration but no connection draining"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    is_production = True
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        internet_facing=is_production,
        cross_zone=is_production,
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12():
    """CLB created with dictionary unpacking but no connection draining"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    lb_props = {
        "vpc": vpc,
        "internet_facing": True,
        "cross_zone": True,
    }
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        **lb_props
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13():
    """CLB created with access logging but no connection draining"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        access_logging_policy=elb.AccessLoggingPolicy(
            enabled=True,
            s3_bucket_name="my-access-logs-bucket",
            s3_bucket_prefix="lb-logs",
        ),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14():
    """CLB created with subnet selection but no connection draining"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        subnet_selection=cdk.aws_ec2.SubnetSelection(
            subnet_type=cdk.aws_ec2.SubnetType.PUBLIC
        ),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15():
    """CLB created with outputs but no connection draining"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ruleid: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
    )
    
    CfnOutput(stack, "LoadBalancerDNS", value=load_balancer.load_balancer_dns_name)
    
    return load_balancer

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1():
    """CLB with connection draining enabled"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, "MyLoadBalancer",
        vpc=cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True),
        internet_facing=True,
        connection_draining=True,
        connection_draining_timeout=Duration.seconds(300),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2():
    """CLB with connection draining enabled and default timeout"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, "MyLoadBalancer",
        vpc=cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True),
        internet_facing=True,
        connection_draining=True,
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3():
    """CLB with connection draining enabled and custom timeout"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        internet_facing=True,
        connection_draining=True,
        connection_draining_timeout=Duration.seconds(60),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4():
    """CLB with connection draining enabled in a class"""
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            vpc = cdk.aws_ec2.Vpc.from_lookup(self, "VPC", is_default=True)
            
            # ok: python-cdk-clb-connection-draining
            self.load_balancer = elb.LoadBalancer(
                self, 
                "MyLoadBalancer",
                vpc=vpc,
                internet_facing=True,
                connection_draining=True,
                connection_draining_timeout=Duration.seconds(300),
            )
    
    app = cdk.App()
    stack = MyStack(app, "TestStack")
    return stack.load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5():
    """CLB with connection draining enabled and health check"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        connection_draining=True,
        connection_draining_timeout=Duration.seconds(300),
        health_check=elb.HealthCheck(
            port=80,
            protocol=elb.LoadBalancingProtocol.HTTP,
            path="/health",
            interval=Duration.seconds(30),
            timeout=Duration.seconds(5),
            healthy_threshold=2,
            unhealthy_threshold=2,
        ),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6():
    """CLB with connection draining enabled and listeners"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        connection_draining=True,
        connection_draining_timeout=Duration.seconds(300),
        listeners=[
            elb.LoadBalancerListener(
                external_port=80,
                external_protocol=elb.LoadBalancingProtocol.HTTP,
                internal_port=8080,
                internal_protocol=elb.LoadBalancingProtocol.HTTP,
            )
        ],
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7():
    """CLB with connection draining enabled and security groups"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    security_group = cdk.aws_ec2.SecurityGroup(
        stack, "LBSecurityGroup", vpc=vpc, description="Load balancer security group"
    )
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        connection_draining=True,
        connection_draining_timeout=Duration.seconds(300),
        security_groups=[security_group],
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8():
    """CLB with connection draining enabled and variable configuration"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    lb_name = "MyLoadBalancer"
    is_internet_facing = True
    draining_timeout = 300
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        lb_name,
        vpc=vpc,
        internet_facing=is_internet_facing,
        connection_draining=True,
        connection_draining_timeout=Duration.seconds(draining_timeout),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9():
    """CLB with connection draining enabled using dictionary unpacking"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    lb_props = {
        "vpc": vpc,
        "internet_facing": True,
        "cross_zone": True,
        "connection_draining": True,
        "connection_draining_timeout": Duration.seconds(300),
    }
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        **lb_props
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10():
    """CLB with connection draining enabled and conditional configuration"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    is_production = True
    draining_timeout = 300 if is_production else 60
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        internet_facing=is_production,
        cross_zone=is_production,
        connection_draining=True,
        connection_draining_timeout=Duration.seconds(draining_timeout),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11():
    """CLB with connection draining enabled and access logging"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        connection_draining=True,
        connection_draining_timeout=Duration.seconds(300),
        access_logging_policy=elb.AccessLoggingPolicy(
            enabled=True,
            s3_bucket_name="my-access-logs-bucket",
            s3_bucket_prefix="lb-logs",
        ),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12():
    """CLB with connection draining enabled and subnet selection"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        connection_draining=True,
        connection_draining_timeout=Duration.seconds(300),
        subnet_selection=cdk.aws_ec2.SubnetSelection(
            subnet_type=cdk.aws_ec2.SubnetType.PUBLIC
        ),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13():
    """CLB with connection draining enabled and outputs"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        connection_draining=True,
        connection_draining_timeout=Duration.seconds(300),
    )
    
    CfnOutput(stack, "LoadBalancerDNS", value=load_balancer.load_balancer_dns_name)
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14():
    """CLB with connection draining enabled and longer timeout"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        connection_draining=True,
        connection_draining_timeout=Duration.minutes(5),
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15():
    """CLB with connection draining enabled and multiple listeners"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = cdk.aws_ec2.Vpc.from_lookup(stack, "VPC", is_default=True)
    
    # ok: python-cdk-clb-connection-draining
    load_balancer = elb.LoadBalancer(
        stack, 
        "MyLoadBalancer",
        vpc=vpc,
        connection_draining=True,
        connection_draining_timeout=Duration.seconds(300),
        listeners=[
            elb.LoadBalancerListener(
                external_port=80,
                external_protocol=elb.LoadBalancingProtocol.HTTP,
                internal_port=8080,
                internal_protocol=elb.LoadBalancingProtocol.HTTP,
            ),
            elb.LoadBalancerListener(
                external_port=443,
                external_protocol=elb.LoadBalancingProtocol.HTTPS,
                internal_port=8443,
                internal_protocol=elb.LoadBalancingProtocol.HTTP,
                ssl_certificate_id="arn:aws:acm:region:account:certificate/certificate-id",
            )
        ],
    )
    
    return load_balancer
# {/fact}