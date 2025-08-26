import aws_cdk as cdk
from aws_cdk import (
    aws_elasticloadbalancing as elb,
    aws_elasticloadbalancingv2 as elbv2,
    Stack,
    CfnOutput,
    Duration,
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a load balancer with HTTP listener (insecure)
    lb = elb.LoadBalancer(scope, "MyLoadBalancer1",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    )
    
    # ruleid: python-cdk-elb-tls-https-listeners-only
    lb.add_listener(
        external_port=80,
        external_protocol=elb.LoadBalancingProtocol.HTTP,
        internal_port=8080
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating a load balancer with TCP listener (insecure)
    lb = elb.LoadBalancer(scope, "MyLoadBalancer2",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    )
    
    # ruleid: python-cdk-elb-tls-https-listeners-only
    lb.add_listener(
        external_port=8080,
        external_protocol=elb.LoadBalancingProtocol.TCP,
        internal_port=8080
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a load balancer with multiple listeners including HTTP (insecure)
    lb = elb.LoadBalancer(scope, "MyLoadBalancer3",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    )
    
    lb.add_listener(
        external_port=443,
        external_protocol=elb.LoadBalancingProtocol.HTTPS,
        internal_port=8443,
        certificates=[elb.LoadBalancerListener.ImportedCertificate("cert-id")]
    )
    
    # ruleid: python-cdk-elb-tls-https-listeners-only
    lb.add_listener(
        external_port=80,
        external_protocol=elb.LoadBalancingProtocol.HTTP,
        internal_port=8080
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a load balancer with HTTP listener and health check (still insecure)
    lb = elb.LoadBalancer(scope, "MyLoadBalancer4",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        health_check=elb.HealthCheck(
            port=8080,
            protocol=elb.LoadBalancingProtocol.HTTP,
            path="/health",
            interval=Duration.seconds(30)
        )
    )
    
    # ruleid: python-cdk-elb-tls-https-listeners-only
    lb.add_listener(
        external_port=80,
        external_protocol=elb.LoadBalancingProtocol.HTTP,
        internal_port=8080
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a load balancer with TCP listener and specific instance (insecure)
    lb = elb.LoadBalancer(scope, "MyLoadBalancer5",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    )
    
    instance = cdk.aws_ec2.Instance(scope, "Instance",
        instance_type=cdk.aws_ec2.InstanceType("t2.micro"),
        machine_image=cdk.aws_ec2.MachineImage.latest_amazon_linux(),
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC2", is_default=True)
    )
    
    # ruleid: python-cdk-elb-tls-https-listeners-only
    lb.add_listener(
        external_port=8080,
        external_protocol=elb.LoadBalancingProtocol.TCP,
        internal_port=8080
    )
    
    lb.add_target(instance)
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a load balancer with HTTP listener using constructor (insecure)
    lb = elb.LoadBalancer(
        scope, 
        "MyLoadBalancer6",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        # ruleid: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=80,
                external_protocol=elb.LoadBalancingProtocol.HTTP,
                internal_port=8080
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a load balancer with TCP listener using constructor (insecure)
    lb = elb.LoadBalancer(
        scope, 
        "MyLoadBalancer7",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        # ruleid: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=8080,
                external_protocol=elb.LoadBalancingProtocol.TCP,
                internal_port=8080
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a load balancer with multiple listeners including TCP (insecure)
    lb = elb.LoadBalancer(
        scope, 
        "MyLoadBalancer8",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        listeners=[
            elb.LoadBalancerListener(
                external_port=443,
                external_protocol=elb.LoadBalancingProtocol.HTTPS,
                internal_port=8443,
                certificates=[elb.LoadBalancerListener.ImportedCertificate("cert-id")]
            ),
            # ruleid: python-cdk-elb-tls-https-listeners-only
            elb.LoadBalancerListener(
                external_port=8080,
                external_protocol=elb.LoadBalancingProtocol.TCP,
                internal_port=8080
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a load balancer with HTTP listener and cross-zone load balancing (insecure)
    lb = elb.LoadBalancer(
        scope, 
        "MyLoadBalancer9",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        cross_zone=True,
        # ruleid: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=80,
                external_protocol=elb.LoadBalancingProtocol.HTTP,
                internal_port=8080
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a load balancer with HTTP listener and specific security groups (insecure)
    vpc = cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    security_group = cdk.aws_ec2.SecurityGroup(scope, "LBSecurityGroup", vpc=vpc)
    
    lb = elb.LoadBalancer(
        scope, 
        "MyLoadBalancer10",
        vpc=vpc,
        security_group=security_group,
        # ruleid: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=80,
                external_protocol=elb.LoadBalancingProtocol.HTTP,
                internal_port=8080
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a load balancer with HTTP listener and internet-facing (insecure)
    lb = elb.LoadBalancer(
        scope, 
        "MyLoadBalancer11",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        internet_facing=True,
        # ruleid: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=80,
                external_protocol=elb.LoadBalancingProtocol.HTTP,
                internal_port=8080
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a load balancer with TCP listener and specific subnets (insecure)
    vpc = cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    subnets = [subnet.subnet_id for subnet in vpc.public_subnets]
    
    lb = elb.LoadBalancer(
        scope, 
        "MyLoadBalancer12",
        vpc=vpc,
        subnet_ids=subnets,
        # ruleid: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=8080,
                external_protocol=elb.LoadBalancingProtocol.TCP,
                internal_port=8080
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a load balancer with HTTP listener and connection draining (insecure)
    lb = elb.LoadBalancer(
        scope, 
        "MyLoadBalancer13",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        connection_draining_timeout=Duration.seconds(60),
        # ruleid: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=80,
                external_protocol=elb.LoadBalancingProtocol.HTTP,
                internal_port=8080
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a load balancer with HTTP listener and access logging (insecure)
    lb = elb.LoadBalancer(
        scope, 
        "MyLoadBalancer14",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        access_logging_policy=elb.AccessLoggingPolicy(
            s3_bucket=cdk.aws_s3.Bucket(scope, "LogBucket"),
            emit_interval=Duration.minutes(5)
        ),
        # ruleid: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=80,
                external_protocol=elb.LoadBalancingProtocol.HTTP,
                internal_port=8080
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a load balancer with multiple listeners including HTTP (insecure)
    vpc = cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    
    lb = elb.LoadBalancer(scope, "MyLoadBalancer15", vpc=vpc)
    
    # Adding a secure listener
    lb.add_listener(
        external_port=443,
        external_protocol=elb.LoadBalancingProtocol.HTTPS,
        internal_port=8443,
        certificates=[elb.LoadBalancerListener.ImportedCertificate("cert-id")]
    )
    
    # Adding a secure listener
    lb.add_listener(
        external_port=8443,
        external_protocol=elb.LoadBalancingProtocol.SSL,
        internal_port=8443
    )
    
    # ruleid: python-cdk-elb-tls-https-listeners-only
    lb.add_listener(
        external_port=80,
        external_protocol=elb.LoadBalancingProtocol.HTTP,
        internal_port=8080
    )
    
    return lb

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a load balancer with HTTPS listener (secure)
    lb = elb.LoadBalancer(scope, "MySecureLoadBalancer1",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    )
    
    # ok: python-cdk-elb-tls-https-listeners-only
    lb.add_listener(
        external_port=443,
        external_protocol=elb.LoadBalancingProtocol.HTTPS,
        internal_port=8443,
        certificates=[elb.LoadBalancerListener.ImportedCertificate("cert-id")]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating a load balancer with SSL listener (secure)
    lb = elb.LoadBalancer(scope, "MySecureLoadBalancer2",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    )
    
    # ok: python-cdk-elb-tls-https-listeners-only
    lb.add_listener(
        external_port=443,
        external_protocol=elb.LoadBalancingProtocol.SSL,
        internal_port=8443
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating a load balancer with multiple secure listeners
    lb = elb.LoadBalancer(scope, "MySecureLoadBalancer3",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    )
    
    # ok: python-cdk-elb-tls-https-listeners-only
    lb.add_listener(
        external_port=443,
        external_protocol=elb.LoadBalancingProtocol.HTTPS,
        internal_port=8443,
        certificates=[elb.LoadBalancerListener.ImportedCertificate("cert-id")]
    )
    
    lb.add_listener(
        external_port=8443,
        external_protocol=elb.LoadBalancingProtocol.SSL,
        internal_port=8443
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a load balancer with HTTPS listener and health check
    lb = elb.LoadBalancer(scope, "MySecureLoadBalancer4",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        health_check=elb.HealthCheck(
            port=8443,
            protocol=elb.LoadBalancingProtocol.HTTPS,
            path="/health",
            interval=Duration.seconds(30)
        )
    )
    
    # ok: python-cdk-elb-tls-https-listeners-only
    lb.add_listener(
        external_port=443,
        external_protocol=elb.LoadBalancingProtocol.HTTPS,
        internal_port=8443,
        certificates=[elb.LoadBalancerListener.ImportedCertificate("cert-id")]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a load balancer with SSL listener and specific instance
    lb = elb.LoadBalancer(scope, "MySecureLoadBalancer5",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    )
    
    instance = cdk.aws_ec2.Instance(scope, "SecureInstance",
        instance_type=cdk.aws_ec2.InstanceType("t2.micro"),
        machine_image=cdk.aws_ec2.MachineImage.latest_amazon_linux(),
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC2", is_default=True)
    )
    
    # ok: python-cdk-elb-tls-https-listeners-only
    lb.add_listener(
        external_port=443,
        external_protocol=elb.LoadBalancingProtocol.SSL,
        internal_port=8443
    )
    
    lb.add_target(instance)
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a load balancer with HTTPS listener using constructor
    lb = elb.LoadBalancer(
        scope, 
        "MySecureLoadBalancer6",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        # ok: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=443,
                external_protocol=elb.LoadBalancingProtocol.HTTPS,
                internal_port=8443,
                certificates=[elb.LoadBalancerListener.ImportedCertificate("cert-id")]
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a load balancer with SSL listener using constructor
    lb = elb.LoadBalancer(
        scope, 
        "MySecureLoadBalancer7",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        # ok: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=443,
                external_protocol=elb.LoadBalancingProtocol.SSL,
                internal_port=8443
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a load balancer with multiple secure listeners using constructor
    lb = elb.LoadBalancer(
        scope, 
        "MySecureLoadBalancer8",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        # ok: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=443,
                external_protocol=elb.LoadBalancingProtocol.HTTPS,
                internal_port=8443,
                certificates=[elb.LoadBalancerListener.ImportedCertificate("cert-id")]
            ),
            elb.LoadBalancerListener(
                external_port=8443,
                external_protocol=elb.LoadBalancingProtocol.SSL,
                internal_port=8443
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a load balancer with HTTPS listener and cross-zone load balancing
    lb = elb.LoadBalancer(
        scope, 
        "MySecureLoadBalancer9",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        cross_zone=True,
        # ok: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=443,
                external_protocol=elb.LoadBalancingProtocol.HTTPS,
                internal_port=8443,
                certificates=[elb.LoadBalancerListener.ImportedCertificate("cert-id")]
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a load balancer with SSL listener and specific security groups
    vpc = cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    security_group = cdk.aws_ec2.SecurityGroup(scope, "SecureLBSecurityGroup", vpc=vpc)
    
    lb = elb.LoadBalancer(
        scope, 
        "MySecureLoadBalancer10",
        vpc=vpc,
        security_group=security_group,
        # ok: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=443,
                external_protocol=elb.LoadBalancingProtocol.SSL,
                internal_port=8443
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a load balancer with HTTPS listener and internet-facing
    lb = elb.LoadBalancer(
        scope, 
        "MySecureLoadBalancer11",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        internet_facing=True,
        # ok: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=443,
                external_protocol=elb.LoadBalancingProtocol.HTTPS,
                internal_port=8443,
                certificates=[elb.LoadBalancerListener.ImportedCertificate("cert-id")]
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a load balancer with SSL listener and specific subnets
    vpc = cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    subnets = [subnet.subnet_id for subnet in vpc.public_subnets]
    
    lb = elb.LoadBalancer(
        scope, 
        "MySecureLoadBalancer12",
        vpc=vpc,
        subnet_ids=subnets,
        # ok: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=443,
                external_protocol=elb.LoadBalancingProtocol.SSL,
                internal_port=8443
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a load balancer with HTTPS listener and connection draining
    lb = elb.LoadBalancer(
        scope, 
        "MySecureLoadBalancer13",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        connection_draining_timeout=Duration.seconds(60),
        # ok: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=443,
                external_protocol=elb.LoadBalancingProtocol.HTTPS,
                internal_port=8443,
                certificates=[elb.LoadBalancerListener.ImportedCertificate("cert-id")]
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a load balancer with SSL listener and access logging
    lb = elb.LoadBalancer(
        scope, 
        "MySecureLoadBalancer14",
        vpc=cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True),
        access_logging_policy=elb.AccessLoggingPolicy(
            s3_bucket=cdk.aws_s3.Bucket(scope, "SecureLogBucket"),
            emit_interval=Duration.minutes(5)
        ),
        # ok: python-cdk-elb-tls-https-listeners-only
        listeners=[
            elb.LoadBalancerListener(
                external_port=443,
                external_protocol=elb.LoadBalancingProtocol.SSL,
                internal_port=8443
            )
        ]
    )
    
    return lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a load balancer with multiple secure listeners added separately
    vpc = cdk.aws_ec2.Vpc.from_lookup(scope, "VPC", is_default=True)
    
    lb = elb.LoadBalancer(scope, "MySecureLoadBalancer15", vpc=vpc)
    
    # ok: python-cdk-elb-tls-https-listeners-only
    lb.add_listener(
        external_port=443,
        external_protocol=elb.LoadBalancingProtocol.HTTPS,
        internal_port=8443,
        certificates=[elb.LoadBalancerListener.ImportedCertificate("cert-id")]
    )
    
    lb.add_listener(
        external_port=8443,
        external_protocol=elb.LoadBalancingProtocol.SSL,
        internal_port=8443
    )
    
    return lb

# Example stack implementation
# {/fact}

class ExampleStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Examples of bad and good implementations
        bad_case_1(self, "BadCase1")
        good_case_1(self, "GoodCase1")