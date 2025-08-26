import aws_cdk as cdk
from aws_cdk import (
    aws_ec2 as ec2,
    aws_elasticloadbalancing as elb,
    aws_elasticloadbalancingv2 as elbv2,
    Stack,
    Duration,
    CfnOutput
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-clb-no-inbound-http-https
    load_balancer = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True,
        health_check=elb.HealthCheck(
            port=80
        )
    )
    
    load_balancer.add_listener(
        external_port=80,  # Using standard HTTP port
        internal_port=8080
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # ruleid: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=443,  # Using standard HTTPS port
        internal_port=8443
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    http_port = 80
    # ruleid: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=http_port,  # Using standard HTTP port via variable
        internal_port=8080
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # Adding multiple listeners with one being insecure
    lb.add_listener(external_port=8080, internal_port=8080)
    # ruleid: python-cdk-clb-no-inbound-http-https
    lb.add_listener(external_port=80, internal_port=80)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # ruleid: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=443,  # Using standard HTTPS port
        internal_port=443,
        protocol=elb.LoadBalancingProtocol.HTTPS
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Creating multiple load balancers with insecure ports
    lb1 = elb.LoadBalancer(scope, "LB1", vpc=vpc, internet_facing=True)
    lb2 = elb.LoadBalancer(scope, "LB2", vpc=vpc, internet_facing=True)
    
    # ruleid: python-cdk-clb-no-inbound-http-https
    lb1.add_listener(external_port=80, internal_port=8080)
    lb2.add_listener(external_port=8443, internal_port=8443)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc, internet_facing=True)
    
    ports = [80, 8080, 9000]
    for port in ports:
        if port == 80:
            # ruleid: python-cdk-clb-no-inbound-http-https
            lb.add_listener(external_port=port, internal_port=8080)
        else:
            lb.add_listener(external_port=port, internal_port=port)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc, internet_facing=True)
    
    def configure_listener(ext_port, int_port):
        # ruleid: python-cdk-clb-no-inbound-http-https
        lb.add_listener(external_port=ext_port, internal_port=int_port)
    
    configure_listener(443, 8443)  # Using standard HTTPS port

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc, internet_facing=True)
    
    # Using constants for ports
    HTTP_PORT = 80
    INTERNAL_PORT = 8080
    
    # ruleid: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=HTTP_PORT,
        internal_port=INTERNAL_PORT
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc, internet_facing=True)
    
    # Using a dictionary for configuration
    listener_config = {
        "external_port": 443,
        "internal_port": 8443,
        "protocol": elb.LoadBalancingProtocol.HTTPS
    }
    
    # ruleid: python-cdk-clb-no-inbound-http-https
    lb.add_listener(**listener_config)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc, internet_facing=True)
    
    # Conditional configuration
    use_secure_port = False
    
    if use_secure_port:
        external_port = 8443
    else:
        external_port = 443
    
    # ruleid: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=external_port,
        internal_port=8443
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc, internet_facing=True)
    
    # Using a function to get port
    def get_port(is_secure):
        return 8080 if is_secure else 80
    
    # ruleid: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=get_port(False),  # Returns 80
        internal_port=8080
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc, internet_facing=True)
    
    # Using arithmetic to calculate port
    base_port = 400
    
    # ruleid: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=base_port + 43,  # 443
        internal_port=8443
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc, internet_facing=True)
    
    # Using a list and indexing
    available_ports = [8080, 443, 9000]
    
    # ruleid: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=available_ports[1],  # 443
        internal_port=8443
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc, internet_facing=True)
    
    # Using string conversion
    port_str = "80"
    
    # ruleid: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=int(port_str),  # 80
        internal_port=8080
    )

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # ok: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=8080,  # Using non-standard port
        internal_port=8080
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # ok: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=8443,  # Using non-standard HTTPS port
        internal_port=8443,
        protocol=elb.LoadBalancingProtocol.HTTPS
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    secure_port = 8080
    # ok: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=secure_port,  # Using non-standard port via variable
        internal_port=secure_port
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # Adding multiple listeners, all secure
    # ok: python-cdk-clb-no-inbound-http-https
    lb.add_listener(external_port=8080, internal_port=8080)
    lb.add_listener(external_port=8443, internal_port=8443)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Using Application Load Balancer instead
    # ok: python-cdk-clb-no-inbound-http-https
    alb = elbv2.ApplicationLoadBalancer(
        scope, "ALB",
        vpc=vpc,
        internet_facing=True
    )
    
    listener = alb.add_listener(
        "Listener",
        port=8443,
        protocol=elbv2.ApplicationProtocol.HTTPS
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # Using a function to determine port
    def get_secure_port():
        return 8443
    
    # ok: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=get_secure_port(),
        internal_port=8443
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # Using a list of secure ports
    secure_ports = [8080, 8443, 9000]
    
    for port in secure_ports:
        # ok: python-cdk-clb-no-inbound-http-https
        lb.add_listener(
            external_port=port,
            internal_port=port
        )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Creating a Network Load Balancer with secure ports
    # ok: python-cdk-clb-no-inbound-http-https
    nlb = elbv2.NetworkLoadBalancer(
        scope, "NLB",
        vpc=vpc,
        internet_facing=True
    )
    
    listener = nlb.add_listener(
        "Listener",
        port=8080
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # Using environment configuration
    import os
    # Simulating environment variable
    os.environ["LB_PORT"] = "8443"
    
    # ok: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=int(os.environ.get("LB_PORT", "8080")),
        internal_port=8443
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # Using a configuration class
    class LoadBalancerConfig:
        def __init__(self):
            self.external_port = 8443
            self.internal_port = 8080
    
    config = LoadBalancerConfig()
    
    # ok: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=config.external_port,
        internal_port=config.internal_port
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # Using a dictionary for configuration
    listener_config = {
        "external_port": 8443,
        "internal_port": 8443,
        "protocol": elb.LoadBalancingProtocol.HTTPS
    }
    
    # ok: python-cdk-clb-no-inbound-http-https
    lb.add_listener(**listener_config)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # Using arithmetic to calculate port
    base_port = 8000
    
    # ok: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=base_port + 80,  # 8080
        internal_port=8080
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Internal load balancer (not internet-facing)
    # ok: python-cdk-clb-no-inbound-http-https
    internal_lb = elb.LoadBalancer(
        scope, "InternalLB",
        vpc=vpc,
        internet_facing=False  # Internal LB
    )
    
    # Even though using port 80, it's internal so less of a concern
    internal_lb.add_listener(
        external_port=9080,
        internal_port=80
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    lb = elb.LoadBalancer(
        scope, "LB",
        vpc=vpc,
        internet_facing=True
    )
    
    # Using string conversion for secure port
    port_str = "8080"
    
    # ok: python-cdk-clb-no-inbound-http-https
    lb.add_listener(
        external_port=int(port_str),  # 8080
        internal_port=8080
    )

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Using Application Load Balancer with redirection
    # ok: python-cdk-clb-no-inbound-http-https
    alb = elbv2.ApplicationLoadBalancer(
        scope, "ALB",
        vpc=vpc,
        internet_facing=True
    )
    
    https_listener = alb.add_listener(
        "HttpsListener",
        port=8443,
        protocol=elbv2.ApplicationProtocol.HTTPS
    )
    
    # Redirect HTTP traffic to HTTPS
    alb.add_redirect(
        source_protocol=elbv2.ApplicationProtocol.HTTP,
        source_port=8080,
        target_protocol=elbv2.ApplicationProtocol.HTTPS,
        target_port=8443
    )
# {/fact}