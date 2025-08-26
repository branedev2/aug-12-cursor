import aws_cdk as cdk
from aws_cdk import (
    aws_elasticloadbalancing as elb,
    aws_ec2 as ec2,
    Stack,
    App
)
from constructs import Construct

# True Positive Examples (vulnerable code that should be detected)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(stack, "LB1",
        vpc=vpc,
        internet_facing=True,
        crossZone=False
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(
        stack, 
        "LB2",
        vpc=vpc,
        crossZone=False,
        health_check=elb.HealthCheck(
            port=80,
            protocol=elb.LoadBalancingProtocol.HTTP
        )
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    props = {
        "vpc": vpc,
        "crossZone": False,
        "listeners": [
            elb.LoadBalancerListener(
                port=80,
                external_port=80
            )
        ]
    }
    
    # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(stack, "LB3", **props)
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    cross_zone_enabled = False
    
    # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(stack, "LB4",
        vpc=vpc,
        crossZone=cross_zone_enabled
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5():
    class MyLoadBalancer(Construct):
        def __init__(self, scope: Construct, id: str):
            super().__init__(scope, id)
            vpc = ec2.Vpc(self, "VPC")
            
            # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
            self.lb = elb.LoadBalancer(self, "LB5",
                vpc=vpc,
                crossZone=False
            )
    
    app = App()
    stack = Stack(app, "MyStack")
    my_lb = MyLoadBalancer(stack, "MyLB")
    return my_lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # Default is False if not specified
    # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(stack, "LB6",
        vpc=vpc
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    config = {"crossZone": False}
    
    # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(
        stack, 
        "LB7",
        vpc=vpc,
        **config
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    def get_lb_config():
        return {"crossZone": False}
    
    # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(
        stack, 
        "LB8",
        vpc=vpc,
        **get_lb_config()
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
    lb1 = elb.LoadBalancer(stack, "LB9a", vpc=vpc, crossZone=False)
    # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
    lb2 = elb.LoadBalancer(stack, "LB9b", vpc=vpc, crossZone=False)
    
    return [lb1, lb2]

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10():
    class CustomStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            vpc = ec2.Vpc(self, "VPC")
            
            # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
            self.load_balancer = elb.LoadBalancer(
                self, 
                "LB10",
                vpc=vpc,
                crossZone=False
            )
    
    app = App()
    stack = CustomStack(app, "MyCustomStack")
    return stack.load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    cross_zone_setting = False
    health_check = elb.HealthCheck(
        port=80,
        protocol=elb.LoadBalancingProtocol.HTTP
    )
    
    # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(
        stack, 
        "LB11",
        vpc=vpc,
        crossZone=cross_zone_setting,
        health_check=health_check
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(
        stack, 
        "LB12",
        vpc=vpc,
        internet_facing=True,
        crossZone=False,
        security_groups=[ec2.SecurityGroup(stack, "LBLSG", vpc=vpc)]
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # Create multiple load balancers with insecure settings
    lbs = []
    for i in range(3):
        # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
        lb = elb.LoadBalancer(
            stack, 
            f"LB13-{i}",
            vpc=vpc,
            crossZone=False
        )
        lbs.append(lb)
    
    return lbs

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    lb_props = {
        "vpc": vpc,
        "internet_facing": True,
    }
    
    # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(
        stack, 
        "LB14",
        crossZone=False,
        **lb_props
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15():
    def create_load_balancer(stack, vpc):
        # ruleid: python-cdk-elb-cross-zone-load-balancing-enabled
        return elb.LoadBalancer(
            stack, 
            "LB15",
            vpc=vpc,
            crossZone=False
        )
    
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    load_balancer = create_load_balancer(stack, vpc)
    return load_balancer

# True Negative Examples (secure code that should not be detected)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(stack, "LB1",
        vpc=vpc,
        internet_facing=True,
        crossZone=True
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(
        stack, 
        "LB2",
        vpc=vpc,
        crossZone=True,
        health_check=elb.HealthCheck(
            port=80,
            protocol=elb.LoadBalancingProtocol.HTTP
        )
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    props = {
        "vpc": vpc,
        "crossZone": True,
        "listeners": [
            elb.LoadBalancerListener(
                port=80,
                external_port=80
            )
        ]
    }
    
    # ok: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(stack, "LB3", **props)
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    cross_zone_enabled = True
    
    # ok: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(stack, "LB4",
        vpc=vpc,
        crossZone=cross_zone_enabled
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5():
    class MyLoadBalancer(Construct):
        def __init__(self, scope: Construct, id: str):
            super().__init__(scope, id)
            vpc = ec2.Vpc(self, "VPC")
            
            # ok: python-cdk-elb-cross-zone-load-balancing-enabled
            self.lb = elb.LoadBalancer(self, "LB5",
                vpc=vpc,
                crossZone=True
            )
    
    app = App()
    stack = Stack(app, "MyStack")
    my_lb = MyLoadBalancer(stack, "MyLB")
    return my_lb

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    config = {"crossZone": True}
    
    # ok: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(
        stack, 
        "LB6",
        vpc=vpc,
        **config
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    def get_lb_config():
        return {"crossZone": True}
    
    # ok: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(
        stack, 
        "LB7",
        vpc=vpc,
        **get_lb_config()
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-elb-cross-zone-load-balancing-enabled
    lb1 = elb.LoadBalancer(stack, "LB8a", vpc=vpc, crossZone=True)
    # ok: python-cdk-elb-cross-zone-load-balancing-enabled
    lb2 = elb.LoadBalancer(stack, "LB8b", vpc=vpc, crossZone=True)
    
    return [lb1, lb2]

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9():
    class CustomStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            vpc = ec2.Vpc(self, "VPC")
            
            # ok: python-cdk-elb-cross-zone-load-balancing-enabled
            self.load_balancer = elb.LoadBalancer(
                self, 
                "LB9",
                vpc=vpc,
                crossZone=True
            )
    
    app = App()
    stack = CustomStack(app, "MyCustomStack")
    return stack.load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    cross_zone_setting = True
    health_check = elb.HealthCheck(
        port=80,
        protocol=elb.LoadBalancingProtocol.HTTP
    )
    
    # ok: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(
        stack, 
        "LB10",
        vpc=vpc,
        crossZone=cross_zone_setting,
        health_check=health_check
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(
        stack, 
        "LB11",
        vpc=vpc,
        internet_facing=True,
        crossZone=True,
        security_groups=[ec2.SecurityGroup(stack, "LBLSG", vpc=vpc)]
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # Create multiple load balancers with secure settings
    lbs = []
    for i in range(3):
        # ok: python-cdk-elb-cross-zone-load-balancing-enabled
        lb = elb.LoadBalancer(
            stack, 
            f"LB12-{i}",
            vpc=vpc,
            crossZone=True
        )
        lbs.append(lb)
    
    return lbs

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    lb_props = {
        "vpc": vpc,
        "internet_facing": True,
    }
    
    # ok: python-cdk-elb-cross-zone-load-balancing-enabled
    load_balancer = elb.LoadBalancer(
        stack, 
        "LB13",
        crossZone=True,
        **lb_props
    )
    
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14():
    def create_load_balancer(stack, vpc):
        # ok: python-cdk-elb-cross-zone-load-balancing-enabled
        return elb.LoadBalancer(
            stack, 
            "LB14",
            vpc=vpc,
            crossZone=True
        )
    
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    load_balancer = create_load_balancer(stack, vpc)
    return load_balancer

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15():
    app = App()
    stack = Stack(app, "MyStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # Using Application Load Balancer instead (which has cross-zone load balancing enabled by default)
    from aws_cdk import aws_elasticloadbalancingv2 as elbv2
    
    # ok: python-cdk-elb-cross-zone-load-balancing-enabled
    alb = elbv2.ApplicationLoadBalancer(
        stack,
        "ALB",
        vpc=vpc,
        internet_facing=True
    )
    
    return alb
# {/fact}