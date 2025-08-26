import aws_cdk as cdk
from aws_cdk import (
    aws_autoscaling as autoscaling,
    aws_ec2 as ec2,
    aws_elasticloadbalancing as elb,
    aws_elasticloadbalancingv2 as elbv2,
    Stack,
    Duration,
)
from constructs import Construct


# True Positives (Vulnerable Code)

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # No health check configuration for the load balancer


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.ec2(),  # Only EC2 health check, no ELB
    )
    

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elbv2.NetworkLoadBalancer(scope, "NLB", vpc=vpc)
    listener = lb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
    )
    target_group.add_target(asg)
    # Missing health check configuration


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.ec2(grace=Duration.minutes(5)),  # Only EC2 health check with grace period
    )
    

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    alb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    listener = alb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        machine_image=ec2.AmazonLinuxImage(),
        desired_capacity=2,
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        machine_image=ec2.AmazonLinuxImage(),
    )
    lb.add_target(asg)
    # Missing health check configuration


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    alb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.COMPUTE5, ec2.InstanceSize.XLARGE),
        machine_image=ec2.AmazonLinuxImage(),
        cooldown=Duration.minutes(3),
        max_capacity=10,
        min_capacity=2,
    )
    # No health check configuration


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    nlb = elbv2.NetworkLoadBalancer(scope, "NLB", vpc=vpc)
    listener = nlb.add_listener("Listener", port=443)
    target_group = listener.add_targets("Fleet", port=443)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.STANDARD5, ec2.InstanceSize.LARGE),
        machine_image=ec2.AmazonLinuxImage(),
        update_policy=autoscaling.UpdatePolicy.rolling_update(),
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        signals=autoscaling.Signals.wait_for_count(1, timeout=Duration.minutes(10)),
    )
    lb.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    alb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    listener = alb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.XLARGE),
        machine_image=ec2.AmazonLinuxImage(),
        termination_policies=[autoscaling.TerminationPolicy.OLDEST_INSTANCE],
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        machine_image=ec2.AmazonLinuxImage(),
        group_metrics=[autoscaling.GroupMetrics.all()],
    )
    # No ELB health check configuration


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    nlb = elbv2.NetworkLoadBalancer(scope, "NLB", vpc=vpc)
    listener = nlb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.STANDARD5, ec2.InstanceSize.MEDIUM),
        machine_image=ec2.AmazonLinuxImage(),
        allow_all_outbound=True,
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.COMPUTE5, ec2.InstanceSize.LARGE),
        machine_image=ec2.AmazonLinuxImage(),
        spot_price="0.05",
    )
    lb.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    alb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    listener = alb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        machine_image=ec2.AmazonLinuxImage(),
        max_instance_lifetime=Duration.days(7),
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    listener = lb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ruleid: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        new_instances_protected_from_scale_in=True,
    )
    target_group.add_target(asg)


# True Negatives (Secure Code)

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(),  # Using ELB health check
    )
    lb.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    alb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    listener = alb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(),  # Using ELB health check
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    nlb = elbv2.NetworkLoadBalancer(scope, "NLB", vpc=vpc)
    listener = nlb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.STANDARD5, ec2.InstanceSize.LARGE),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(grace=Duration.minutes(2)),  # ELB health check with grace period
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(),  # Using ELB health check
        cooldown=Duration.minutes(5),
    )
    lb.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    alb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    listener = alb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.XLARGE),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(),  # Using ELB health check
        max_capacity=10,
        min_capacity=2,
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    nlb = elbv2.NetworkLoadBalancer(scope, "NLB", vpc=vpc)
    listener = nlb.add_listener("Listener", port=443)
    target_group = listener.add_targets("Fleet", port=443)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.COMPUTE5, ec2.InstanceSize.LARGE),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(grace=Duration.minutes(3)),  # ELB health check with grace period
        update_policy=autoscaling.UpdatePolicy.rolling_update(),
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(),  # Using ELB health check
        signals=autoscaling.Signals.wait_for_count(1, timeout=Duration.minutes(10)),
    )
    lb.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    alb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    listener = alb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(),  # Using ELB health check
        termination_policies=[autoscaling.TerminationPolicy.OLDEST_INSTANCE],
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(grace=Duration.minutes(5)),  # ELB health check with grace period
        group_metrics=[autoscaling.GroupMetrics.all()],
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    nlb = elbv2.NetworkLoadBalancer(scope, "NLB", vpc=vpc)
    listener = nlb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.STANDARD5, ec2.InstanceSize.MEDIUM),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(),  # Using ELB health check
        allow_all_outbound=True,
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elb.LoadBalancer(scope, "LB", vpc=vpc)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.COMPUTE5, ec2.InstanceSize.LARGE),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(grace=Duration.minutes(2)),  # ELB health check with grace period
        spot_price="0.05",
    )
    lb.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    alb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    listener = alb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.MEMORY5, ec2.InstanceSize.LARGE),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(),  # Using ELB health check
        max_instance_lifetime=Duration.days(7),
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    lb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    listener = lb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(grace=Duration.minutes(1)),  # ELB health check with grace period
        new_instances_protected_from_scale_in=True,
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    alb = elbv2.ApplicationLoadBalancer(scope, "ALB", vpc=vpc)
    listener = alb.add_listener("Listener", port=80)
    target_group = listener.add_targets("Fleet", port=80)
    
    # ok: python-cdk-auto-scaling-group-health-check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.STANDARD5, ec2.InstanceSize.XLARGE),
        machine_image=ec2.AmazonLinuxImage(),
        health_check=autoscaling.HealthCheck.elb(),  # Using ELB health check
        desired_capacity=3,
    )
    target_group.add_target(asg)


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    nlb = elbv2.NetworkLoadBalancer(scope, "NLB", vpc=vpc)
    listener = nlb.add_listener("Listener", port=443)
    target_group = listener.add_targets("Fleet", port=443)
    
    # First create ASG with EC2 health check
    asg = autoscaling.AutoScalingGroup(
        scope, 
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MEDIUM),
        machine_image=ec2.AmazonLinuxImage(),
    )
    
    # ok: python-cdk-auto-scaling-group-health-check
    # Then update to use ELB health check
    asg.add_health_check(autoscaling.HealthCheck.elb(grace=Duration.minutes(3)))
    
    target_group.add_target(asg)
# {/fact}