import aws_cdk as cdk
from aws_cdk import (
    aws_autoscaling as autoscaling,
    aws_ec2 as ec2,
    Stack,
    Duration,
    CfnOutput
)
from constructs import Construct

# True Positives (Vulnerable Code - Missing Cooldown Period)

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_1():
    """Auto Scaling Group created without specifying any cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_2():
    """Auto Scaling Group with scaling policy but no cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    asg = autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=5
    )
    
    asg.scale_on_cpu_utilization("ScaleOnCpu",
        target_utilization_percent=75
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_3():
    """Auto Scaling Group with explicit None for cooldown property"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=2,
        max_capacity=10,
        cooldown=None
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_4():
    """Auto Scaling Group with step scaling but no cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    asg = autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=10
    )
    
    metric = cdk.aws_cloudwatch.Metric(
        namespace="AWS/EC2",
        metric_name="CPUUtilization"
    )
    
    asg.scale_on_metric("ScaleOnMetric", metric=metric, scaling_steps=[
        autoscaling.ScalingInterval(change=1, lower=70),
        autoscaling.ScalingInterval(change=3, lower=90),
        autoscaling.ScalingInterval(change=-1, upper=40)
    ])

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_5():
    """Auto Scaling Group with scheduled scaling but no cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    asg = autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=5
    )
    
    asg.scale_on_schedule("ScaleOutInMorning",
        schedule=autoscaling.Schedule.cron(hour="8", minute="0"),
        min_capacity=3
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_6():
    """Auto Scaling Group in a custom stack without cooldown period"""
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            vpc = ec2.Vpc(self, "VPC")
            
            # ruleid: python-cdk-auto-scaling-group-cooldown-period
            autoscaling.AutoScalingGroup(self, "ASG",
                vpc=vpc,
                instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
                machine_image=ec2.AmazonLinuxImage(),
                min_capacity=1,
                max_capacity=3
            )
    
    app = cdk.App()
    MyStack(app, "MyStack")

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_7():
    """Auto Scaling Group with health check but no cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        health_check=autoscaling.HealthCheck.elb(grace=Duration.minutes(5))
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_8():
    """Auto Scaling Group with spot instances but no cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=10,
        spot_price="0.05"
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_9():
    """Auto Scaling Group with multiple instance types but no cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_types=[
            ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
            ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL)
        ],
        mixed_instances_policy=autoscaling.MixedInstancesPolicy(
            instances_distribution=autoscaling.InstancesDistribution(
                on_demand_percentage_above_base_capacity=50
            )
        ),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=5
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_10():
    """Auto Scaling Group with user data but no cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    user_data = ec2.UserData.for_linux()
    user_data.add_commands("yum update -y", "yum install -y httpd", "systemctl start httpd")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        user_data=user_data,
        min_capacity=1,
        max_capacity=3
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_11():
    """Auto Scaling Group with termination policies but no cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        termination_policies=[
            autoscaling.TerminationPolicy.OLDEST_INSTANCE,
            autoscaling.TerminationPolicy.DEFAULT
        ]
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_12():
    """Auto Scaling Group with capacity rebalance but no cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        capacity_rebalance=True
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_13():
    """Auto Scaling Group with notifications but no cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    topic = cdk.aws_sns.Topic(stack, "Topic")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    asg = autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3
    )
    
    asg.notify_on_all_scaling_events(topic)

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_14():
    """Auto Scaling Group with max instance lifetime but no cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        max_instance_lifetime=Duration.days(7)
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_15():
    """Auto Scaling Group with launch template but no cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    launch_template = ec2.LaunchTemplate(stack, "LaunchTemplate",
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage()
    )
    
    # ruleid: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        launch_template=launch_template,
        min_capacity=1,
        max_capacity=3
    )

# True Negatives (Secure Code - With Cooldown Period)

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_1():
    """Auto Scaling Group with cooldown period specified"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        cooldown=Duration.seconds(300)
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_2():
    """Auto Scaling Group with scaling policy and cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    asg = autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=5,
        cooldown=Duration.seconds(180)
    )
    
    asg.scale_on_cpu_utilization("ScaleOnCpu",
        target_utilization_percent=75
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_3():
    """Auto Scaling Group with longer cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=2,
        max_capacity=10,
        cooldown=Duration.minutes(5)
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_4():
    """Auto Scaling Group with step scaling and cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    asg = autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=10,
        cooldown=Duration.seconds(240)
    )
    
    metric = cdk.aws_cloudwatch.Metric(
        namespace="AWS/EC2",
        metric_name="CPUUtilization"
    )
    
    asg.scale_on_metric("ScaleOnMetric", metric=metric, scaling_steps=[
        autoscaling.ScalingInterval(change=1, lower=70),
        autoscaling.ScalingInterval(change=3, lower=90),
        autoscaling.ScalingInterval(change=-1, upper=40)
    ])

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_5():
    """Auto Scaling Group with scheduled scaling and cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    asg = autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=5,
        cooldown=Duration.minutes(3)
    )
    
    asg.scale_on_schedule("ScaleOutInMorning",
        schedule=autoscaling.Schedule.cron(hour="8", minute="0"),
        min_capacity=3
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_6():
    """Auto Scaling Group in a custom stack with cooldown period"""
    class MyStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs) -> None:
            super().__init__(scope, id, **kwargs)
            vpc = ec2.Vpc(self, "VPC")
            
            # ok: python-cdk-auto-scaling-group-cooldown-period
            autoscaling.AutoScalingGroup(self, "ASG",
                vpc=vpc,
                instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
                machine_image=ec2.AmazonLinuxImage(),
                min_capacity=1,
                max_capacity=3,
                cooldown=Duration.seconds(300)
            )
    
    app = cdk.App()
    MyStack(app, "MyStack")

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_7():
    """Auto Scaling Group with health check and cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        health_check=autoscaling.HealthCheck.elb(grace=Duration.minutes(5)),
        cooldown=Duration.seconds(300)
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_8():
    """Auto Scaling Group with spot instances and cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=10,
        spot_price="0.05",
        cooldown=Duration.minutes(2)
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_9():
    """Auto Scaling Group with multiple instance types and cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_types=[
            ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
            ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.SMALL)
        ],
        mixed_instances_policy=autoscaling.MixedInstancesPolicy(
            instances_distribution=autoscaling.InstancesDistribution(
                on_demand_percentage_above_base_capacity=50
            )
        ),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=5,
        cooldown=Duration.seconds(360)
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_10():
    """Auto Scaling Group with user data and cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    user_data = ec2.UserData.for_linux()
    user_data.add_commands("yum update -y", "yum install -y httpd", "systemctl start httpd")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        user_data=user_data,
        min_capacity=1,
        max_capacity=3,
        cooldown=Duration.minutes(4)
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_11():
    """Auto Scaling Group with termination policies and cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        termination_policies=[
            autoscaling.TerminationPolicy.OLDEST_INSTANCE,
            autoscaling.TerminationPolicy.DEFAULT
        ],
        cooldown=Duration.seconds(270)
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_12():
    """Auto Scaling Group with capacity rebalance and cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        capacity_rebalance=True,
        cooldown=Duration.seconds(180)
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_13():
    """Auto Scaling Group with notifications and cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    topic = cdk.aws_sns.Topic(stack, "Topic")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    asg = autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        cooldown=Duration.minutes(6)
    )
    
    asg.notify_on_all_scaling_events(topic)

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_14():
    """Auto Scaling Group with max instance lifetime and cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        max_instance_lifetime=Duration.days(7),
        cooldown=Duration.seconds(300)
    )

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_15():
    """Auto Scaling Group with launch template and cooldown period"""
    app = cdk.App()
    stack = Stack(app, "TestStack")
    vpc = ec2.Vpc(stack, "VPC")
    
    launch_template = ec2.LaunchTemplate(stack, "LaunchTemplate",
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage()
    )
    
    # ok: python-cdk-auto-scaling-group-cooldown-period
    autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        launch_template=launch_template,
        min_capacity=1,
        max_capacity=3,
        cooldown=Duration.seconds(300)
    )
# {/fact}