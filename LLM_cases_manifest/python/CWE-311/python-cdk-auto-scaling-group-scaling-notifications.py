import aws_cdk as cdk
from aws_cdk import (
    aws_autoscaling as autoscaling,
    aws_sns as sns,
    aws_ec2 as ec2,
    Stack,
    App
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # No notifications configured at all

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Only configuring notifications for instance launch events, missing other events
    asg.notify_on_instance_launch(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Only configuring notifications for termination events, missing other events
    asg.notify_on_instance_terminate(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Only configuring notifications for launch error events, missing other events
    asg.notify_on_instance_launch_errors(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Only configuring notifications for termination error events, missing other events
    asg.notify_on_instance_terminate_errors(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Only configuring notifications for launch and launch error events, missing termination events
    asg.notify_on_instance_launch(topic)
    asg.notify_on_instance_launch_errors(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Only configuring notifications for termination and termination error events, missing launch events
    asg.notify_on_instance_terminate(topic)
    asg.notify_on_instance_terminate_errors(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Only configuring notifications for launch and termination events, missing error events
    asg.notify_on_instance_launch(topic)
    asg.notify_on_instance_terminate(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Only configuring notifications for error events, missing normal events
    asg.notify_on_instance_launch_errors(topic)
    asg.notify_on_instance_terminate_errors(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Only configuring notifications for launch, termination, and launch error events, missing termination error events
    asg.notify_on_instance_launch(topic)
    asg.notify_on_instance_terminate(topic)
    asg.notify_on_instance_launch_errors(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Only configuring notifications for launch, termination, and termination error events, missing launch error events
    asg.notify_on_instance_launch(topic)
    asg.notify_on_instance_terminate(topic)
    asg.notify_on_instance_terminate_errors(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Only configuring notifications for launch, launch error, and termination error events, missing termination events
    asg.notify_on_instance_launch(topic)
    asg.notify_on_instance_launch_errors(topic)
    asg.notify_on_instance_terminate_errors(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Only configuring notifications for termination, launch error, and termination error events, missing launch events
    asg.notify_on_instance_terminate(topic)
    asg.notify_on_instance_launch_errors(topic)
    asg.notify_on_instance_terminate_errors(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    # Creating multiple ASGs but not configuring notifications for all of them
    topic = sns.Topic(scope, "Topic")
    asg1 = autoscaling.AutoScalingGroup(
        scope,
        "ASG1",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    
    # Configure all notifications for the first ASG
    asg1.notify_on_instance_launch(topic)
    asg1.notify_on_instance_terminate(topic)
    asg1.notify_on_instance_launch_errors(topic)
    asg1.notify_on_instance_terminate_errors(topic)
    
    asg2 = autoscaling.AutoScalingGroup(
        scope,
        "ASG2",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # Second ASG has no notifications configured

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    
    # Creating ASG with custom options but no notifications
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        desired_capacity=2,
        cooldown=cdk.Duration.seconds(300),
        health_check=autoscaling.HealthCheck.ec2(),
        update_policy=autoscaling.UpdatePolicy.rolling_update(),
    )
    # ruleid: python-cdk-auto-scaling-group-scaling-notifications
    # No notifications configured despite detailed ASG configuration

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ok: python-cdk-auto-scaling-group-scaling-notifications
    # Configuring notifications for all scaling events
    asg.notify_on_instance_launch(topic)
    asg.notify_on_instance_terminate(topic)
    asg.notify_on_instance_launch_errors(topic)
    asg.notify_on_instance_terminate_errors(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic1 = sns.Topic(scope, "Topic1")
    topic2 = sns.Topic(scope, "Topic2")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    # ok: python-cdk-auto-scaling-group-scaling-notifications
    # Configuring notifications for all scaling events with different topics
    asg.notify_on_instance_launch(topic1)
    asg.notify_on_instance_terminate(topic1)
    asg.notify_on_instance_launch_errors(topic2)
    asg.notify_on_instance_terminate_errors(topic2)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    
    # ok: python-cdk-auto-scaling-group-scaling-notifications
    # Configuring notifications during ASG creation
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        notifications=[
            autoscaling.NotificationConfiguration(
                topic=topic,
                scaling_events=autoscaling.ScalingEvents.ALL
            )
        ]
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    
    # ok: python-cdk-auto-scaling-group-scaling-notifications
    # Configuring notifications during ASG creation with explicit events
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        notifications=[
            autoscaling.NotificationConfiguration(
                topic=topic,
                scaling_events=autoscaling.ScalingEvents.INSTANCE_LAUNCH | 
                               autoscaling.ScalingEvents.INSTANCE_TERMINATE |
                               autoscaling.ScalingEvents.INSTANCE_LAUNCH_ERROR |
                               autoscaling.ScalingEvents.INSTANCE_TERMINATE_ERROR
            )
        ]
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic1 = sns.Topic(scope, "Topic1")
    topic2 = sns.Topic(scope, "Topic2")
    
    # ok: python-cdk-auto-scaling-group-scaling-notifications
    # Configuring multiple notification configurations
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        notifications=[
            autoscaling.NotificationConfiguration(
                topic=topic1,
                scaling_events=autoscaling.ScalingEvents.INSTANCE_LAUNCH | 
                               autoscaling.ScalingEvents.INSTANCE_TERMINATE
            ),
            autoscaling.NotificationConfiguration(
                topic=topic2,
                scaling_events=autoscaling.ScalingEvents.INSTANCE_LAUNCH_ERROR | 
                               autoscaling.ScalingEvents.INSTANCE_TERMINATE_ERROR
            )
        ]
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    
    # ok: python-cdk-auto-scaling-group-scaling-notifications
    # Adding notification configuration after ASG creation
    asg.add_notification(
        topic=topic,
        scaling_events=autoscaling.ScalingEvents.ALL
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic1 = sns.Topic(scope, "Topic1")
    topic2 = sns.Topic(scope, "Topic2")
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    
    # ok: python-cdk-auto-scaling-group-scaling-notifications
    # Adding multiple notification configurations after ASG creation
    asg.add_notification(
        topic=topic1,
        scaling_events=autoscaling.ScalingEvents.INSTANCE_LAUNCH | 
                       autoscaling.ScalingEvents.INSTANCE_TERMINATE
    )
    asg.add_notification(
        topic=topic2,
        scaling_events=autoscaling.ScalingEvents.INSTANCE_LAUNCH_ERROR | 
                       autoscaling.ScalingEvents.INSTANCE_TERMINATE_ERROR
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    
    # Creating multiple ASGs with notifications for all of them
    asg1 = autoscaling.AutoScalingGroup(
        scope,
        "ASG1",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    
    # ok: python-cdk-auto-scaling-group-scaling-notifications
    # Configure all notifications for the first ASG
    asg1.notify_on_instance_launch(topic)
    asg1.notify_on_instance_terminate(topic)
    asg1.notify_on_instance_launch_errors(topic)
    asg1.notify_on_instance_terminate_errors(topic)
    
    asg2 = autoscaling.AutoScalingGroup(
        scope,
        "ASG2",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    
    # ok: python-cdk-auto-scaling-group-scaling-notifications
    # Configure all notifications for the second ASG
    asg2.notify_on_instance_launch(topic)
    asg2.notify_on_instance_terminate(topic)
    asg2.notify_on_instance_launch_errors(topic)
    asg2.notify_on_instance_terminate_errors(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    
    # ok: python-cdk-auto-scaling-group-scaling-notifications
    # Creating ASG with custom options and all notifications
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
        desired_capacity=2,
        cooldown=cdk.Duration.seconds(300),
        health_check=autoscaling.HealthCheck.ec2(),
        update_policy=autoscaling.UpdatePolicy.rolling_update(),
        notifications=[
            autoscaling.NotificationConfiguration(
                topic=topic,
                scaling_events=autoscaling.ScalingEvents.ALL
            )
        ]
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    
    # Creating a function to set up ASG with notifications
    def create_asg_with_notifications(scope, id, vpc, topic):
        asg = autoscaling.AutoScalingGroup(
            scope,
            id,
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
            machine_image=ec2.AmazonLinuxImage(),
            min_capacity=1,
            max_capacity=3,
        )
        
        # ok: python-cdk-auto-scaling-group-scaling-notifications
        # Configure all notifications
        asg.notify_on_instance_launch(topic)
        asg.notify_on_instance_terminate(topic)
        asg.notify_on_instance_launch_errors(topic)
        asg.notify_on_instance_terminate_errors(topic)
        
        return asg
    
    # Create ASG with notifications
    asg = create_asg_with_notifications(scope, "ASG", vpc, topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    
    # Creating a custom ASG class with notifications
    class NotifyingAutoScalingGroup(autoscaling.AutoScalingGroup):
        def __init__(self, scope, id, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            # ok: python-cdk-auto-scaling-group-scaling-notifications
            # Configure all notifications in the constructor
            self.notify_on_instance_launch(topic)
            self.notify_on_instance_terminate(topic)
            self.notify_on_instance_launch_errors(topic)
            self.notify_on_instance_terminate_errors(topic)
    
    # Create custom ASG with built-in notifications
    asg = NotifyingAutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Creating a topic and ASG in a loop with notifications
    for i in range(3):
        topic = sns.Topic(scope, f"Topic{i}")
        asg = autoscaling.AutoScalingGroup(
            scope,
            f"ASG{i}",
            vpc=vpc,
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
            machine_image=ec2.AmazonLinuxImage(),
            min_capacity=1,
            max_capacity=3,
        )
        
        # ok: python-cdk-auto-scaling-group-scaling-notifications
        # Configure all notifications for each ASG in the loop
        asg.notify_on_instance_launch(topic)
        asg.notify_on_instance_terminate(topic)
        asg.notify_on_instance_launch_errors(topic)
        asg.notify_on_instance_terminate_errors(topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    topic = sns.Topic(scope, "Topic")
    
    # Creating ASG with conditional notifications based on environment
    env = "production"  # This would typically come from a context or parameter
    
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    
    # ok: python-cdk-auto-scaling-group-scaling-notifications
    # Configure all notifications conditionally
    if env == "production":
        asg.notify_on_instance_launch(topic)
        asg.notify_on_instance_terminate(topic)
        asg.notify_on_instance_launch_errors(topic)
        asg.notify_on_instance_terminate_errors(topic)
    else:
        # Even in non-production, we still configure all notifications
        dev_topic = sns.Topic(scope, "DevTopic")
        asg.notify_on_instance_launch(dev_topic)
        asg.notify_on_instance_terminate(dev_topic)
        asg.notify_on_instance_launch_errors(dev_topic)
        asg.notify_on_instance_terminate_errors(dev_topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Creating ASG with notifications to different topics based on event type
    launch_topic = sns.Topic(scope, "LaunchTopic")
    terminate_topic = sns.Topic(scope, "TerminateTopic")
    error_topic = sns.Topic(scope, "ErrorTopic")
    
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        machine_image=ec2.AmazonLinuxImage(),
        min_capacity=1,
        max_capacity=3,
    )
    
    # ok: python-cdk-auto-scaling-group-scaling-notifications
    # Configure notifications to different topics based on event type
    asg.notify_on_instance_launch(launch_topic)
    asg.notify_on_instance_terminate(terminate_topic)
    asg.notify_on_instance_launch_errors(error_topic)
    asg.notify_on_instance_terminate_errors(error_topic)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Creating a stack with multiple ASGs and topics
    class MultiAsgStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            vpc = ec2.Vpc(self, "VPC")
            
            # Create topics for different environments
            prod_topic = sns.Topic(self, "ProdTopic")
            dev_topic = sns.Topic(self, "DevTopic")
            
            # Create ASGs for different environments
            prod_asg = autoscaling.AutoScalingGroup(
                self,
                "ProdASG",
                vpc=vpc,
                instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
                machine_image=ec2.AmazonLinuxImage(),
                min_capacity=2,
                max_capacity=10,
            )
            
            dev_asg = autoscaling.AutoScalingGroup(
                self,
                "DevASG",
                vpc=vpc,
                instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
                machine_image=ec2.AmazonLinuxImage(),
                min_capacity=1,
                max_capacity=3,
            )
            
            # ok: python-cdk-auto-scaling-group-scaling-notifications
            # Configure all notifications for production ASG
            prod_asg.notify_on_instance_launch(prod_topic)
            prod_asg.notify_on_instance_terminate(prod_topic)
            prod_asg.notify_on_instance_launch_errors(prod_topic)
            prod_asg.notify_on_instance_terminate_errors(prod_topic)
            
            # ok: python-cdk-auto-scaling-group-scaling-notifications
            # Configure all notifications for development ASG
            dev_asg.notify_on_instance_launch(dev_topic)
            dev_asg.notify_on_instance_terminate(dev_topic)
            dev_asg.notify_on_instance_launch_errors(dev_topic)
            dev_asg.notify_on_instance_terminate_errors(dev_topic)
    
    # Create the stack
    app = App()
    MultiAsgStack(app, "MultiAsgStack")
# {/fact}