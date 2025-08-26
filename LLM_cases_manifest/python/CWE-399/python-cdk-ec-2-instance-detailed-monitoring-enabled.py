import aws_cdk as cdk
from aws_cdk import (
    aws_autoscaling as autoscaling,
    aws_ec2 as ec2,
    Stack,
    App,
)
from constructs import Construct


# True Positive Examples (Vulnerable Code)

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        # Missing detailed_monitoring configuration
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=autoscaling.Monitoring.BASIC,  # Explicitly setting BASIC monitoring
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    asg = autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
    )
    # Default is BASIC monitoring


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Creating an EC2 instance without detailed monitoring
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    instance = ec2.Instance(
        scope,
        "Instance",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        detailed_monitoring=False,  # Explicitly disabling detailed monitoring
    )
    
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=instance.instance_type,
        machine_image=instance.machine_image,
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    monitoring_config = autoscaling.Monitoring.BASIC
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=monitoring_config,  # Using variable with BASIC monitoring
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=autoscaling.Monitoring.BASIC,
        # Other configurations but no detailed monitoring
        min_capacity=2,
        max_capacity=10,
        desired_capacity=2,
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Creating EC2 instance with detailed monitoring but ASG without it
    instance = ec2.Instance(
        scope,
        "Instance",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        detailed_monitoring=True,
    )
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=instance.instance_type,
        machine_image=instance.machine_image,
        instance_monitoring=autoscaling.Monitoring.BASIC,  # Still using BASIC in ASG
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Using conditional logic that results in BASIC monitoring
    enable_detailed = False
    monitoring_type = autoscaling.Monitoring.DETAILED if enable_detailed else autoscaling.Monitoring.BASIC
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=monitoring_type,  # Will be BASIC
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    asg_props = {
        "vpc": vpc,
        "instance_type": ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        "machine_image": ec2.AmazonLinuxImage(),
        "instance_monitoring": autoscaling.Monitoring.BASIC,
    }
    
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        **asg_props
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        # No instance_monitoring specified, defaults to BASIC
        key_name="my-key-pair",
        security_group=ec2.SecurityGroup(scope, "SecurityGroup", vpc=vpc),
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Creating multiple ASGs, all with BASIC monitoring
    for i in range(3):
        # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
        autoscaling.AutoScalingGroup(
            scope,
            f"ASG-{i}",
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
            ),
            machine_image=ec2.AmazonLinuxImage(),
            instance_monitoring=autoscaling.Monitoring.BASIC,
        )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    launch_template = ec2.LaunchTemplate(
        scope,
        "LaunchTemplate",
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        detailed_monitoring=False,  # Explicitly disabling detailed monitoring
    )
    
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        launch_template=launch_template,
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=autoscaling.Monitoring.BASIC,
        health_check=autoscaling.HealthCheck.ec2(grace=cdk.Duration.minutes(5)),
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Using a function that returns BASIC monitoring
    def get_monitoring_config():
        return autoscaling.Monitoring.BASIC
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=get_monitoring_config(),
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ruleid: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=autoscaling.Monitoring.BASIC,
        user_data=ec2.UserData.for_linux(),
    )


# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=autoscaling.Monitoring.DETAILED,  # Explicitly enabling detailed monitoring
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Creating an EC2 instance with detailed monitoring
    instance = ec2.Instance(
        scope,
        "Instance",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        detailed_monitoring=True,  # Enabling detailed monitoring
    )
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=instance.instance_type,
        machine_image=instance.machine_image,
        instance_monitoring=autoscaling.Monitoring.DETAILED,
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    monitoring_config = autoscaling.Monitoring.DETAILED
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=monitoring_config,  # Using variable with DETAILED monitoring
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=autoscaling.Monitoring.DETAILED,
        min_capacity=2,
        max_capacity=10,
        desired_capacity=2,
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Using conditional logic that results in DETAILED monitoring
    enable_detailed = True
    monitoring_type = autoscaling.Monitoring.DETAILED if enable_detailed else autoscaling.Monitoring.BASIC
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=monitoring_type,  # Will be DETAILED
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    asg_props = {
        "vpc": vpc,
        "instance_type": ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO),
        "machine_image": ec2.AmazonLinuxImage(),
        "instance_monitoring": autoscaling.Monitoring.DETAILED,
    }
    
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        **asg_props
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Creating multiple ASGs, all with DETAILED monitoring
    for i in range(3):
        # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
        autoscaling.AutoScalingGroup(
            scope,
            f"ASG-{i}",
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
            ),
            machine_image=ec2.AmazonLinuxImage(),
            instance_monitoring=autoscaling.Monitoring.DETAILED,
        )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    launch_template = ec2.LaunchTemplate(
        scope,
        "LaunchTemplate",
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        detailed_monitoring=True,  # Explicitly enabling detailed monitoring
    )
    
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        launch_template=launch_template,
        instance_monitoring=autoscaling.Monitoring.DETAILED,
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Using a function that returns DETAILED monitoring
    def get_monitoring_config():
        return autoscaling.Monitoring.DETAILED
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=get_monitoring_config(),
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=autoscaling.Monitoring.DETAILED,
        health_check=autoscaling.HealthCheck.ec2(grace=cdk.Duration.minutes(5)),
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=autoscaling.Monitoring.DETAILED,
        user_data=ec2.UserData.for_linux(),
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Creating a custom class that extends AutoScalingGroup with detailed monitoring
    class DetailedMonitoringASG(autoscaling.AutoScalingGroup):
        def __init__(self, scope, id, **kwargs):
            kwargs["instance_monitoring"] = autoscaling.Monitoring.DETAILED
            super().__init__(scope, id, **kwargs)
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    DetailedMonitoringASG(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=autoscaling.Monitoring.DETAILED,
        signals=autoscaling.Signals.wait_for_all(
            timeout=cdk.Duration.minutes(10)
        ),
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Using environment variables to determine monitoring level
    import os
    monitoring_level = os.environ.get("MONITORING_LEVEL", "DETAILED")
    monitoring = autoscaling.Monitoring.DETAILED if monitoring_level == "DETAILED" else autoscaling.Monitoring.BASIC
    
    # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
    autoscaling.AutoScalingGroup(
        scope,
        "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType.of(
            ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
        ),
        machine_image=ec2.AmazonLinuxImage(),
        instance_monitoring=autoscaling.Monitoring.DETAILED,  # Explicitly setting to DETAILED regardless of env var
    )


# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "VPC")
    
    # Creating a stack with multiple ASGs, all with detailed monitoring
    class MultiAsgStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            for i in range(3):
                # ok: python-cdk-ec-2-instance-detailed-monitoring-enabled
                autoscaling.AutoScalingGroup(
                    self,
                    f"ASG-{i}",
                    vpc=vpc,
                    instance_type=ec2.InstanceType.of(
                        ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.MICRO
                    ),
                    machine_image=ec2.AmazonLinuxImage(),
                    instance_monitoring=autoscaling.Monitoring.DETAILED,
                )
    
    app = App()
    MultiAsgStack(app, "MultiAsgStack")
# {/fact}