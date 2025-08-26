import aws_cdk as cdk
from aws_cdk import (
    aws_ec2 as ec2,
    aws_autoscaling as autoscaling,
    Stack,
    App,
    CfnOutput
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_1():
    """EC2 instance created without any termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=ec2.Vpc(stack, "VPC")
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_2():
    """EC2 instance with termination protection explicitly disabled"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        disable_api_termination=False
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_3():
    """EC2 instance created using CfnInstance without termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    subnet = vpc.public_subnets[0]
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.CfnInstance(stack, "Instance",
        instance_type="t2.micro",
        image_id="ami-12345678",
        subnet_id=subnet.subnet_id
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_4():
    """EC2 instance created with CfnInstance and explicitly disabled termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    subnet = vpc.public_subnets[0]
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.CfnInstance(stack, "Instance",
        instance_type="t2.micro",
        image_id="ami-12345678",
        subnet_id=subnet.subnet_id,
        disable_api_termination=False
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_5():
    """Multiple EC2 instances created without termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    for i in range(3):
        # ruleid: python-cdk-ec2-instance-termination-protection
        instance = ec2.Instance(stack, f"Instance{i}",
            instance_type=ec2.InstanceType("t2.micro"),
            machine_image=ec2.MachineImage.latest_amazon_linux(),
            vpc=vpc
        )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_6():
    """EC2 instance created with complex configuration but missing termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    security_group = ec2.SecurityGroup(stack, "SecurityGroup", vpc=vpc)
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.large"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        security_group=security_group,
        key_name="my-key-pair",
        role=ec2.Role(stack, "InstanceRole", 
            assumed_by=ec2.ServicePrincipal("ec2.amazonaws.com")
        ),
        block_devices=[
            ec2.BlockDevice(
                device_name="/dev/sda1",
                volume=ec2.BlockDeviceVolume.ebs(100)
            )
        ]
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_7():
    """EC2 instance created with user data but no termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    user_data = ec2.UserData.for_linux()
    user_data.add_commands("yum update -y", "yum install -y httpd", "systemctl start httpd")
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "WebServer",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        user_data=user_data
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_8():
    """EC2 instance created in a custom stack class without termination protection"""
    class CustomInfraStack(Stack):
        def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
            super().__init__(scope, construct_id, **kwargs)
            
            vpc = ec2.Vpc(self, "VPC")
            
            # ruleid: python-cdk-ec2-instance-termination-protection
            self.instance = ec2.Instance(self, "Instance",
                instance_type=ec2.InstanceType("t2.micro"),
                machine_image=ec2.MachineImage.latest_amazon_linux(),
                vpc=vpc
            )
    
    app = cdk.App()
    stack = CustomInfraStack(app, "CustomStack")
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_9():
    """EC2 instance created with a condition but no termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    environment = "production"
    instance_type = "t2.micro" if environment == "dev" else "m5.large"
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType(instance_type),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_10():
    """EC2 instance with advanced networking but no termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC", max_azs=3)
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT)
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_11():
    """EC2 instance created with CloudFormation init but no termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    init = ec2.CloudFormationInit.from_elements(
        ec2.InitFile.from_string("/etc/nginx/nginx.conf", "worker_processes auto;")
    )
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        init=init
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_12():
    """EC2 instance with EBS volumes but no termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        block_devices=[
            ec2.BlockDevice(
                device_name="/dev/sda1",
                volume=ec2.BlockDeviceVolume.ebs(100, encrypted=True)
            ),
            ec2.BlockDevice(
                device_name="/dev/sdf",
                volume=ec2.BlockDeviceVolume.ebs(500, encrypted=True)
            )
        ]
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_13():
    """EC2 instance with signals but no termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        init=ec2.CloudFormationInit.from_elements(),
        signals=ec2.Signals.wait_for_all(timeout=cdk.Duration.minutes(5))
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_14():
    """EC2 instance with detailed monitoring but no termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.CfnInstance(stack, "Instance",
        instance_type="t2.micro",
        image_id="ami-12345678",
        subnet_id=vpc.public_subnets[0].subnet_id,
        monitoring=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_15():
    """EC2 instance with tags but no termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ruleid: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc
    )
    
    cdk.Tags.of(instance).add("Environment", "Production")
    cdk.Tags.of(instance).add("CriticalData", "True")
    cdk.Tags.of(instance).add("BackupRequired", "Daily")
    
    return stack

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_1():
    """EC2 instance with termination protection enabled"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        disable_api_termination=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_2():
    """EC2 instance created with CfnInstance and termination protection enabled"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    subnet = vpc.public_subnets[0]
    
    # ok: python-cdk-ec2-instance-termination-protection
    instance = ec2.CfnInstance(stack, "Instance",
        instance_type="t2.micro",
        image_id="ami-12345678",
        subnet_id=subnet.subnet_id,
        disable_api_termination=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_3():
    """Multiple EC2 instances with termination protection enabled"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    for i in range(3):
        # ok: python-cdk-ec2-instance-termination-protection
        instance = ec2.Instance(stack, f"Instance{i}",
            instance_type=ec2.InstanceType("t2.micro"),
            machine_image=ec2.MachineImage.latest_amazon_linux(),
            vpc=vpc,
            disable_api_termination=True
        )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_4():
    """EC2 instance in AutoScalingGroup (ASG) - exempt from rule"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-ec2-instance-termination-protection
    asg = autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        min_capacity=2,
        max_capacity=5
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_5():
    """EC2 instance with complex configuration and termination protection enabled"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    security_group = ec2.SecurityGroup(stack, "SecurityGroup", vpc=vpc)
    
    # ok: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.large"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        security_group=security_group,
        key_name="my-key-pair",
        role=ec2.Role(stack, "InstanceRole", 
            assumed_by=ec2.ServicePrincipal("ec2.amazonaws.com")
        ),
        block_devices=[
            ec2.BlockDevice(
                device_name="/dev/sda1",
                volume=ec2.BlockDeviceVolume.ebs(100)
            )
        ],
        disable_api_termination=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_6():
    """EC2 instance with user data and termination protection enabled"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    user_data = ec2.UserData.for_linux()
    user_data.add_commands("yum update -y", "yum install -y httpd", "systemctl start httpd")
    
    # ok: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "WebServer",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        user_data=user_data,
        disable_api_termination=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_7():
    """EC2 instance created in a custom stack class with termination protection"""
    class CustomInfraStack(Stack):
        def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
            super().__init__(scope, construct_id, **kwargs)
            
            vpc = ec2.Vpc(self, "VPC")
            
            # ok: python-cdk-ec2-instance-termination-protection
            self.instance = ec2.Instance(self, "Instance",
                instance_type=ec2.InstanceType("t2.micro"),
                machine_image=ec2.MachineImage.latest_amazon_linux(),
                vpc=vpc,
                disable_api_termination=True
            )
    
    app = cdk.App()
    stack = CustomInfraStack(app, "CustomStack")
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_8():
    """EC2 instance created with a condition and termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    environment = "production"
    instance_type = "t2.micro" if environment == "dev" else "m5.large"
    
    # ok: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType(instance_type),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        disable_api_termination=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_9():
    """EC2 instance with advanced networking and termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC", max_azs=3)
    
    # ok: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        vpc_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT),
        disable_api_termination=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_10():
    """EC2 instance created with CloudFormation init and termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    init = ec2.CloudFormationInit.from_elements(
        ec2.InitFile.from_string("/etc/nginx/nginx.conf", "worker_processes auto;")
    )
    
    # ok: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        init=init,
        disable_api_termination=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_11():
    """EC2 instance with EBS volumes and termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        block_devices=[
            ec2.BlockDevice(
                device_name="/dev/sda1",
                volume=ec2.BlockDeviceVolume.ebs(100, encrypted=True)
            ),
            ec2.BlockDevice(
                device_name="/dev/sdf",
                volume=ec2.BlockDeviceVolume.ebs(500, encrypted=True)
            )
        ],
        disable_api_termination=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_12():
    """EC2 instance with signals and termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        init=ec2.CloudFormationInit.from_elements(),
        signals=ec2.Signals.wait_for_all(timeout=cdk.Duration.minutes(5)),
        disable_api_termination=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_13():
    """EC2 instance with detailed monitoring and termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-ec2-instance-termination-protection
    instance = ec2.CfnInstance(stack, "Instance",
        instance_type="t2.micro",
        image_id="ami-12345678",
        subnet_id=vpc.public_subnets[0].subnet_id,
        monitoring=True,
        disable_api_termination=True
    )
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_14():
    """EC2 instance with tags and termination protection"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-ec2-instance-termination-protection
    instance = ec2.Instance(stack, "Instance",
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        vpc=vpc,
        disable_api_termination=True
    )
    
    cdk.Tags.of(instance).add("Environment", "Production")
    cdk.Tags.of(instance).add("CriticalData", "True")
    cdk.Tags.of(instance).add("BackupRequired", "Daily")
    
    return stack

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_15():
    """EC2 instance in ASG with lifecycle hook - exempt from rule"""
    app = cdk.App()
    stack = cdk.Stack(app, "MyStack")
    
    vpc = ec2.Vpc(stack, "VPC")
    
    # ok: python-cdk-ec2-instance-termination-protection
    asg = autoscaling.AutoScalingGroup(stack, "ASG",
        vpc=vpc,
        instance_type=ec2.InstanceType("t2.micro"),
        machine_image=ec2.MachineImage.latest_amazon_linux(),
        min_capacity=2,
        max_capacity=5
    )
    
    asg.add_lifecycle_hook("TerminationHook",
        lifecycle_transition=autoscaling.LifecycleTransition.INSTANCE_TERMINATING,
        notification_target=autoscaling.NotificationTarget.topic(cdk.aws_sns.Topic(stack, "Topic")),
        default_result=autoscaling.DefaultResult.CONTINUE,
        heartbeat_timeout=cdk.Duration.minutes(5)
    )
    
    return stack
# {/fact}