from aws_cdk import (
    aws_elasticbeanstalk as elasticbeanstalk,
    core,
    Stack,
    App,
    CfnOutput
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_1():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_2():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        # No option_settings provided
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_3():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:autoscaling:asg",
                option_name="MinSize",
                value="1"
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_4():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    options = [
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:ec2:instances",
            option_name="InstanceTypes",
            value="t3.micro"
        )
    ]
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=options
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_5():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    env = elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="true"
            )
            # Missing UpdateLevel setting
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_6():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="true"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="PreferredStartTime",
                value="Tue:09:00"
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_7():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="UpdateLevel",  # Correct option_name but wrong namespace
                value="minor"
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_8():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    options = []
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=options
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_9():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="UpdateLevel",
                value=""  # Empty value
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_10():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="false"  # Explicitly disabled
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_11():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="UpdateLevel",
                value="patch"  # Not set to 'minor'
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_12():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # Define options separately
    security_options = [
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:autoscaling:launchconfiguration",
            option_name="SecurityGroups",
            value="sg-12345678"
        )
    ]
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=security_options
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_13():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="true"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="UpdateLevel",
                value="none"  # Incorrect value
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_14():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="UpdateLevel",
                value="minor"
            )
            # Missing ManagedActionsEnabled setting
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=1}
def bad_case_15():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ruleid: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="true"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="OptionName",  # Wrong option name
                value="minor"
            )
        ]
    )
    
    app.synth()

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_1():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="true"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="UpdateLevel",
                value="minor"
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_2():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    options = [
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions",
            option_name="ManagedActionsEnabled",
            value="true"
        ),
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions:platformupdate",
            option_name="UpdateLevel",
            value="minor"
        ),
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions",
            option_name="PreferredStartTime",
            value="Mon:09:00"
        )
    ]
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=options
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_3():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    managed_update_options = [
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions",
            option_name="ManagedActionsEnabled",
            value="true"
        ),
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions:platformupdate",
            option_name="UpdateLevel",
            value="minor"
        )
    ]
    
    scaling_options = [
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:autoscaling:asg",
            option_name="MinSize",
            value="1"
        ),
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:autoscaling:asg",
            option_name="MaxSize",
            value="4"
        )
    ]
    
    all_options = managed_update_options + scaling_options
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=all_options
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_4():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="true"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="UpdateLevel",
                value="minor"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="PreferredStartTime",
                value="Tue:09:00"
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_5():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # Define managed update options
    managed_update_options = [
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions",
            option_name="ManagedActionsEnabled",
            value="true"
        ),
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions:platformupdate",
            option_name="UpdateLevel",
            value="minor"
        )
    ]
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    env = elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=managed_update_options
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_6():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="true"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="UpdateLevel",
                value="minor"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:ec2:instances",
                option_name="InstanceTypes",
                value="t3.micro"
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_7():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="true"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="UpdateLevel",
                value="minor"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:environment",
                option_name="EnvironmentType",
                value="LoadBalanced"
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_8():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # Create options with managed updates enabled
    options = []
    options.append(
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions",
            option_name="ManagedActionsEnabled",
            value="true"
        )
    )
    options.append(
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions:platformupdate",
            option_name="UpdateLevel",
            value="minor"
        )
    )
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=options
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_9():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="true"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="UpdateLevel",
                value="minor"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="InstanceRefreshEnabled",
                value="true"
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_10():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # Define different option groups
    managed_update_options = [
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions",
            option_name="ManagedActionsEnabled",
            value="true"
        ),
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions:platformupdate",
            option_name="UpdateLevel",
            value="minor"
        )
    ]
    
    instance_options = [
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:ec2:instances",
            option_name="InstanceTypes",
            value="t3.micro,t3.small"
        )
    ]
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=managed_update_options + instance_options
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_11():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="true"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="UpdateLevel",
                value="minor"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:autoscaling:launchconfiguration",
                option_name="SecurityGroups",
                value="sg-12345678"
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_12():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # Create a list for options
    option_settings = []
    
    # Add managed update options
    option_settings.append(
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions",
            option_name="ManagedActionsEnabled",
            value="true"
        )
    )
    
    option_settings.append(
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions:platformupdate",
            option_name="UpdateLevel",
            value="minor"
        )
    )
    
    # Add other configuration options
    option_settings.append(
        elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:environment",
            option_name="EnvironmentType",
            value="SingleInstance"
        )
    )
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=option_settings
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_13():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="true"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="PreferredStartTime",
                value="Sun:02:00"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="UpdateLevel",
                value="minor"
            )
        ]
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_14():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # Define options in a dictionary-like structure first
    option_dict = {
        "managed_actions": elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions",
            option_name="ManagedActionsEnabled",
            value="true"
        ),
        "update_level": elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions:platformupdate",
            option_name="UpdateLevel",
            value="minor"
        ),
        "instance_refresh": elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
            namespace="aws:elasticbeanstalk:managedactions:platformupdate",
            option_name="InstanceRefreshEnabled",
            value="false"
        )
    }
    
    # Convert to list
    option_list = list(option_dict.values())
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=option_list
    )
    
    app.synth()

# {/fact}

# {fact rule=improper-input-validation@v1.0 defects=0}
def good_case_15():
    app = App()
    stack = Stack(app, "ElasticBeanstalkStack")
    
    # ok: python-cdk-elastic-beanstalk-managed-updates-enabled
    elasticbeanstalk.CfnEnvironment(
        stack, 
        "Environment",
        application_name="MyApp",
        solution_stack_name="64bit Amazon Linux 2 v3.4.1 running Python 3.8",
        option_settings=[
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions",
                option_name="ManagedActionsEnabled",
                value="true"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:managedactions:platformupdate",
                option_name="UpdateLevel",
                value="minor"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:application:environment",
                option_name="DB_HOST",
                value="mydb.example.com"
            ),
            elasticbeanstalk.CfnEnvironment.OptionSettingProperty(
                namespace="aws:elasticbeanstalk:application:environment",
                option_name="DB_PORT",
                value="5432"
            )
        ]
    )
    
    app.synth()
# {/fact}