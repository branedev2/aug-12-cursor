import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2
from constructs import Construct

# True Positives (vulnerable code - missing descriptions)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ruleid: python-cdk-ec-2-security-group-description
    security_group = ec2.SecurityGroup(scope, "MySG", vpc=vpc)
    security_group.add_ingress_rule(
        peer=ec2.Peer.any_ipv4(),
        connection=ec2.Port.tcp(22)
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ruleid: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope, 
        "WebServerSG",
        vpc=vpc,
        allow_all_outbound=True
    )
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ruleid: python-cdk-ec-2-security-group-description
    db_sg = ec2.SecurityGroup(
        scope,
        "DatabaseSG",
        vpc=vpc,
        security_group_name="database-sg"
    )
    db_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(3306))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # Create multiple security groups without descriptions
    # ruleid: python-cdk-ec-2-security-group-description
    web_sg = ec2.SecurityGroup(scope, "WebSG", vpc=vpc)
    # ruleid: python-cdk-ec-2-security-group-description
    app_sg = ec2.SecurityGroup(scope, "AppSG", vpc=vpc)
    
    web_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80))
    app_sg.add_ingress_rule(web_sg, ec2.Port.tcp(8080))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ruleid: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "ElasticLoadBalancerSG",
        vpc=vpc,
        allow_all_outbound=True,
        security_group_name="elb-sg"
    )
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ruleid: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(scope, "CacheSG", vpc=vpc)
    
    # Add multiple ingress rules
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(6379))
    sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(22))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # Create security group with empty string description (effectively no description)
    # ruleid: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "EmptyDescSG",
        vpc=vpc,
        description=""
    )
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    props = {
        "vpc": vpc,
        "allow_all_outbound": True
    }
    # ruleid: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(scope, "PropsSG", **props)
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ruleid: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "KafkaSG",
        vpc=vpc,
        security_group_name="kafka-broker-sg"
    )
    # Multiple ports
    for port in [9092, 9093, 2181]:
        sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(port))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # Using None as description (effectively no description)
    # ruleid: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "NoneDescSG",
        vpc=vpc,
        description=None
    )
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ruleid: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "MongoDBSG",
        vpc=vpc,
        allow_all_outbound=False
    )
    sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(27017))
    sg.add_egress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # Creating security group in a conditional block without description
    if vpc.vpc_id:
        # ruleid: python-cdk-ec-2-security-group-description
        sg = ec2.SecurityGroup(
            scope,
            "ConditionalSG",
            vpc=vpc
        )
        sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ruleid: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "RedshiftSG",
        vpc=vpc,
        security_group_name="redshift-cluster-sg"
    )
    sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(5439))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ruleid: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(scope, "RDPSG", vpc=vpc)
    
    # Windows RDP access
    sg.add_ingress_rule(
        peer=ec2.Peer.ipv4("192.168.1.0/24"),
        connection=ec2.Port.tcp(3389),
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # Using whitespace as description (effectively no useful description)
    # ruleid: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "WhitespaceDescSG",
        vpc=vpc,
        description="   "
    )
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22))

# True Negatives (secure code - with descriptions)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ok: python-cdk-ec-2-security-group-description
    security_group = ec2.SecurityGroup(
        scope, 
        "MySG", 
        vpc=vpc,
        description="Security group for SSH access to EC2 instances"
    )
    security_group.add_ingress_rule(
        peer=ec2.Peer.any_ipv4(),
        connection=ec2.Port.tcp(22)
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ok: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope, 
        "WebServerSG",
        vpc=vpc,
        allow_all_outbound=True,
        description="Security group for web servers allowing HTTP traffic"
    )
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ok: python-cdk-ec-2-security-group-description
    db_sg = ec2.SecurityGroup(
        scope,
        "DatabaseSG",
        vpc=vpc,
        security_group_name="database-sg",
        description="Security group for MySQL database instances"
    )
    db_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(3306))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # Create multiple security groups with descriptions
    # ok: python-cdk-ec-2-security-group-description
    web_sg = ec2.SecurityGroup(
        scope, 
        "WebSG", 
        vpc=vpc,
        description="Security group for web tier"
    )
    # ok: python-cdk-ec-2-security-group-description
    app_sg = ec2.SecurityGroup(
        scope, 
        "AppSG", 
        vpc=vpc,
        description="Security group for application tier"
    )
    
    web_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80))
    app_sg.add_ingress_rule(web_sg, ec2.Port.tcp(8080))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ok: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "ElasticLoadBalancerSG",
        vpc=vpc,
        allow_all_outbound=True,
        security_group_name="elb-sg",
        description="Security group for Elastic Load Balancer with HTTPS access"
    )
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ok: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope, 
        "CacheSG", 
        vpc=vpc,
        description="Security group for Redis cache instances"
    )
    
    # Add multiple ingress rules
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(6379))
    sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(22))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    desc = "Security group for bastion hosts with SSH access"
    # ok: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "BastionSG",
        vpc=vpc,
        description=desc
    )
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    props = {
        "vpc": vpc,
        "allow_all_outbound": True,
        "description": "Security group created from properties dictionary"
    }
    # ok: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(scope, "PropsSG", **props)
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ok: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "KafkaSG",
        vpc=vpc,
        security_group_name="kafka-broker-sg",
        description="Security group for Kafka brokers with multiple ports"
    )
    # Multiple ports
    for port in [9092, 9093, 2181]:
        sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(port))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    env = "prod"
    # Dynamic description based on environment
    # ok: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "DynamicDescSG",
        vpc=vpc,
        description=f"Security group for {env} environment"
    )
    sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ok: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "MongoDBSG",
        vpc=vpc,
        allow_all_outbound=False,
        description="Security group for MongoDB with restricted outbound traffic"
    )
    sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(27017))
    sg.add_egress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # Creating security group in a conditional block with description
    if vpc.vpc_id:
        # ok: python-cdk-ec-2-security-group-description
        sg = ec2.SecurityGroup(
            scope,
            "ConditionalSG",
            vpc=vpc,
            description="Security group created conditionally"
        )
        sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(22))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ok: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "RedshiftSG",
        vpc=vpc,
        security_group_name="redshift-cluster-sg",
        description="Security group for Redshift cluster with access from internal network"
    )
    sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/16"), ec2.Port.tcp(5439))

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # ok: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope, 
        "RDPSG", 
        vpc=vpc,
        description="Security group for Windows instances with RDP access"
    )
    
    # Windows RDP access
    sg.add_ingress_rule(
        peer=ec2.Peer.ipv4("192.168.1.0/24"),
        connection=ec2.Port.tcp(3389),
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    vpc = ec2.Vpc(scope, "MyVpc")
    # Using a detailed description
    # ok: python-cdk-ec-2-security-group-description
    sg = ec2.SecurityGroup(
        scope,
        "DetailedDescSG",
        vpc=vpc,
        description="Security group for internal services with specific access controls and compliance requirements"
    )
    sg.add_ingress_rule(ec2.Peer.ipv4("10.0.0.0/8"), ec2.Port.tcp(443))
# {/fact}