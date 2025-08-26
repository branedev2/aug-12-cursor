import aws_cdk as cdk
from aws_cdk import (
    aws_ec2 as ec2,
    aws_logs as logs,
    Stack,
    CfnOutput
)
from constructs import Construct

# True Positive Examples (vulnerable code - missing flow logs)

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a VPC without flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "VpcWithoutFlowLogs",
        max_azs=2,
        nat_gateways=1
    )
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating a VPC with minimal configuration, no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "MinimalVpc",
        ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
        vpc_name="minimal-vpc"
    )
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a VPC with subnet configuration but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "SubnetConfiguredVpc",
        ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
        subnet_configuration=[
            ec2.SubnetConfiguration(
                name="public",
                subnet_type=ec2.SubnetType.PUBLIC,
                cidr_mask=24
            ),
            ec2.SubnetConfiguration(
                name="private",
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                cidr_mask=24
            )
        ]
    )
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a VPC with NAT gateway configuration but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "NatGatewayVpc",
        nat_gateways=2,
        max_azs=3,
        enable_dns_hostnames=True,
        enable_dns_support=True
    )
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a VPC with custom CIDR but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "CustomCidrVpc",
        ip_addresses=ec2.IpAddresses.cidr("192.168.0.0/16"),
        max_azs=2
    )
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a VPC with gateway endpoints but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "VpcWithGatewayEndpoints")
    
    vpc.add_gateway_endpoint("S3Endpoint",
        service=ec2.GatewayVpcEndpointAwsService.S3
    )
    
    vpc.add_gateway_endpoint("DynamoDBEndpoint",
        service=ec2.GatewayVpcEndpointAwsService.DYNAMODB
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a VPC with interface endpoints but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "VpcWithInterfaceEndpoints")
    
    vpc.add_interface_endpoint("SsmEndpoint",
        service=ec2.InterfaceVpcEndpointAwsService.SSM
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a VPC with VPN connection but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "VpcWithVpn")
    
    customer_gateway = ec2.CfnCustomerGateway(scope, "CustomerGateway",
        bgp_asn=65000,
        ip_address="203.0.113.1",
        type="ipsec.1"
    )
    
    vpn_gateway = ec2.CfnVPNGateway(scope, "VpnGateway",
        type="ipsec.1"
    )
    
    ec2.CfnVPNConnection(scope, "VpnConnection",
        customer_gateway_id=customer_gateway.ref,
        vpn_gateway_id=vpn_gateway.ref,
        type="ipsec.1"
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a VPC with transit gateway attachment but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "VpcWithTransitGateway")
    
    transit_gateway = ec2.CfnTransitGateway(scope, "TransitGateway")
    
    ec2.CfnTransitGatewayAttachment(scope, "TgwAttachment",
        transit_gateway_id=transit_gateway.ref,
        vpc_id=vpc.vpc_id,
        subnet_ids=[subnet.subnet_id for subnet in vpc.private_subnets]
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a VPC with security groups but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "VpcWithSecurityGroups")
    
    security_group = ec2.SecurityGroup(scope, "SecurityGroup",
        vpc=vpc,
        description="Allow SSH access",
        allow_all_outbound=True
    )
    
    security_group.add_ingress_rule(
        ec2.Peer.any_ipv4(),
        ec2.Port.tcp(22),
        "Allow SSH access from anywhere"
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a VPC with network ACLs but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "VpcWithNetworkAcls")
    
    network_acl = ec2.NetworkAcl(scope, "NetworkAcl",
        vpc=vpc
    )
    
    network_acl.add_entry("AllowHTTP",
        cidr=ec2.AclCidr.any_ipv4(),
        rule_number=100,
        traffic=ec2.AclTraffic.tcp_port(80),
        direction=ec2.TrafficDirection.INGRESS,
        rule_action=ec2.Action.ALLOW
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a VPC with isolated subnets but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "VpcWithIsolatedSubnets",
        subnet_configuration=[
            ec2.SubnetConfiguration(
                name="isolated",
                subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                cidr_mask=24
            )
        ]
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a VPC with IPv6 support but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "VpcWithIpv6",
        ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
        enable_dns_support=True,
        enable_dns_hostnames=True,
        vpc_name="ipv6-vpc"
    )
    
    cfn_vpc = vpc.node.default_child
    cfn_vpc.add_property_override("EnableIpv6", True)
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a VPC with tags but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.Vpc(scope, "VpcWithTags")
    
    cdk.Tags.of(vpc).add("Environment", "Production")
    cdk.Tags.of(vpc).add("Department", "IT")
    cdk.Tags.of(vpc).add("CostCenter", "12345")
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a VPC using Cfn construct but no flow logs
    # ruleid: python-cdk-vpc-flow-logs-enabled
    vpc = ec2.CfnVPC(scope, "CfnVpc",
        cidr_block="10.0.0.0/16",
        enable_dns_support=True,
        enable_dns_hostnames=True
    )
    
    return vpc

# True Negative Examples (secure code - flow logs enabled)

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a VPC with flow logs enabled with default settings
    vpc = ec2.Vpc(scope, "VpcWithDefaultFlowLogs")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    flow_log = ec2.FlowLog.add_to_vpc(scope, "FlowLog", vpc)
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating a VPC with flow logs to CloudWatch
    vpc = ec2.Vpc(scope, "VpcWithCloudWatchFlowLogs")
    
    log_group = logs.LogGroup(scope, "FlowLogsGroup")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    flow_log = ec2.FlowLog(scope, "FlowLog",
        resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
        destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group)
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating a VPC with flow logs to S3
    vpc = ec2.Vpc(scope, "VpcWithS3FlowLogs")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    flow_log = ec2.FlowLog(scope, "FlowLog",
        resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
        destination=ec2.FlowLogDestination.to_s3()
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a VPC with flow logs with custom IAM role
    vpc = ec2.Vpc(scope, "VpcWithCustomRoleFlowLogs")
    
    log_group = logs.LogGroup(scope, "FlowLogsGroup")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    flow_log = ec2.FlowLog(scope, "FlowLog",
        resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
        destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group),
        traffic_type=ec2.FlowLogTrafficType.ALL
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a VPC with flow logs capturing only rejected traffic
    vpc = ec2.Vpc(scope: Construct, id: "VpcWithRejectedTrafficFlowLogs")
    
    log_group = logs.LogGroup(scope, "FlowLogsGroup")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    flow_log = ec2.FlowLog(scope, "FlowLog",
        resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
        destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group),
        traffic_type=ec2.FlowLogTrafficType.REJECT
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a VPC with flow logs capturing only accepted traffic
    vpc = ec2.Vpc(scope, "VpcWithAcceptedTrafficFlowLogs")
    
    log_group = logs.LogGroup(scope, "FlowLogsGroup")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    flow_log = ec2.FlowLog(scope, "FlowLog",
        resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
        destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group),
        traffic_type=ec2.FlowLogTrafficType.ACCEPT
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a VPC with flow logs with custom format
    vpc = ec2.Vpc(scope, "VpcWithCustomFormatFlowLogs")
    
    log_group = logs.LogGroup(scope, "FlowLogsGroup")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    flow_log = ec2.FlowLog(scope, "FlowLog",
        resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
        destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group),
        traffic_type=ec2.FlowLogTrafficType.ALL,
        log_format=ec2.FlowLogFormat.custom([
            ec2.LogFormat.VERSION,
            ec2.LogFormat.ACCOUNT_ID,
            ec2.LogFormat.INTERFACE_ID,
            ec2.LogFormat.SRC_ADDR,
            ec2.LogFormat.DST_ADDR,
            ec2.LogFormat.SRC_PORT,
            ec2.LogFormat.DST_PORT,
            ec2.LogFormat.PROTOCOL,
            ec2.LogFormat.PACKETS,
            ec2.LogFormat.BYTES,
            ec2.LogFormat.START,
            ec2.LogFormat.END,
            ec2.LogFormat.ACTION,
            ec2.LogFormat.LOG_STATUS
        ])
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a VPC with flow logs using max aggregation interval
    vpc = ec2.Vpc(scope, "VpcWithMaxAggregationFlowLogs")
    
    log_group = logs.LogGroup(scope, "FlowLogsGroup")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    flow_log = ec2.FlowLog(scope, "FlowLog",
        resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
        destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group),
        max_aggregation_interval=ec2.FlowLogMaxAggregationInterval.ONE_MINUTE
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a VPC with flow logs to S3 with custom prefix
    vpc = ec2.Vpc(scope, "VpcWithS3PrefixFlowLogs")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    flow_log = ec2.FlowLog(scope, "FlowLog",
        resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
        destination=ec2.FlowLogDestination.to_s3(
            bucket_name="my-flow-logs-bucket",
            key_prefix="vpc-flow-logs/"
        )
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a VPC with flow logs using CfnFlowLog
    vpc = ec2.Vpc(scope, "VpcWithCfnFlowLog")
    
    log_group = logs.LogGroup(scope, "FlowLogsGroup")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    flow_log = ec2.CfnFlowLog(scope, "FlowLog",
        resource_id=vpc.vpc_id,
        resource_type="VPC",
        traffic_type="ALL",
        log_destination_type="cloud-watch-logs",
        log_destination=log_group.log_group_arn
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a VPC with flow logs and adding them after VPC creation
    vpc = ec2.Vpc(scope, "VpcWithPostCreationFlowLogs")
    
    # Create the VPC first
    
    # Then add flow logs
    log_group = logs.LogGroup(scope, "FlowLogsGroup")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    ec2.FlowLog(scope, "FlowLog",
        resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
        destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group)
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a VPC with flow logs in a custom stack
    vpc = ec2.Vpc(scope, "VpcWithStackFlowLogs")
    
    # Create a separate stack for flow logs
    flow_logs_stack = Stack(scope, "FlowLogsStack")
    
    log_group = logs.LogGroup(flow_logs_stack, "FlowLogsGroup")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    ec2.FlowLog(flow_logs_stack, "FlowLog",
        resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
        destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group)
    )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a VPC with flow logs using helper function
    vpc = ec2.Vpc(scope, "VpcWithHelperFlowLogs")
    
    def add_flow_logs(vpc_resource):
        log_group = logs.LogGroup(scope, "FlowLogsGroup")
        # ok: python-cdk-vpc-flow-logs-enabled
        return ec2.FlowLog(scope, "FlowLog",
            resource_type=ec2.FlowLogResourceType.from_vpc(vpc_resource),
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group)
        )
    
    flow_log = add_flow_logs(vpc)
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a VPC with flow logs using conditional logic
    vpc = ec2.Vpc(scope, "VpcWithConditionalFlowLogs")
    
    enable_flow_logs = True
    
    if enable_flow_logs:
        log_group = logs.LogGroup(scope, "FlowLogsGroup")
        # ok: python-cdk-vpc-flow-logs-enabled
        flow_log = ec2.FlowLog(scope, "FlowLog",
            resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group)
        )
    
    return vpc

# {/fact}

# {fact rule=object-presence@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a VPC with flow logs and exporting outputs
    vpc = ec2.Vpc(scope, "VpcWithOutputsFlowLogs")
    
    log_group = logs.LogGroup(scope, "FlowLogsGroup")
    
    # ok: python-cdk-vpc-flow-logs-enabled
    flow_log = ec2.FlowLog(scope, "FlowLog",
        resource_type=ec2.FlowLogResourceType.from_vpc(vpc),
        destination=ec2.FlowLogDestination.to_cloud_watch_logs(log_group)
    )
    
    CfnOutput(scope, "VpcId", value=vpc.vpc_id)
    CfnOutput(scope, "FlowLogId", value=flow_log.flow_log_id)
    CfnOutput(scope, "LogGroupName", value=log_group.log_group_name)
    
    return vpc
# {/fact}