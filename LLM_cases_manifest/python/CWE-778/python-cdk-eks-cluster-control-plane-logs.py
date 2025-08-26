import aws_cdk as cdk
from aws_cdk import aws_eks as eks
from aws_cdk import aws_ec2 as ec2
from constructs import Construct

class EksClusterStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_1(app):
    # Creating an EKS cluster without any logging configuration
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        default_capacity=2
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_2(app):
    # Creating an EKS cluster with empty logging configuration
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        default_capacity=2,
        cluster_logging=[]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_3(app):
    # Creating an EKS cluster with incomplete logging configuration (missing audit)
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_4(app):
    # Creating an EKS cluster with incomplete logging configuration (missing api and audit)
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_5(app):
    # Creating an EKS cluster with incomplete logging configuration (only api)
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.API
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_6(app):
    # Creating an EKS cluster with incomplete logging configuration (only audit)
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.AUDIT
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_7(app):
    # Creating an EKS cluster with incomplete logging configuration (missing scheduler)
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_8(app):
    # Creating an EKS cluster with incomplete logging configuration (missing controller_manager)
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_9(app):
    # Creating an EKS cluster with incomplete logging configuration (missing authenticator)
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_10(app):
    # Creating an EKS cluster with incomplete logging configuration (only authenticator and scheduler)
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_11(app):
    # Creating an EKS cluster with incomplete logging configuration (only api and audit)
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_12(app):
    # Creating an EKS cluster with incomplete logging configuration (only controller_manager and scheduler)
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_13(app):
    # Creating an EKS cluster with incomplete logging configuration (api, audit, authenticator)
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_14(app):
    # Creating an EKS cluster with logging disabled
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=None
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_15(app):
    # Creating an EKS FargateCluster without logging configuration
    # ruleid: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.FargateCluster(
        app, "MyFargateCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_1(app):
    # Creating an EKS cluster with all required logging types
    # ok: python-cdk-eks-cluster-control-plane-logs
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_2(app):
    # Creating an EKS cluster with all required logging types using ALL enum
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.ALL
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_3(app):
    # Creating an EKS cluster with all required logging types explicitly defined
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_4(app):
    # Creating an EKS cluster with all required logging types and additional configuration
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ],
        endpoint_access=eks.EndpointAccess.PRIVATE
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_5(app):
    # Creating an EKS cluster with all required logging types and custom capacity
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=0,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    cluster.add_nodegroup_capacity("custom-ng",
        desired_size=2,
        min_size=1,
        max_size=3
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_6(app):
    # Creating an EKS FargateCluster with all required logging types
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.FargateCluster(
        app, "MyFargateCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_7(app):
    # Creating an EKS cluster with all required logging types and custom security group
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    security_group = ec2.SecurityGroup(app, "ClusterSG", vpc=vpc)
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        security_group=security_group,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_8(app):
    # Creating an EKS cluster with all required logging types using variable
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    logging_types = [
        eks.ClusterLoggingTypes.API,
        eks.ClusterLoggingTypes.AUDIT,
        eks.ClusterLoggingTypes.AUTHENTICATOR,
        eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
        eks.ClusterLoggingTypes.SCHEDULER
    ]
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        cluster_logging=logging_types
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_9(app):
    # Creating an EKS cluster with all required logging types and custom VPC options
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc", max_azs=3)
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        vpc_subnets=[{"subnetType": ec2.SubnetType.PRIVATE_WITH_NAT}],
        default_capacity=2,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_10(app):
    # Creating an EKS cluster with all required logging types and custom instance type
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        default_capacity_instance=ec2.InstanceType("t3.medium"),
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_11(app):
    # Creating an EKS cluster with all required logging types and custom node AMI type
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        default_capacity_instance=ec2.InstanceType("t3.medium"),
        default_capacity_type=eks.DefaultCapacityType.NODEGROUP,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_12(app):
    # Creating an EKS cluster with all required logging types and custom bootstrap options
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=0,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    
    cluster.add_nodegroup_capacity("custom-ng",
        desired_size=2,
        min_size=1,
        max_size=3,
        bootstrap_options={
            "container_runtime": "containerd",
            "kubelet_extra_args": "--node-labels=node-type=worker"
        }
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_13(app):
    # Creating an EKS cluster with all required logging types and custom role
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    role = cdk.aws_iam.Role(
        app, "ClusterRole",
        assumed_by=cdk.aws_iam.ServicePrincipal("eks.amazonaws.com"),
        managed_policies=[
            cdk.aws_iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSClusterPolicy")
        ]
    )
    
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        role=role,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_14(app):
    # Creating an EKS cluster with all required logging types and custom tags
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        tags={
            "Environment": "Production",
            "Department": "Operations"
        },
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_15(app):
    # Creating an EKS cluster with all required logging types and custom kubectl layer
    # ok: python-cdk-eks-cluster-control-plane-logs
    vpc = ec2.Vpc(app, "MyVpc")
    kubectl_layer = cdk.aws_lambda.LayerVersion(
        app, "KubectlLayer",
        code=cdk.aws_lambda.Code.from_asset("lambda/kubectl-layer"),
        compatible_runtimes=[cdk.aws_lambda.Runtime.PYTHON_3_9]
    )
    
    cluster = eks.Cluster(
        app, "MyCluster",
        version=eks.KubernetesVersion.V1_21,
        vpc=vpc,
        default_capacity=2,
        kubectl_layer=kubectl_layer,
        cluster_logging=[
            eks.ClusterLoggingTypes.API,
            eks.ClusterLoggingTypes.AUDIT,
            eks.ClusterLoggingTypes.AUTHENTICATOR,
            eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
            eks.ClusterLoggingTypes.SCHEDULER
        ]
    )
    return cluster

# {/fact}

def main():
    app = cdk.App()
    stack = EksClusterStack(app, "EksClusterStack")
    app.synth()

if __name__ == "__main__":
    main()