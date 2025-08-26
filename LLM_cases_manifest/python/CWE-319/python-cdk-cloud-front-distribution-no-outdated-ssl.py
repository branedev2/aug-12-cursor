import aws_cdk as cdk
from aws_cdk import (
    aws_cloudfront as cloudfront,
    aws_s3 as s3,
    aws_cloudfront_origins as origins,
    Stack,
    CfnOutput
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a CloudFront distribution with SSLv3 protocol
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
            origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER,
            viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.HTTPS_ONLY
        ),
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.SSL_V3
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1 protocol
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_0
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1 protocol in a variable
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    protocol_version = cloudfront.SecurityPolicyProtocol.TLS_V1_0
    
    # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=protocol_version
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a CloudFront distribution with SSLv3 protocol using a function
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    def get_protocol():
        return cloudfront.SecurityPolicyProtocol.SSL_V3
    
    # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=get_protocol()
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1 protocol in a conditional
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    use_secure = False
    protocol = cloudfront.SecurityPolicyProtocol.TLS_V1_2 if use_secure else cloudfront.SecurityPolicyProtocol.TLS_V1_0
    
    # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=protocol
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a CloudFront distribution with default protocol (which defaults to TLSv1)
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        )
        # No minimum_protocol_version specified, which might default to an insecure version
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a CloudFront distribution with SSLv3 protocol using a dictionary
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    config = {
        "protocol": cloudfront.SecurityPolicyProtocol.SSL_V3
    }
    
    # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=config["protocol"]
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1 protocol in a loop
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    protocols = [cloudfront.SecurityPolicyProtocol.TLS_V1_0]
    
    for i, protocol in enumerate(protocols):
        # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
        distribution = cloudfront.Distribution(scope, f"MyDistribution{i}",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origin,
            ),
            minimum_protocol_version=protocol
        )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a CloudFront distribution with SSLv3 protocol in a class method
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    class DistributionCreator:
        @staticmethod
        def create_distribution(scope, id, origin):
            # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
            return cloudfront.Distribution(scope, id,
                default_behavior=cloudfront.BehaviorOptions(
                    origin=origin,
                ),
                minimum_protocol_version=cloudfront.SecurityPolicyProtocol.SSL_V3
            )
    
    distribution = DistributionCreator.create_distribution(scope, "MyDistribution", origin)
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1 protocol using a custom stack
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    class CustomStack(Stack):
        def __init__(self, scope, id, **kwargs):
            super().__init__(scope, id, **kwargs)
            # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
            self.distribution = cloudfront.Distribution(self, "MyDistribution",
                default_behavior=cloudfront.BehaviorOptions(
                    origin=origin,
                ),
                minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_0
            )
    
    stack = CustomStack(scope, "CustomStack")
    return stack.distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a CloudFront distribution with SSLv3 protocol using kwargs
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    kwargs = {
        "default_behavior": cloudfront.BehaviorOptions(origin=origin),
        "minimum_protocol_version": cloudfront.SecurityPolicyProtocol.SSL_V3
    }
    
    # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution", **kwargs)
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1 protocol using a factory function
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    def create_distribution_config(protocol):
        return {
            "default_behavior": cloudfront.BehaviorOptions(origin=origin),
            "minimum_protocol_version": protocol
        }
    
    config = create_distribution_config(cloudfront.SecurityPolicyProtocol.TLS_V1_0)
    
    # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution", **config)
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a CloudFront distribution with SSLv3 protocol using environment variables
    import os
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    # Simulating environment variable (in a real scenario this would be os.environ.get())
    env_protocol = "SSLv3"
    
    protocol_map = {
        "SSLv3": cloudfront.SecurityPolicyProtocol.SSL_V3,
        "TLSv1": cloudfront.SecurityPolicyProtocol.TLS_V1_0,
        "TLSv1.1": cloudfront.SecurityPolicyProtocol.TLS_V1_1,
        "TLSv1.2": cloudfront.SecurityPolicyProtocol.TLS_V1_2,
    }
    
    # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=protocol_map[env_protocol]
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1 protocol using a custom construct
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    class CustomDistribution(Construct):
        def __init__(self, scope, id):
            super().__init__(scope, id)
            # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
            self.distribution = cloudfront.Distribution(self, "Distribution",
                default_behavior=cloudfront.BehaviorOptions(
                    origin=origin,
                ),
                minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_0
            )
    
    custom = CustomDistribution(scope, "CustomDist")
    return custom.distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a CloudFront distribution with SSLv3 protocol using a list of distributions
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    distributions = []
    
    # ruleid: python-cdk-cloud-front-distribution-no-outdated-ssl
    distributions.append(cloudfront.Distribution(scope, "MyDistribution1",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.SSL_V3
    ))
    
    return distributions[0]

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.1 protocol
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_1
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol in a variable
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    protocol_version = cloudfront.SecurityPolicyProtocol.TLS_V1_2
    
    # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=protocol_version
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol using a function
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    def get_protocol():
        return cloudfront.SecurityPolicyProtocol.TLS_V1_2
    
    # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=get_protocol()
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol in a conditional
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    use_secure = True
    protocol = cloudfront.SecurityPolicyProtocol.TLS_V1_2 if use_secure else cloudfront.SecurityPolicyProtocol.TLS_V1_1
    
    # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=protocol
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a CloudFront distribution with explicitly set TLSv1.2 protocol
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol using a dictionary
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    config = {
        "protocol": cloudfront.SecurityPolicyProtocol.TLS_V1_2
    }
    
    # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=config["protocol"]
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol in a loop
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    protocols = [cloudfront.SecurityPolicyProtocol.TLS_V1_2]
    
    for i, protocol in enumerate(protocols):
        # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
        distribution = cloudfront.Distribution(scope, f"MyDistribution{i}",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origin,
            ),
            minimum_protocol_version=protocol
        )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol in a class method
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    class DistributionCreator:
        @staticmethod
        def create_distribution(scope, id, origin):
            # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
            return cloudfront.Distribution(scope, id,
                default_behavior=cloudfront.BehaviorOptions(
                    origin=origin,
                ),
                minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2
            )
    
    distribution = DistributionCreator.create_distribution(scope, "MyDistribution", origin)
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol using a custom stack
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    class CustomStack(Stack):
        def __init__(self, scope, id, **kwargs):
            super().__init__(scope, id, **kwargs)
            # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
            self.distribution = cloudfront.Distribution(self, "MyDistribution",
                default_behavior=cloudfront.BehaviorOptions(
                    origin=origin,
                ),
                minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2
            )
    
    stack = CustomStack(scope, "CustomStack")
    return stack.distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol using kwargs
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    kwargs = {
        "default_behavior": cloudfront.BehaviorOptions(origin=origin),
        "minimum_protocol_version": cloudfront.SecurityPolicyProtocol.TLS_V1_2
    }
    
    # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution", **kwargs)
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol using a factory function
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    def create_distribution_config(protocol):
        return {
            "default_behavior": cloudfront.BehaviorOptions(origin=origin),
            "minimum_protocol_version": protocol
        }
    
    config = create_distribution_config(cloudfront.SecurityPolicyProtocol.TLS_V1_2)
    
    # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution", **config)
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol using environment variables
    import os
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    # Simulating environment variable (in a real scenario this would be os.environ.get())
    env_protocol = "TLSv1.2"
    
    protocol_map = {
        "SSLv3": cloudfront.SecurityPolicyProtocol.SSL_V3,
        "TLSv1": cloudfront.SecurityPolicyProtocol.TLS_V1_0,
        "TLSv1.1": cloudfront.SecurityPolicyProtocol.TLS_V1_1,
        "TLSv1.2": cloudfront.SecurityPolicyProtocol.TLS_V1_2,
    }
    
    # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=protocol_map[env_protocol]
    )
    return distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol using a custom construct
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    class CustomDistribution(Construct):
        def __init__(self, scope, id):
            super().__init__(scope, id)
            # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
            self.distribution = cloudfront.Distribution(self, "Distribution",
                default_behavior=cloudfront.BehaviorOptions(
                    origin=origin,
                ),
                minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2
            )
    
    custom = CustomDistribution(scope, "CustomDist")
    return custom.distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a CloudFront distribution with TLSv1.2 protocol using a list of distributions
    bucket = s3.Bucket(scope, "MyBucket")
    origin = origins.S3Origin(bucket)
    
    distributions = []
    
    # ok: python-cdk-cloud-front-distribution-no-outdated-ssl
    distributions.append(cloudfront.Distribution(scope, "MyDistribution1",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origin,
        ),
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2
    ))
    
    return distributions[0]
# {/fact}