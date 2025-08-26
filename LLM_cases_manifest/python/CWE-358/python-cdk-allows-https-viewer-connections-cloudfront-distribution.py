import aws_cdk as cdk
from aws_cdk import (
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_s3 as s3,
    aws_certificatemanager as acm,
    Stack,
    CfnOutput
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Using default CloudFront certificate without specifying minimum protocol version
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        )
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Using CloudFront certificate with TLSv1 (insecure)
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        certificate=None,
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Using custom certificate but with vip SSL support method
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        certificate=certificate,
        ssl_support_method=cloudfront.SSLMethod.VIP
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Using CloudFront certificate with TLSv1_2016 (insecure)
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2016
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Using CloudFront certificate with VIP method and TLSv1
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        certificate=certificate,
        ssl_support_method=cloudfront.SSLMethod.VIP,
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Using CloudFront certificate with explicit default values
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        certificate=None,
        ssl_support_method=None,
        minimum_protocol_version=None
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Using CloudFront certificate with TLSv1_2_2018 but VIP method
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        certificate=certificate,
        ssl_support_method=cloudfront.SSLMethod.VIP,
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2018
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Using CloudFront certificate with TLSv1_2019
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2019
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Using CloudFront with distribution config
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        distribution_config=cloudfront.DistributionConfig(
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(bucket)
            )
        )
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Using CloudFront with distribution config and TLSv1
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        distribution_config=cloudfront.DistributionConfig(
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(bucket)
            ),
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1
        )
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Using CloudFront with L1 construct
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.CfnDistribution(
        scope, 
        "Distribution",
        distribution_config=cloudfront.CfnDistribution.DistributionConfigProperty(
            origins=[cloudfront.CfnDistribution.OriginProperty(
                domain_name=bucket.bucket_domain_name,
                id="myS3Origin",
                s3_origin_config=cloudfront.CfnDistribution.S3OriginConfigProperty(
                    origin_access_identity=""
                )
            )],
            default_cache_behavior=cloudfront.CfnDistribution.DefaultCacheBehaviorProperty(
                target_origin_id="myS3Origin",
                viewer_protocol_policy="redirect-to-https",
                forwarded_values=cloudfront.CfnDistribution.ForwardedValuesProperty(
                    query_string=False,
                    cookies=cloudfront.CfnDistribution.CookiesProperty(
                        forward="none"
                    )
                )
            ),
            enabled=True
        )
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Using CloudFront with L1 construct and TLSv1
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.CfnDistribution(
        scope, 
        "Distribution",
        distribution_config=cloudfront.CfnDistribution.DistributionConfigProperty(
            origins=[cloudfront.CfnDistribution.OriginProperty(
                domain_name=bucket.bucket_domain_name,
                id="myS3Origin",
                s3_origin_config=cloudfront.CfnDistribution.S3OriginConfigProperty(
                    origin_access_identity=""
                )
            )],
            default_cache_behavior=cloudfront.CfnDistribution.DefaultCacheBehaviorProperty(
                target_origin_id="myS3Origin",
                viewer_protocol_policy="redirect-to-https",
                forwarded_values=cloudfront.CfnDistribution.ForwardedValuesProperty(
                    query_string=False,
                    cookies=cloudfront.CfnDistribution.CookiesProperty(
                        forward="none"
                    )
                )
            ),
            enabled=True,
            viewer_certificate=cloudfront.CfnDistribution.ViewerCertificateProperty(
                cloud_front_default_certificate=True,
                minimum_protocol_version="TLSv1"
            )
        )
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Using CloudFront with L1 construct and VIP method
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.CfnDistribution(
        scope, 
        "Distribution",
        distribution_config=cloudfront.CfnDistribution.DistributionConfigProperty(
            origins=[cloudfront.CfnDistribution.OriginProperty(
                domain_name=bucket.bucket_domain_name,
                id="myS3Origin",
                s3_origin_config=cloudfront.CfnDistribution.S3OriginConfigProperty(
                    origin_access_identity=""
                )
            )],
            default_cache_behavior=cloudfront.CfnDistribution.DefaultCacheBehaviorProperty(
                target_origin_id="myS3Origin",
                viewer_protocol_policy="redirect-to-https",
                forwarded_values=cloudfront.CfnDistribution.ForwardedValuesProperty(
                    query_string=False,
                    cookies=cloudfront.CfnDistribution.CookiesProperty(
                        forward="none"
                    )
                )
            ),
            enabled=True,
            viewer_certificate=cloudfront.CfnDistribution.ViewerCertificateProperty(
                acm_certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/abcdef",
                ssl_support_method="vip"
            )
        )
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Using CloudFront with L1 construct, VIP method and TLSv1
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.CfnDistribution(
        scope, 
        "Distribution",
        distribution_config=cloudfront.CfnDistribution.DistributionConfigProperty(
            origins=[cloudfront.CfnDistribution.OriginProperty(
                domain_name=bucket.bucket_domain_name,
                id="myS3Origin",
                s3_origin_config=cloudfront.CfnDistribution.S3OriginConfigProperty(
                    origin_access_identity=""
                )
            )],
            default_cache_behavior=cloudfront.CfnDistribution.DefaultCacheBehaviorProperty(
                target_origin_id="myS3Origin",
                viewer_protocol_policy="redirect-to-https",
                forwarded_values=cloudfront.CfnDistribution.ForwardedValuesProperty(
                    query_string=False,
                    cookies=cloudfront.CfnDistribution.CookiesProperty(
                        forward="none"
                    )
                )
            ),
            enabled=True,
            viewer_certificate=cloudfront.CfnDistribution.ViewerCertificateProperty(
                acm_certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/abcdef",
                ssl_support_method="vip",
                minimum_protocol_version="TLSv1"
            )
        )
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Using CloudFront with L1 construct and default certificate
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.CfnDistribution(
        scope, 
        "Distribution",
        distribution_config=cloudfront.CfnDistribution.DistributionConfigProperty(
            origins=[cloudfront.CfnDistribution.OriginProperty(
                domain_name=bucket.bucket_domain_name,
                id="myS3Origin",
                s3_origin_config=cloudfront.CfnDistribution.S3OriginConfigProperty(
                    origin_access_identity=""
                )
            )],
            default_cache_behavior=cloudfront.CfnDistribution.DefaultCacheBehaviorProperty(
                target_origin_id="myS3Origin",
                viewer_protocol_policy="redirect-to-https",
                forwarded_values=cloudfront.CfnDistribution.ForwardedValuesProperty(
                    query_string=False,
                    cookies=cloudfront.CfnDistribution.CookiesProperty(
                        forward="none"
                    )
                )
            ),
            enabled=True,
            viewer_certificate=cloudfront.CfnDistribution.ViewerCertificateProperty(
                cloud_front_default_certificate=True
            )
        )
    )
    
    return distribution

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Using custom certificate with TLSv1.2 and SNI
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        certificate=certificate,
        ssl_support_method=cloudfront.SSLMethod.SNI,
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2018
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Using custom certificate with TLSv1.2 and SNI
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        certificate=certificate,
        ssl_support_method=cloudfront.SSLMethod.SNI,
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Using custom certificate with TLSv1.2 and SNI
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        certificate=certificate,
        ssl_support_method=cloudfront.SSLMethod.SNI,
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Using custom certificate with TLSv1.1 and SNI
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        certificate=certificate,
        ssl_support_method=cloudfront.SSLMethod.SNI,
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_1_2016
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Using custom certificate with TLSv1.2 and SNI via distribution config
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        distribution_config=cloudfront.DistributionConfig(
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(bucket)
            ),
            certificate=certificate,
            ssl_support_method=cloudfront.SSLMethod.SNI,
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2018
        )
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Using L1 construct with TLSv1.2 and SNI
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.CfnDistribution(
        scope, 
        "Distribution",
        distribution_config=cloudfront.CfnDistribution.DistributionConfigProperty(
            origins=[cloudfront.CfnDistribution.OriginProperty(
                domain_name=bucket.bucket_domain_name,
                id="myS3Origin",
                s3_origin_config=cloudfront.CfnDistribution.S3OriginConfigProperty(
                    origin_access_identity=""
                )
            )],
            default_cache_behavior=cloudfront.CfnDistribution.DefaultCacheBehaviorProperty(
                target_origin_id="myS3Origin",
                viewer_protocol_policy="redirect-to-https",
                forwarded_values=cloudfront.CfnDistribution.ForwardedValuesProperty(
                    query_string=False,
                    cookies=cloudfront.CfnDistribution.CookiesProperty(
                        forward="none"
                    )
                )
            ),
            enabled=True,
            viewer_certificate=cloudfront.CfnDistribution.ViewerCertificateProperty(
                acm_certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/abcdef",
                ssl_support_method="sni-only",
                minimum_protocol_version="TLSv1.2_2018"
            )
        )
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Using L1 construct with TLSv1.2 and SNI
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.CfnDistribution(
        scope, 
        "Distribution",
        distribution_config=cloudfront.CfnDistribution.DistributionConfigProperty(
            origins=[cloudfront.CfnDistribution.OriginProperty(
                domain_name=bucket.bucket_domain_name,
                id="myS3Origin",
                s3_origin_config=cloudfront.CfnDistribution.S3OriginConfigProperty(
                    origin_access_identity=""
                )
            )],
            default_cache_behavior=cloudfront.CfnDistribution.DefaultCacheBehaviorProperty(
                target_origin_id="myS3Origin",
                viewer_protocol_policy="redirect-to-https",
                forwarded_values=cloudfront.CfnDistribution.ForwardedValuesProperty(
                    query_string=False,
                    cookies=cloudfront.CfnDistribution.CookiesProperty(
                        forward="none"
                    )
                )
            ),
            enabled=True,
            viewer_certificate=cloudfront.CfnDistribution.ViewerCertificateProperty(
                acm_certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/abcdef",
                ssl_support_method="sni-only",
                minimum_protocol_version="TLSv1.2_2019"
            )
        )
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Using L1 construct with TLSv1.2 and SNI
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.CfnDistribution(
        scope, 
        "Distribution",
        distribution_config=cloudfront.CfnDistribution.DistributionConfigProperty(
            origins=[cloudfront.CfnDistribution.OriginProperty(
                domain_name=bucket.bucket_domain_name,
                id="myS3Origin",
                s3_origin_config=cloudfront.CfnDistribution.S3OriginConfigProperty(
                    origin_access_identity=""
                )
            )],
            default_cache_behavior=cloudfront.CfnDistribution.DefaultCacheBehaviorProperty(
                target_origin_id="myS3Origin",
                viewer_protocol_policy="redirect-to-https",
                forwarded_values=cloudfront.CfnDistribution.ForwardedValuesProperty(
                    query_string=False,
                    cookies=cloudfront.CfnDistribution.CookiesProperty(
                        forward="none"
                    )
                )
            ),
            enabled=True,
            viewer_certificate=cloudfront.CfnDistribution.ViewerCertificateProperty(
                acm_certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/abcdef",
                ssl_support_method="sni-only",
                minimum_protocol_version="TLSv1.2_2021"
            )
        )
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Using L1 construct with TLSv1.1 and SNI
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.CfnDistribution(
        scope, 
        "Distribution",
        distribution_config=cloudfront.CfnDistribution.DistributionConfigProperty(
            origins=[cloudfront.CfnDistribution.OriginProperty(
                domain_name=bucket.bucket_domain_name,
                id="myS3Origin",
                s3_origin_config=cloudfront.CfnDistribution.S3OriginConfigProperty(
                    origin_access_identity=""
                )
            )],
            default_cache_behavior=cloudfront.CfnDistribution.DefaultCacheBehaviorProperty(
                target_origin_id="myS3Origin",
                viewer_protocol_policy="redirect-to-https",
                forwarded_values=cloudfront.CfnDistribution.ForwardedValuesProperty(
                    query_string=False,
                    cookies=cloudfront.CfnDistribution.CookiesProperty(
                        forward="none"
                    )
                )
            ),
            enabled=True,
            viewer_certificate=cloudfront.CfnDistribution.ViewerCertificateProperty(
                acm_certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/abcdef",
                ssl_support_method="sni-only",
                minimum_protocol_version="TLSv1.1_2016"
            )
        )
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Using custom certificate with TLSv1.2 and SNI via properties
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    props = {
        "default_behavior": cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        "certificate": certificate,
        "ssl_support_method": cloudfront.SSLMethod.SNI,
        "minimum_protocol_version": cloudfront.SecurityPolicyProtocol.TLS_V1_2_2018
    }
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        **props
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Using custom certificate with TLSv1.2 and SNI via dictionary
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        certificate=certificate,
        ssl_support_method=cloudfront.SSLMethod.SNI,
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021
    )
    
    return distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Using custom certificate with TLSv1.2 and SNI via factory method
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = create_secure_distribution(scope, "Distribution", bucket, certificate)
    
    return distribution

# {/fact}

def create_secure_distribution(scope, id, bucket, certificate):
    return cloudfront.Distribution(
        scope, 
        id,
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        certificate=certificate,
        ssl_support_method=cloudfront.SSLMethod.SNI,
        minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019
    )

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Using custom certificate with TLSv1.2 and SNI via class
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
    distribution = SecureDistribution(
        scope, 
        "Distribution",
        bucket=bucket,
        certificate=certificate
    )
    
    return distribution.distribution

# {/fact}

class SecureDistribution(Construct):
    def __init__(self, scope: Construct, id: str, *, bucket: s3.Bucket, certificate: acm.ICertificate):
        super().__init__(scope, id)
        
        self.distribution = cloudfront.Distribution(
            self, 
            "Distribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(bucket)
            ),
            certificate=certificate,
            ssl_support_method=cloudfront.SSLMethod.SNI,
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2018
        )

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Using custom certificate with TLSv1.2 and SNI via stack
    class SecureDistributionStack(Stack):
        def __init__(self, scope: Construct, id: str, **kwargs):
            super().__init__(scope, id, **kwargs)
            
            bucket = s3.Bucket(self, "MyBucket")
            certificate = acm.Certificate.from_certificate_arn(
                self, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
            )
            
            # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
            self.distribution = cloudfront.Distribution(
                self, 
                "Distribution",
                default_behavior=cloudfront.BehaviorOptions(
                    origin=origins.S3Origin(bucket)
                ),
                certificate=certificate,
                ssl_support_method=cloudfront.SSLMethod.SNI,
                minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2019
            )
    
    app = cdk.App()
    stack = SecureDistributionStack(app, "SecureDistributionStack")
    return stack.distribution

# {/fact}

# {fact rule=improperly-implemented-security-check@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Using custom certificate with TLSv1.2 and SNI via function
    bucket = s3.Bucket(scope, "MyBucket")
    certificate = acm.Certificate.from_certificate_arn(
        scope, "Certificate", "arn:aws:acm:us-east-1:123456789012:certificate/abcdef"
    )
    
    def create_distribution():
        # ok: python-cdk-allows-https-viewer-connections-cloudfront-distribution
        return cloudfront.Distribution(
            scope, 
            "Distribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(bucket)
            ),
            certificate=certificate,
            ssl_support_method=cloudfront.SSLMethod.SNI,
            minimum_protocol_version=cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021
        )
    
    distribution = create_distribution()
    return distribution
# {/fact}