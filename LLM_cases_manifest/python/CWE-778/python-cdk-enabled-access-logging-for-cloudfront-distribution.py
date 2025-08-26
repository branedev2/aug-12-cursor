import aws_cdk as cdk
from aws_cdk import (
    aws_cloudfront as cloudfront,
    aws_s3 as s3,
    aws_cloudfront_origins as origins,
    Stack,
    CfnOutput,
    RemovalPolicy
)
from constructs import Construct

# True Positives (Vulnerable Code - Missing Access Logging)

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating a CloudFront distribution without access logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        )
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating a CloudFront distribution with explicit disabling of access logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        enable_logging=False
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating a CloudFront distribution with additional configuration but no logging
    bucket = s3.Bucket(scope, "ContentBucket")
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket),
            viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL
        )
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating a CloudFront distribution with price class configuration but no logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        price_class=cloudfront.PriceClass.PRICE_CLASS_100
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating a CloudFront distribution with multiple behaviors but no logging
    bucket = s3.Bucket(scope, "ContentBucket")
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        additional_behaviors={
            "/images/*": cloudfront.BehaviorOptions(
                origin=origins.HttpOrigin("images.example.com")
            )
        }
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating a CloudFront distribution with certificate but no logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        domain_names=["example.com"],
        certificate=None  # In real code, this would be a valid certificate
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating a CloudFront distribution with error responses but no logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        error_responses=[
            cloudfront.ErrorResponse(
                http_status=404,
                response_http_status=200,
                response_page_path="/index.html"
            )
        ]
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating a CloudFront distribution with geo restrictions but no logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        geo_restriction=cloudfront.GeoRestriction.whitelist("US", "CA")
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating a CloudFront distribution with web ACL ID but no logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        web_acl_id="waf-web-acl-id"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating a CloudFront distribution with comment but no logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        comment="Production CDN"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating a CloudFront distribution with enabled flag but no logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        enabled=True
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating a CloudFront distribution with HTTP version but no logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        http_version=cloudfront.HttpVersion.HTTP2
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating a CloudFront distribution with default root object but no logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        default_root_object="index.html"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating a CloudFront distribution with IPv6 enabled but no logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        enable_ipv6=True
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a CloudFront distribution with custom error responses but no logging
    # ruleid: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        error_responses=[
            cloudfront.ErrorResponse(
                http_status=403,
                response_http_status=200,
                response_page_path="/index.html",
                ttl=cdk.Duration.seconds(30)
            ),
            cloudfront.ErrorResponse(
                http_status=404,
                response_http_status=200,
                response_page_path="/index.html",
                ttl=cdk.Duration.seconds(30)
            )
        ]
    )
    return distribution

# True Negatives (Secure Code - Access Logging Enabled)

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="cloudfront-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and additional configuration
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com"),
            viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS
        ),
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="distribution-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and S3 origin
    content_bucket = s3.Bucket(scope, "ContentBucket")
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(content_bucket)
        ),
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="cdn-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and price class configuration
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="access-logs/",
        price_class=cloudfront.PriceClass.PRICE_CLASS_100
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and multiple behaviors
    content_bucket = s3.Bucket(scope, "ContentBucket")
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(content_bucket)
        ),
        additional_behaviors={
            "/images/*": cloudfront.BehaviorOptions(
                origin=origins.HttpOrigin("images.example.com")
            )
        },
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="cdn-access-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and custom domain
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        domain_names=["example.com"],
        certificate=None,  # In real code, this would be a valid certificate
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="domain-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and error responses
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        error_responses=[
            cloudfront.ErrorResponse(
                http_status=404,
                response_http_status=200,
                response_page_path="/index.html"
            )
        ],
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="error-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and geo restrictions
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        geo_restriction=cloudfront.GeoRestriction.whitelist("US", "CA"),
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="geo-restricted-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and WAF integration
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        web_acl_id="waf-web-acl-id",
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="waf-protected-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and comment
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        comment="Production CDN with logging",
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="prod-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and specific enabled flag
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        enabled=True,
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="enabled-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and HTTP version
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        http_version=cloudfront.HttpVersion.HTTP2,
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="http2-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and default root object
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        default_root_object="index.html",
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="root-object-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and IPv6
    logging_bucket = s3.Bucket(scope, "LoggingBucket")
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        enable_ipv6=True,
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="ipv6-logs/"
    )
    return distribution

# {/fact}

# {fact rule=insufficient-logging@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating a CloudFront distribution with access logging enabled and custom error responses
    logging_bucket = s3.Bucket(scope, "LoggingBucket", removal_policy=RemovalPolicy.DESTROY)
    # ok: python-cdk-enabled-access-logging-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("www.example.com")
        ),
        error_responses=[
            cloudfront.ErrorResponse(
                http_status=403,
                response_http_status=200,
                response_page_path="/index.html",
                ttl=cdk.Duration.seconds(30)
            ),
            cloudfront.ErrorResponse(
                http_status=404,
                response_http_status=200,
                response_page_path="/index.html",
                ttl=cdk.Duration.seconds(30)
            )
        ],
        enable_logging=True,
        log_bucket=logging_bucket,
        log_file_prefix="error-response-logs/"
    )
    return distribution

# {/fact}

class CloudFrontStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Examples of both vulnerable and secure CloudFront distributions
        bad_distribution = bad_case_1(self, "BadDistribution1")
        good_distribution = good_case_1(self, "GoodDistribution1")
        
        CfnOutput(self, "BadDistributionDomainName", value=bad_distribution.distribution_domain_name)
        CfnOutput(self, "GoodDistributionDomainName", value=good_distribution.distribution_domain_name)

app = cdk.App()
CloudFrontStack(app, "CloudFrontStack")
app.synth()