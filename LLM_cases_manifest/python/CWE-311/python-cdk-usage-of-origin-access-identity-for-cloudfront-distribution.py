import aws_cdk as cdk
from aws_cdk import (
    aws_cloudfront as cloudfront,
    aws_s3 as s3,
    aws_cloudfront_origins as origins,
    aws_iam as iam,
    Stack
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "MyBucket")
    
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        )
    )
    return distribution

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "WebsiteBucket", website_index_document="index.html")
    
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope, 
        "WebDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket, origin_access_identity=None)
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "ContentBucket")
    s3_origin = origins.S3Origin(bucket)
    
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope, 
        "ContentDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=s3_origin
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "AssetsBucket")
    
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    distribution = cloudfront.CloudFrontWebDistribution(
        scope,
        "AssetsDistribution",
        origin_configs=[
            cloudfront.SourceConfiguration(
                s3_origin_source=cloudfront.S3OriginConfig(
                    s3_bucket_source=bucket
                ),
                behaviors=[cloudfront.Behavior(is_default_behavior=True)]
            )
        ]
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "MediaBucket")
    
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.CloudFrontWebDistribution(
        scope,
        "MediaDistribution",
        origin_configs=[
            cloudfront.SourceConfiguration(
                s3_origin_source=cloudfront.S3OriginConfig(
                    s3_bucket_source=bucket,
                    origin_access_identity=None
                ),
                behaviors=[cloudfront.Behavior(is_default_behavior=True)]
            )
        ]
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "ImagesBucket")
    
    # Create distribution with multiple origins, but S3 origin has no OAI
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "ImagesDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("api.example.com")
        ),
        additional_behaviors={
            "images/*": cloudfront.BehaviorOptions(
                origin=origins.S3Origin(bucket, origin_access_identity=None)
            )
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "DocumentsBucket")
    
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "DocsDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        enable_logging=True,
        log_bucket=s3.Bucket(scope, "LogBucket")
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "StaticSiteBucket", website_index_document="index.html")
    
    # Using website endpoint without OAI (common pattern but flagged as insecure)
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "StaticSiteDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        default_root_object="index.html"
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "VideosBucket")
    
    # Using custom domain name but still S3 origin without OAI
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "VideosDistribution",
        domain_names=["videos.example.com"],
        certificate=None,  # Certificate would be required in real code
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "DownloadsBucket")
    
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    distribution = cloudfront.CloudFrontWebDistribution(
        scope,
        "DownloadsDistribution",
        price_class=cloudfront.PriceClass.PRICE_CLASS_100,
        origin_configs=[
            cloudfront.SourceConfiguration(
                s3_origin_source=cloudfront.S3OriginConfig(
                    s3_bucket_source=bucket
                ),
                behaviors=[cloudfront.Behavior(is_default_behavior=True)]
            )
        ]
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating bucket and distribution in one function
    bucket = s3.Bucket(scope, "AppBucket")
    
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "AppDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket),
            viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Using a variable for the origin
    bucket = s3.Bucket(scope, "ResourcesBucket")
    s3_origin_without_oai = origins.S3Origin(bucket)
    
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "ResourcesDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=s3_origin_without_oai,
            allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating multiple distributions with the same bucket
    bucket = s3.Bucket(scope, "SharedBucket")
    
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "PublicDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        )
    )
    
    # Another distribution using the same bucket without OAI
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "InternalDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "ConfigBucket")
    
    # Using deprecated CloudFrontWebDistribution without OAI
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.CloudFrontWebDistribution(
        scope,
        "ConfigDistribution",
        origin_configs=[
            cloudfront.SourceConfiguration(
                s3_origin_source=cloudfront.S3OriginConfig(
                    s3_bucket_source=bucket
                ),
                behaviors=[
                    cloudfront.Behavior(
                        is_default_behavior=True,
                        compress=True
                    )
                ]
            )
        ]
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating a distribution with an imported bucket
    imported_bucket = s3.Bucket.from_bucket_name(scope, "ImportedBucket", "existing-bucket-name")
    
    # ruleid: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "ImportedBucketDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(imported_bucket)
        )
    )

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "SecureBucket")
    
    # Create OAI explicitly
    oai = cloudfront.OriginAccessIdentity(scope, "OAI", comment="OAI for secure bucket access")
    
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    distribution = cloudfront.Distribution(
        scope, 
        "SecureDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket, origin_access_identity=oai)
        )
    )
    return distribution

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "WebsiteSecureBucket")
    oai = cloudfront.OriginAccessIdentity(scope, "WebsiteOAI")
    
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope, 
        "SecureWebDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket, origin_access_identity=oai)
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "ContentSecureBucket")
    
    # Using the default OAI created by S3Origin when not explicitly set to None
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope, 
        "SecureContentDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket,
                # By default, S3Origin creates an OAI if not specified
            )
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "AssetsSecureBucket")
    oai = cloudfront.OriginAccessIdentity(scope, "AssetsOAI", comment="OAI for assets")
    
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.CloudFrontWebDistribution(
        scope,
        "SecureAssetsDistribution",
        origin_configs=[
            cloudfront.SourceConfiguration(
                s3_origin_source=cloudfront.S3OriginConfig(
                    s3_bucket_source=bucket,
                    origin_access_identity=oai
                ),
                behaviors=[cloudfront.Behavior(is_default_behavior=True)]
            )
        ]
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "MediaSecureBucket")
    oai = cloudfront.OriginAccessIdentity(scope, "MediaOAI")
    
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.CloudFrontWebDistribution(
        scope,
        "SecureMediaDistribution",
        origin_configs=[
            cloudfront.SourceConfiguration(
                s3_origin_source=cloudfront.S3OriginConfig(
                    s3_bucket_source=bucket,
                    origin_access_identity=oai
                ),
                behaviors=[cloudfront.Behavior(is_default_behavior=True)]
            )
        ]
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "ImagesSecureBucket")
    oai = cloudfront.OriginAccessIdentity(scope, "ImagesOAI")
    
    # Multiple origins with secure S3 origin
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "SecureImagesDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("api.example.com")
        ),
        additional_behaviors={
            "images/*": cloudfront.BehaviorOptions(
                origin=origins.S3Origin(bucket, origin_access_identity=oai)
            )
        }
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "DocumentsSecureBucket")
    oai = cloudfront.OriginAccessIdentity(scope, "DocsOAI")
    
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "SecureDocsDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket, origin_access_identity=oai)
        ),
        enable_logging=True,
        log_bucket=s3.Bucket(scope, "SecureLogBucket")
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Using OAI with website configuration
    bucket = s3.Bucket(scope, "StaticSiteSecureBucket", website_index_document="index.html")
    oai = cloudfront.OriginAccessIdentity(scope, "StaticSiteOAI")
    
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "SecureStaticSiteDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket, origin_access_identity=oai)
        ),
        default_root_object="index.html"
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Using OAI with custom domain
    bucket = s3.Bucket(scope, "VideosSecureBucket")
    oai = cloudfront.OriginAccessIdentity(scope, "VideosOAI")
    
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "SecureVideosDistribution",
        domain_names=["videos.example.com"],
        certificate=None,  # Certificate would be required in real code
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket, origin_access_identity=oai)
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    bucket = s3.Bucket(scope, "DownloadsSecureBucket")
    oai = cloudfront.OriginAccessIdentity(scope, "DownloadsOAI")
    
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    distribution = cloudfront.CloudFrontWebDistribution(
        scope,
        "SecureDownloadsDistribution",
        price_class=cloudfront.PriceClass.PRICE_CLASS_100,
        origin_configs=[
            cloudfront.SourceConfiguration(
                s3_origin_source=cloudfront.S3OriginConfig(
                    s3_bucket_source=bucket,
                    origin_access_identity=oai
                ),
                behaviors=[cloudfront.Behavior(is_default_behavior=True)]
            )
        ]
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Using Origin Access Identity with HTTPS redirection
    bucket = s3.Bucket(scope, "AppSecureBucket")
    oai = cloudfront.OriginAccessIdentity(scope, "AppOAI")
    
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "SecureAppDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket, origin_access_identity=oai),
            viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Using a variable for the origin with OAI
    bucket = s3.Bucket(scope, "ResourcesSecureBucket")
    oai = cloudfront.OriginAccessIdentity(scope, "ResourcesOAI")
    s3_origin_with_oai = origins.S3Origin(bucket, origin_access_identity=oai)
    
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "SecureResourcesDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=s3_origin_with_oai,
            allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Using Origin Access Control (OAC) instead of OAI (newer approach)
    bucket = s3.Bucket(scope, "ModernBucket")
    
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "ModernDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket,
                origin_access_control_id="E3KCNVS1QUH9VC"  # Example OAC ID
            )
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Using non-S3 origin (not applicable for this rule)
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "ApiDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin("api.example.com")
        )
    )

# {/fact}

# {fact rule=aws-kms-reencryption@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Using imported bucket with OAI
    imported_bucket = s3.Bucket.from_bucket_name(scope, "ImportedSecureBucket", "existing-bucket-name")
    oai = cloudfront.OriginAccessIdentity(scope, "ImportedBucketOAI")
    
    # ok: python-cdk-usage-of-origin-access-identity-for-cloudfront-distribution
    cloudfront.Distribution(
        scope,
        "SecureImportedBucketDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(imported_bucket, origin_access_identity=oai)
        )
    )

# Example stack implementation
# {/fact}

class CloudFrontS3Stack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Example usage of the functions
        bad_case_1(self, "BadCase1")
        good_case_1(self, "GoodCase1")

app = cdk.App()
CloudFrontS3Stack(app, "CloudFrontS3Stack")
app.synth()