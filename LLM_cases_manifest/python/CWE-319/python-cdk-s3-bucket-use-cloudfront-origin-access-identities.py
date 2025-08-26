import aws_cdk as cdk
from aws_cdk import (
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_iam as iam,
    Stack,
    RemovalPolicy,
)
from constructs import Construct

# True Positive Examples (Vulnerable Code)

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_1(scope: Construct, id: str):
    # Creating an S3 bucket without CloudFront OAI
    bucket = s3.Bucket(scope, "WebsiteBucket",
        website_index_document="index.html",
        public_read_access=True,  # This makes the bucket publicly accessible
        removal_policy=RemovalPolicy.DESTROY
    )
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    distribution = cloudfront.Distribution(scope, "Distribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)  # No OAI specified
        )
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_2(scope: Construct, id: str):
    # Creating an S3 bucket with public access
    bucket = s3.Bucket(scope, "StaticSiteBucket")
    
    # Adding a bucket policy that allows public access
    bucket_policy = iam.PolicyStatement(
        actions=["s3:GetObject"],
        resources=[bucket.arn_for_objects("*")],
        principals=[iam.AnyPrincipal()]  # Open to everyone
    )
    bucket.add_to_resource_policy(bucket_policy)
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating CloudFront distribution without OAI
    distribution = cloudfront.Distribution(scope, "MyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        )
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_3(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "ContentBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ACLS,  # Only blocks ACLs, not bucket policies
        removal_policy=RemovalPolicy.DESTROY
    )
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Using S3 bucket as origin without OAI
    distribution = cloudfront.Distribution(scope, "CDNDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=None  # Explicitly setting OAI to None
            )
        )
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_4(scope: Construct, id: str):
    # Creating an S3 bucket with website configuration
    bucket = s3.Bucket(scope, "WebBucket",
        website_index_document="index.html",
        website_error_document="error.html",
        removal_policy=RemovalPolicy.DESTROY
    )
    
    # Adding a policy to allow public read access
    bucket.add_to_resource_policy(iam.PolicyStatement(
        actions=["s3:GetObject"],
        resources=[bucket.arn_for_objects("*")],
        principals=[iam.AnyPrincipal()]
    ))
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Using HTTP origin instead of S3Origin with OAI
    distribution = cloudfront.Distribution(scope, "WebDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin(f"{bucket.bucket_website_domain_name}")
        )
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_5(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "AssetsBucket")
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating a distribution with custom origin configuration
    distribution = cloudfront.Distribution(scope, "AssetsDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.OriginBase(
                domain_name=bucket.bucket_domain_name,
                origin_id="S3Origin"
            )
        )
    )
    
    # Making bucket public after creating the distribution
    bucket.grant_public_access("*", "s3:GetObject")
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_6(scope: Construct, id: str):
    # Creating an S3 bucket with website hosting enabled
    bucket = s3.Bucket(scope, "SiteBucket",
        website_index_document="index.html",
        removal_policy=RemovalPolicy.DESTROY
    )
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating CloudFront distribution with S3 website as origin
    distribution = cloudfront.Distribution(scope, "SiteDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        )
    )
    
    # Adding public read access after creating the distribution
    bucket.add_to_resource_policy(iam.PolicyStatement(
        actions=["s3:GetObject"],
        resources=[f"{bucket.bucket_arn}/*"],
        principals=[iam.AnyPrincipal()]
    ))
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_7(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "MediaBucket")
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating CloudFront distribution with custom domain
    distribution = cloudfront.Distribution(scope, "MediaDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        domain_names=["media.example.com"]
    )
    
    # Disabling block public access settings
    bucket.add_to_resource_policy(iam.PolicyStatement(
        effect=iam.Effect.ALLOW,
        actions=["s3:GetObject"],
        resources=[bucket.arn_for_objects("*")],
        principals=[iam.AnyPrincipal()]
    ))
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_8(scope: Construct, id: str):
    # Creating an S3 bucket with public read access
    bucket = s3.Bucket(scope, "PublicBucket",
        public_read_access=True,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating CloudFront distribution without OAI
    distribution = cloudfront.Distribution(scope, "PublicDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        )
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_9(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "DocumentsBucket")
    
    # Adding a bucket policy for public access
    bucket.add_to_resource_policy(iam.PolicyStatement(
        actions=["s3:GetObject"],
        resources=[bucket.arn_for_objects("public/*")],
        principals=[iam.AnyPrincipal()]
    ))
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating CloudFront distribution without OAI
    distribution = cloudfront.Distribution(scope, "DocsDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        )
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_10(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "ImagesBucket")
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating CloudFront distribution with S3 origin but no OAI
    distribution = cloudfront.Distribution(scope, "ImagesDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_path="/images"
            )
        )
    )
    
    # Making the bucket public
    bucket.grant_read_write(iam.AnyPrincipal())
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_11(scope: Construct, id: str):
    # Creating an S3 bucket with website configuration
    bucket = s3.Bucket(scope, "BlogBucket",
        website_index_document="index.html",
        website_error_document="error.html"
    )
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Using bucket website endpoint as origin
    distribution = cloudfront.Distribution(scope, "BlogDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.HttpOrigin(bucket.bucket_website_domain_name)
        )
    )
    
    # Making the bucket public
    bucket.add_to_resource_policy(iam.PolicyStatement(
        actions=["s3:GetObject"],
        resources=[bucket.arn_for_objects("*")],
        principals=[iam.AnyPrincipal()]
    ))
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_12(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "DownloadsBucket")
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating CloudFront distribution with S3 origin
    distribution = cloudfront.Distribution(scope, "DownloadsDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        )
    )
    
    # Adding a policy to allow public access to specific objects
    bucket.add_to_resource_policy(iam.PolicyStatement(
        actions=["s3:GetObject"],
        resources=[bucket.arn_for_objects("downloads/*")],
        principals=[iam.AnyPrincipal()]
    ))
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_13(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "StaticAssetsBucket")
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating CloudFront distribution with multiple origins but no OAI
    distribution = cloudfront.Distribution(scope, "AssetsDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        ),
        additional_behaviors={
            "/images/*": cloudfront.BehaviorOptions(
                origin=origins.S3Origin(bucket)
            )
        }
    )
    
    # Making bucket public
    bucket.grant_public_access()
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_14(scope: Construct, id: str):
    # Creating an S3 bucket with website hosting
    bucket = s3.Bucket(scope, "LandingPageBucket",
        website_index_document="index.html"
    )
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating CloudFront distribution with S3 origin
    distribution = cloudfront.Distribution(scope, "LandingPageDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        )
    )
    
    # Adding a policy that allows public read access
    policy_document = iam.PolicyDocument(
        statements=[
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[f"{bucket.bucket_arn}/*"],
                principals=[iam.AnyPrincipal()]
            )
        ]
    )
    s3.BucketPolicy(scope, "BucketPolicy", bucket=bucket, policy_document=policy_document)
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=1}
def bad_case_15(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "ResourcesBucket")
    
    # ruleid: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating CloudFront distribution with S3 origin
    distribution = cloudfront.Distribution(scope, "ResourcesDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(bucket)
        )
    )
    
    # Creating a custom resource to update bucket policy to allow public access
    custom_resource = cdk.CustomResource(scope, "PublicAccessResource",
        service_token="SomeServiceToken",
        properties={
            "BucketName": bucket.bucket_name,
            "PolicyAction": "s3:GetObject",
            "Principal": "*"
        }
    )
    
    return bucket, distribution

# True Negative Examples (Secure Code)

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_1(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureWebsiteBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating CloudFront distribution with OAI
    origin_identity = cloudfront.OriginAccessIdentity(scope, "OAI",
        comment="Origin Access Identity for secure access"
    )
    
    distribution = cloudfront.Distribution(scope, "SecureDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=origin_identity
            )
        )
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_2(scope: Construct, id: str):
    # Creating an S3 bucket with block public access
    bucket = s3.Bucket(scope, "PrivateStaticSiteBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI and CloudFront distribution
    oai = cloudfront.OriginAccessIdentity(scope, "SiteOAI")
    
    distribution = cloudfront.Distribution(scope, "SecureMyDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=oai
            )
        )
    )
    
    # Grant read permissions only to CloudFront OAI
    bucket.grant_read(oai)
    
    return bucket, distribution, oai

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_3(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureContentBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI and using it with CloudFront
    origin_access_identity = cloudfront.OriginAccessIdentity(scope, "ContentOAI")
    
    distribution = cloudfront.Distribution(scope, "SecureCDNDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=origin_access_identity
            )
        )
    )
    
    # Adding a bucket policy that only allows access from the OAI
    bucket.add_to_resource_policy(iam.PolicyStatement(
        actions=["s3:GetObject"],
        resources=[bucket.arn_for_objects("*")],
        principals=[origin_access_identity.grant_principal]
    ))
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_4(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureWebBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI for CloudFront
    oai = cloudfront.OriginAccessIdentity(scope, "WebOAI", 
        comment="OAI for secure web content access"
    )
    
    # Creating CloudFront distribution with OAI
    distribution = cloudfront.Distribution(scope, "SecureWebDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=oai
            ),
            viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS
        )
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_5(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureAssetsBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI and CloudFront distribution
    origin_identity = cloudfront.OriginAccessIdentity(scope, "AssetsOAI")
    
    distribution = cloudfront.Distribution(scope, "SecureAssetsDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=origin_identity
            )
        )
    )
    
    # Explicitly grant permissions to the OAI
    bucket.grant_read(origin_identity)
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_6(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureSiteBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI for CloudFront
    oai = cloudfront.OriginAccessIdentity(scope, "SiteOAI")
    
    # Creating CloudFront distribution with OAI
    distribution = cloudfront.Distribution(scope, "SecureSiteDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=oai
            )
        ),
        error_responses=[
            cloudfront.ErrorResponse(
                http_status=404,
                response_http_status=200,
                response_page_path="/index.html"
            )
        ]
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_7(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureMediaBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI for CloudFront
    oai = cloudfront.OriginAccessIdentity(scope, "MediaOAI")
    
    # Creating CloudFront distribution with OAI and custom domain
    distribution = cloudfront.Distribution(scope, "SecureMediaDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=oai
            )
        ),
        domain_names=["secure-media.example.com"]
    )
    
    # Adding a bucket policy that only allows access from the OAI
    bucket.add_to_resource_policy(iam.PolicyStatement(
        actions=["s3:GetObject"],
        resources=[bucket.arn_for_objects("*")],
        principals=[oai.grant_principal]
    ))
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_8(scope: Construct, id: str):
    # Creating an S3 bucket with block public access
    bucket = s3.Bucket(scope, "SecurePublicBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
        removal_policy=RemovalPolicy.DESTROY
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI and CloudFront distribution
    origin_identity = cloudfront.OriginAccessIdentity(scope, "PublicOAI")
    
    distribution = cloudfront.Distribution(scope, "SecurePublicDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=origin_identity
            ),
            viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.HTTPS_ONLY
        )
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_9(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureDocumentsBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI for CloudFront
    oai = cloudfront.OriginAccessIdentity(scope, "DocsOAI")
    
    # Creating CloudFront distribution with OAI
    distribution = cloudfront.Distribution(scope, "SecureDocsDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=oai
            )
        )
    )
    
    # Grant read permissions to the OAI for specific paths
    bucket.add_to_resource_policy(iam.PolicyStatement(
        actions=["s3:GetObject"],
        resources=[bucket.arn_for_objects("public/*")],
        principals=[oai.grant_principal]
    ))
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_10(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureImagesBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI and CloudFront distribution with origin path
    oai = cloudfront.OriginAccessIdentity(scope, "ImagesOAI")
    
    distribution = cloudfront.Distribution(scope, "SecureImagesDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=oai,
                origin_path="/images"
            )
        )
    )
    
    # Grant permissions to the OAI
    bucket.grant_read(oai)
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_11(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureBlogBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI for CloudFront
    oai = cloudfront.OriginAccessIdentity(scope, "BlogOAI")
    
    # Creating CloudFront distribution with OAI
    distribution = cloudfront.Distribution(scope, "SecureBlogDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=oai
            )
        ),
        default_root_object="index.html"
    )
    
    # Create custom error responses for SPA routing
    distribution.add_behavior("*",
        origins.S3Origin(
            bucket=bucket,
            origin_access_identity=oai
        ),
        error_responses=[
            cloudfront.ErrorResponse(
                http_status=404,
                response_http_status=200,
                response_page_path="/index.html"
            )
        ]
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_12(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureDownloadsBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI for CloudFront
    oai = cloudfront.OriginAccessIdentity(scope, "DownloadsOAI")
    
    # Creating CloudFront distribution with OAI and cache policy
    distribution = cloudfront.Distribution(scope, "SecureDownloadsDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=oai
            ),
            cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED
        )
    )
    
    # Add specific behavior for downloads directory
    distribution.add_behavior("downloads/*",
        origins.S3Origin(
            bucket=bucket,
            origin_access_identity=oai
        ),
        cache_policy=cloudfront.CachePolicy.CACHING_DISABLED
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_13(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureStaticAssetsBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI for CloudFront
    oai = cloudfront.OriginAccessIdentity(scope, "StaticAssetsOAI")
    
    # Creating CloudFront distribution with OAI and multiple behaviors
    distribution = cloudfront.Distribution(scope, "SecureAssetsDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=oai
            )
        ),
        additional_behaviors={
            "/images/*": cloudfront.BehaviorOptions(
                origin=origins.S3Origin(
                    bucket=bucket,
                    origin_access_identity=oai
                ),
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED
            ),
            "/css/*": cloudfront.BehaviorOptions(
                origin=origins.S3Origin(
                    bucket=bucket,
                    origin_access_identity=oai
                )
            )
        }
    )
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_14(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureLandingPageBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI for CloudFront
    oai = cloudfront.OriginAccessIdentity(scope, "LandingPageOAI")
    
    # Creating CloudFront distribution with OAI
    distribution = cloudfront.Distribution(scope, "SecureLandingPageDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=oai
            )
        ),
        default_root_object="index.html"
    )
    
    # Create a bucket policy that only allows access from the OAI
    policy_document = iam.PolicyDocument(
        statements=[
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[f"{bucket.bucket_arn}/*"],
                principals=[oai.grant_principal]
            )
        ]
    )
    s3.BucketPolicy(scope, "SecureBucketPolicy", bucket=bucket, policy_document=policy_document)
    
    return bucket, distribution

# {/fact}

# {fact rule=insecure-cookie@v1.0 defects=0}
def good_case_15(scope: Construct, id: str):
    # Creating an S3 bucket
    bucket = s3.Bucket(scope, "SecureResourcesBucket",
        block_public_access=s3.BlockPublicAccess.BLOCK_ALL
    )
    
    # ok: python-cdk-s3-bucket-use-cloudfront-origin-access-identities
    # Creating OAI for CloudFront with versioned objects
    oai = cloudfront.OriginAccessIdentity(scope, "ResourcesOAI")
    
    # Creating CloudFront distribution with OAI and custom error responses
    distribution = cloudfront.Distribution(scope, "SecureResourcesDistribution",
        default_behavior=cloudfront.BehaviorOptions(
            origin=origins.S3Origin(
                bucket=bucket,
                origin_access_identity=oai
            )
        ),
        error_responses=[
            cloudfront.ErrorResponse(
                http_status=403,
                response_http_status=200,
                response_page_path="/index.html"
            ),
            cloudfront.ErrorResponse(
                http_status=404,
                response_http_status=200,
                response_page_path="/index.html"
            )
        ]
    )
    
    # Grant read permissions to the OAI
    bucket.grant_read(oai)
    
    return bucket, distribution
# {/fact}