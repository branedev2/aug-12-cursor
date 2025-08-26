package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// True Positive Examples (Missing ExpectedBucketOwner)

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_1() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String("my-bucket"),
		Key:    aws.String("my-object"),
	})
	if err != nil {
		fmt.Printf("Error getting object: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_2() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String("my-bucket"),
		Key:    aws.String("my-object"),
		Body:   aws.ReadSeekCloser(strings.NewReader("hello world")),
	})
	if err != nil {
		fmt.Printf("Error putting object: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_3() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String("my-bucket"),
		Key:    aws.String("my-object"),
	})
	if err != nil {
		fmt.Printf("Error deleting object: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_4() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String("my-bucket"),
	})
	if err != nil {
		fmt.Printf("Error listing objects: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_5() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.CopyObject(context.TODO(), &s3.CopyObjectInput{
		Bucket:     aws.String("destination-bucket"),
		CopySource: aws.String("source-bucket/source-object"),
		Key:        aws.String("destination-object"),
	})
	if err != nil {
		fmt.Printf("Error copying object: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_6() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.CreateMultipartUpload(context.TODO(), &s3.CreateMultipartUploadInput{
		Bucket: aws.String("my-bucket"),
		Key:    aws.String("my-large-object"),
	})
	if err != nil {
		fmt.Printf("Error creating multipart upload: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_7() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	bucketName := "my-bucket"
	
	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.HeadBucket(context.TODO(), &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		fmt.Printf("Error checking bucket existence: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_8() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.GetBucketPolicy(context.TODO(), &s3.GetBucketPolicyInput{
		Bucket: aws.String("my-bucket"),
	})
	if err != nil {
		fmt.Printf("Error getting bucket policy: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_9() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.GetBucketAcl(context.TODO(), &s3.GetBucketAclInput{
		Bucket: aws.String("my-bucket"),
	})
	if err != nil {
		fmt.Printf("Error getting bucket ACL: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_10() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.PutBucketPolicy(context.TODO(), &s3.PutBucketPolicyInput{
		Bucket: aws.String("my-bucket"),
		Policy: aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/*"}]}`),
	})
	if err != nil {
		fmt.Printf("Error putting bucket policy: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_11() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.GetObjectTagging(context.TODO(), &s3.GetObjectTaggingInput{
		Bucket: aws.String("my-bucket"),
		Key:    aws.String("my-object"),
	})
	if err != nil {
		fmt.Printf("Error getting object tags: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_12() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.RestoreObject(context.TODO(), &s3.RestoreObjectInput{
		Bucket: aws.String("my-bucket"),
		Key:    aws.String("my-archived-object"),
	})
	if err != nil {
		fmt.Printf("Error restoring object: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_13() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.GetObjectAttributes(context.TODO(), &s3.GetObjectAttributesInput{
		Bucket: aws.String("my-bucket"),
		Key:    aws.String("my-object"),
	})
	if err != nil {
		fmt.Printf("Error getting object attributes: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_14() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.GetBucketLocation(context.TODO(), &s3.GetBucketLocationInput{
		Bucket: aws.String("my-bucket"),
	})
	if err != nil {
		fmt.Printf("Error getting bucket location: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=1}
func bad_case_15() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ruleid: rule-s3-verify-bucket-owner
	_, err = client.GetBucketVersioning(context.TODO(), &s3.GetBucketVersioningInput{
		Bucket: aws.String("my-bucket"),
	})
	if err != nil {
		fmt.Printf("Error getting bucket versioning: %v\n", err)
	}
}
// {/fact}

// True Negative Examples (Using ExpectedBucketOwner)

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_1() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket:              aws.String("my-bucket"),
		Key:                 aws.String("my-object"),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error getting object: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_2() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:              aws.String("my-bucket"),
		Key:                 aws.String("my-object"),
		Body:                aws.ReadSeekCloser(strings.NewReader("hello world")),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error putting object: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_3() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket:              aws.String("my-bucket"),
		Key:                 aws.String("my-object"),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error deleting object: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_4() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket:              aws.String("my-bucket"),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error listing objects: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_5() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.CopyObject(context.TODO(), &s3.CopyObjectInput{
		Bucket:                  aws.String("destination-bucket"),
		CopySource:              aws.String("source-bucket/source-object"),
		Key:                     aws.String("destination-object"),
		ExpectedBucketOwner:     aws.String("123456789012"),
		ExpectedSourceBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error copying object: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_6() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.CreateMultipartUpload(context.TODO(), &s3.CreateMultipartUploadInput{
		Bucket:              aws.String("my-bucket"),
		Key:                 aws.String("my-large-object"),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error creating multipart upload: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_7() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	bucketName := "my-bucket"
	accountID := "123456789012"
	
	// ok: rule-s3-verify-bucket-owner
	_, err = client.HeadBucket(context.TODO(), &s3.HeadBucketInput{
		Bucket:              aws.String(bucketName),
		ExpectedBucketOwner: aws.String(accountID),
	})
	if err != nil {
		fmt.Printf("Error checking bucket existence: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_8() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.GetBucketPolicy(context.TODO(), &s3.GetBucketPolicyInput{
		Bucket:              aws.String("my-bucket"),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error getting bucket policy: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_9() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.GetBucketAcl(context.TODO(), &s3.GetBucketAclInput{
		Bucket:              aws.String("my-bucket"),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error getting bucket ACL: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_10() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.PutBucketPolicy(context.TODO(), &s3.PutBucketPolicyInput{
		Bucket:              aws.String("my-bucket"),
		Policy:              aws.String(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/*"}]}`),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error putting bucket policy: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_11() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.GetObjectTagging(context.TODO(), &s3.GetObjectTaggingInput{
		Bucket:              aws.String("my-bucket"),
		Key:                 aws.String("my-object"),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error getting object tags: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_12() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.RestoreObject(context.TODO(), &s3.RestoreObjectInput{
		Bucket:              aws.String("my-bucket"),
		Key:                 aws.String("my-archived-object"),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error restoring object: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_13() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.GetObjectAttributes(context.TODO(), &s3.GetObjectAttributesInput{
		Bucket:              aws.String("my-bucket"),
		Key:                 aws.String("my-object"),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error getting object attributes: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_14() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.GetBucketLocation(context.TODO(), &s3.GetBucketLocationInput{
		Bucket:              aws.String("my-bucket"),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error getting bucket location: %v\n", err)
	}
}
// {/fact}

// {fact rule=s3-verify-bucket-owner@v1.0 defects=0}
func good_case_15() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Printf("Error loading AWS config: %v\n", err)
		return
	}
	client := s3.NewFromConfig(cfg)

	// ok: rule-s3-verify-bucket-owner
	_, err = client.GetBucketVersioning(context.TODO(), &s3.GetBucketVersioningInput{
		Bucket:              aws.String("my-bucket"),
		ExpectedBucketOwner: aws.String("123456789012"),
	})
	if err != nil {
		fmt.Printf("Error getting bucket versioning: %v\n", err)
	}
}
// {/fact}

func main() {
	// This is just a placeholder main function
	fmt.Println("S3 Bucket Owner Verification Examples")
}