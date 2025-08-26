package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sns"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	"github.com/aws/aws-sdk-go/service/iam"
	
	// Recommended SDK imports
	"github.com/aws/aws-sdk-go-v2/aws"
	v2config "github.com/aws/aws-sdk-go-v2/config"
	v2credentials "github.com/aws/aws-sdk-go-v2/credentials"
	v2s3 "github.com/aws/aws-sdk-go-v2/service/s3"
	v2dynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	v2ec2 "github.com/aws/aws-sdk-go-v2/service/ec2"
	v2lambda "github.com/aws/aws-sdk-go-v2/service/lambda"
	v2sqs "github.com/aws/aws-sdk-go-v2/service/sqs"
	v2sns "github.com/aws/aws-sdk-go-v2/service/sns"
	v2cloudwatch "github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	v2iam "github.com/aws/aws-sdk-go-v2/service/iam"
)

// True positives (vulnerable or insecure code that MUST be detected)

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_1() {
	// ruleid: rule-not-recommended-apis
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("us-west-2"),
	}))
	
	s3Client := s3.New(sess)
	
	_, err := s3Client.ListBuckets(nil)
	if err != nil {
		log.Println("Error listing buckets:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_2() {
	// ruleid: rule-not-recommended-apis
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String("us-east-1"),
		Credentials: credentials.NewStaticCredentials("AKIA_PLACEHOLDER_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", ""),
	})
	
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}
	
	dynamoClient := dynamodb.New(sess)
	
	input := &dynamodb.ListTablesInput{}
	_, err = dynamoClient.ListTables(input)
	if err != nil {
		log.Println("Error listing tables:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_3() {
	// ruleid: rule-not-recommended-apis
	sess := session.Must(session.NewSession())
	ec2Client := ec2.New(sess, &aws.Config{
		Region: aws.String("eu-central-1"),
	})
	
	_, err := ec2Client.DescribeInstances(nil)
	if err != nil {
		log.Println("Error describing instances:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_4() {
	// ruleid: rule-not-recommended-apis
	sess := session.Must(session.NewSession())
	lambdaClient := lambda.New(sess, &aws.Config{
		Region: aws.String("us-west-1"),
	})
	
	input := &lambda.ListFunctionsInput{}
	_, err := lambdaClient.ListFunctions(input)
	if err != nil {
		log.Println("Error listing Lambda functions:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_5() {
	// ruleid: rule-not-recommended-apis
	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
	
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}
	
	sqsClient := sqs.New(sess)
	
	_, err = sqsClient.ListQueues(nil)
	if err != nil {
		log.Println("Error listing queues:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_6() {
	// ruleid: rule-not-recommended-apis
	sess := session.Must(session.NewSession())
	snsClient := sns.New(sess, &aws.Config{
		Region: aws.String("ap-southeast-1"),
	})
	
	input := &sns.ListTopicsInput{}
	_, err := snsClient.ListTopics(input)
	if err != nil {
		log.Println("Error listing topics:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_7() {
	// ruleid: rule-not-recommended-apis
	sess := session.Must(session.NewSession())
	cwClient := cloudwatch.New(sess, &aws.Config{
		Region: aws.String("us-east-2"),
	})
	
	_, err := cwClient.ListMetrics(&cloudwatch.ListMetricsInput{})
	if err != nil {
		log.Println("Error listing metrics:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_8() {
	// ruleid: rule-not-recommended-apis
	creds := credentials.NewEnvCredentials()
	sess := session.Must(session.NewSession(&aws.Config{
		Credentials: creds,
		Region:      aws.String("eu-west-1"),
	}))
	
	iamClient := iam.New(sess)
	
	_, err := iamClient.ListUsers(&iam.ListUsersInput{})
	if err != nil {
		log.Println("Error listing IAM users:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_9() {
	// ruleid: rule-not-recommended-apis
	sess := session.Must(session.NewSession())
	s3Client := s3.New(sess, &aws.Config{
		Region: aws.String("us-west-2"),
	})
	
	input := &s3.GetObjectInput{
		Bucket: aws.String("my-bucket"),
		Key:    aws.String("my-object"),
	}
	
	_, err := s3Client.GetObject(input)
	if err != nil {
		log.Println("Error getting object:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_10() {
	// ruleid: rule-not-recommended-apis
	sess := session.Must(session.NewSession())
	dynamoClient := dynamodb.New(sess, &aws.Config{
		Region: aws.String("us-east-1"),
	})
	
	input := &dynamodb.ScanInput{
		TableName: aws.String("my-table"),
	}
	
	_, err := dynamoClient.Scan(input)
	if err != nil {
		log.Println("Error scanning table:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_11() {
	// ruleid: rule-not-recommended-apis
	sess := session.Must(session.NewSession())
	ec2Client := ec2.New(sess, &aws.Config{
		Region: aws.String("ap-northeast-1"),
	})
	
	input := &ec2.DescribeSecurityGroupsInput{}
	
	_, err := ec2Client.DescribeSecurityGroups(input)
	if err != nil {
		log.Println("Error describing security groups:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_12() {
	// ruleid: rule-not-recommended-apis
	sess := session.Must(session.NewSession())
	lambdaClient := lambda.New(sess, &aws.Config{
		Region: aws.String("eu-west-2"),
	})
	
	input := &lambda.GetFunctionInput{
		FunctionName: aws.String("my-function"),
	}
	
	_, err := lambdaClient.GetFunction(input)
	if err != nil {
		log.Println("Error getting Lambda function:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_13() {
	// ruleid: rule-not-recommended-apis
	sess := session.Must(session.NewSession())
	sqsClient := sqs.New(sess, &aws.Config{
		Region: aws.String("us-west-1"),
	})
	
	input := &sqs.SendMessageInput{
		QueueUrl:    aws.String("https://sqs.us-west-1.amazonaws.com/123456789012/my-queue"),
		MessageBody: aws.String("Hello, world!"),
	}
	
	_, err := sqsClient.SendMessage(input)
	if err != nil {
		log.Println("Error sending message:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_14() {
	// ruleid: rule-not-recommended-apis
	sess := session.Must(session.NewSession())
	snsClient := sns.New(sess, &aws.Config{
		Region: aws.String("eu-central-1"),
	})
	
	input := &sns.PublishInput{
		TopicArn: aws.String("arn:aws:sns:eu-central-1:123456789012:my-topic"),
		Message:  aws.String("Hello, world!"),
	}
	
	_, err := snsClient.Publish(input)
	if err != nil {
		log.Println("Error publishing message:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=1}
func bad_case_15() {
	// ruleid: rule-not-recommended-apis
	sess := session.Must(session.NewSession())
	iamClient := iam.New(sess, &aws.Config{
		Region: aws.String("us-east-1"),
	})
	
	input := &iam.GetUserInput{
		UserName: aws.String("my-user"),
	}
	
	_, err := iamClient.GetUser(input)
	if err != nil {
		log.Println("Error getting IAM user:", err)
	}
}
// {/fact}

// True negatives (safe or secure code that MUST NOT be detected)

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_1() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("us-west-2"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	s3Client := v2s3.NewFromConfig(cfg)
	
	_, err = s3Client.ListBuckets(ctx, &v2s3.ListBucketsInput{})
	if err != nil {
		log.Println("Error listing buckets:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_2() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx,
		v2config.WithRegion("us-east-1"),
		v2config.WithCredentialsProvider(v2credentials.NewStaticCredentialsProvider(
			"AKIA_PLACEHOLDER_ACCESS_KEY",
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			"",
		)),
	)
	
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	dynamoClient := v2dynamodb.NewFromConfig(cfg)
	
	_, err = dynamoClient.ListTables(ctx, &v2dynamodb.ListTablesInput{})
	if err != nil {
		log.Println("Error listing tables:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_3() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("eu-central-1"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	ec2Client := v2ec2.NewFromConfig(cfg)
	
	_, err = ec2Client.DescribeInstances(ctx, &v2ec2.DescribeInstancesInput{})
	if err != nil {
		log.Println("Error describing instances:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_4() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("us-west-1"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	lambdaClient := v2lambda.NewFromConfig(cfg)
	
	_, err = lambdaClient.ListFunctions(ctx, &v2lambda.ListFunctionsInput{})
	if err != nil {
		log.Println("Error listing Lambda functions:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_5() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	sqsClient := v2sqs.NewFromConfig(cfg)
	
	_, err = sqsClient.ListQueues(ctx, &v2sqs.ListQueuesInput{})
	if err != nil {
		log.Println("Error listing queues:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_6() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("ap-southeast-1"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	snsClient := v2sns.NewFromConfig(cfg)
	
	_, err = snsClient.ListTopics(ctx, &v2sns.ListTopicsInput{})
	if err != nil {
		log.Println("Error listing topics:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_7() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("us-east-2"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	cwClient := v2cloudwatch.NewFromConfig(cfg)
	
	_, err = cwClient.ListMetrics(ctx, &v2cloudwatch.ListMetricsInput{})
	if err != nil {
		log.Println("Error listing metrics:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_8() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("eu-west-1"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	iamClient := v2iam.NewFromConfig(cfg)
	
	_, err = iamClient.ListUsers(ctx, &v2iam.ListUsersInput{})
	if err != nil {
		log.Println("Error listing IAM users:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_9() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("us-west-2"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	s3Client := v2s3.NewFromConfig(cfg)
	
	input := &v2s3.GetObjectInput{
		Bucket: aws.String("my-bucket"),
		Key:    aws.String("my-object"),
	}
	
	_, err = s3Client.GetObject(ctx, input)
	if err != nil {
		log.Println("Error getting object:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_10() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("us-east-1"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	dynamoClient := v2dynamodb.NewFromConfig(cfg)
	
	input := &v2dynamodb.ScanInput{
		TableName: aws.String("my-table"),
	}
	
	_, err = dynamoClient.Scan(ctx, input)
	if err != nil {
		log.Println("Error scanning table:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_11() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("ap-northeast-1"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	ec2Client := v2ec2.NewFromConfig(cfg)
	
	_, err = ec2Client.DescribeSecurityGroups(ctx, &v2ec2.DescribeSecurityGroupsInput{})
	if err != nil {
		log.Println("Error describing security groups:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_12() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("eu-west-2"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	lambdaClient := v2lambda.NewFromConfig(cfg)
	
	input := &v2lambda.GetFunctionInput{
		FunctionName: aws.String("my-function"),
	}
	
	_, err = lambdaClient.GetFunction(ctx, input)
	if err != nil {
		log.Println("Error getting Lambda function:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_13() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("us-west-1"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	sqsClient := v2sqs.NewFromConfig(cfg)
	
	input := &v2sqs.SendMessageInput{
		QueueUrl:    aws.String("https://sqs.us-west-1.amazonaws.com/123456789012/my-queue"),
		MessageBody: aws.String("Hello, world!"),
	}
	
	_, err = sqsClient.SendMessage(ctx, input)
	if err != nil {
		log.Println("Error sending message:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_14() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("eu-central-1"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	snsClient := v2sns.NewFromConfig(cfg)
	
	input := &v2sns.PublishInput{
		TopicArn: aws.String("arn:aws:sns:eu-central-1:123456789012:my-topic"),
		Message:  aws.String("Hello, world!"),
	}
	
	_, err = snsClient.Publish(ctx, input)
	if err != nil {
		log.Println("Error publishing message:", err)
	}
}
// {/fact}

// {fact rule=not-recommended-apis@v1.0 defects=0}
func good_case_15() {
	// ok: rule-not-recommended-apis
	ctx := context.TODO()
	cfg, err := v2config.LoadDefaultConfig(ctx, v2config.WithRegion("us-east-1"))
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	iamClient := v2iam.NewFromConfig(cfg)
	
	input := &v2iam.GetUserInput{
		UserName: aws.String("my-user"),
	}
	
	_, err = iamClient.GetUser(ctx, input)
	if err != nil {
		log.Println("Error getting IAM user:", err)
	}
}
// {/fact}

func main() {
	// This is just a placeholder main function
	fmt.Println("AWS SDK examples")
}