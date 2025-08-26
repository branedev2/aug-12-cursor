package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
)

// True Positives (Vulnerable Code)

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_1() {
	// Manual pagination for S3 ListObjectsV2
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := s3.NewFromConfig(cfg)
	bucketName := "my-bucket"
	
	// ruleid: rule-missing-pagination
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	}
	
	var nextToken *string
	for {
		output, err := client.ListObjectsV2(context.TODO(), input)
		if err != nil {
			log.Printf("Error listing objects: %v", err)
			break
		}
		
		for _, object := range output.Contents {
			fmt.Println(*object.Key)
		}
		
		if !output.IsTruncated {
			break
		}
		
		input.ContinuationToken = output.NextContinuationToken
		nextToken = output.NextContinuationToken
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_2() {
	// Manual pagination for DynamoDB Scan
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := dynamodb.NewFromConfig(cfg)
	tableName := "users"
	
	// ruleid: rule-missing-pagination
	input := &dynamodb.ScanInput{
		TableName: aws.String(tableName),
	}
	
	var lastEvaluatedKey map[string]dynamodb.AttributeValue
	for {
		output, err := client.Scan(context.TODO(), input)
		if err != nil {
			log.Printf("Error scanning table: %v", err)
			break
		}
		
		for _, item := range output.Items {
			fmt.Println(item)
		}
		
		if output.LastEvaluatedKey == nil {
			break
		}
		
		input.ExclusiveStartKey = output.LastEvaluatedKey
		lastEvaluatedKey = output.LastEvaluatedKey
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_3() {
	// Manual pagination for EC2 DescribeInstances
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := ec2.NewFromConfig(cfg)
	
	// ruleid: rule-missing-pagination
	input := &ec2.DescribeInstancesInput{}
	
	var nextToken *string
	for {
		output, err := client.DescribeInstances(context.TODO(), input)
		if err != nil {
			log.Printf("Error describing instances: %v", err)
			break
		}
		
		for _, reservation := range output.Reservations {
			for _, instance := range reservation.Instances {
				fmt.Println(*instance.InstanceId)
			}
		}
		
		if output.NextToken == nil {
			break
		}
		
		input.NextToken = output.NextToken
		nextToken = output.NextToken
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_4() {
	// Manual pagination for IAM ListUsers
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := iam.NewFromConfig(cfg)
	
	// ruleid: rule-missing-pagination
	input := &iam.ListUsersInput{}
	
	var marker *string
	for {
		output, err := client.ListUsers(context.TODO(), input)
		if err != nil {
			log.Printf("Error listing users: %v", err)
			break
		}
		
		for _, user := range output.Users {
			fmt.Println(*user.UserName)
		}
		
		if !output.IsTruncated {
			break
		}
		
		input.Marker = output.Marker
		marker = output.Marker
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_5() {
	// Manual pagination for CloudWatch ListMetrics
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := cloudwatch.NewFromConfig(cfg)
	
	// ruleid: rule-missing-pagination
	input := &cloudwatch.ListMetricsInput{}
	
	var nextToken *string
	for {
		output, err := client.ListMetrics(context.TODO(), input)
		if err != nil {
			log.Printf("Error listing metrics: %v", err)
			break
		}
		
		for _, metric := range output.Metrics {
			fmt.Println(*metric.MetricName)
		}
		
		if output.NextToken == nil {
			break
		}
		
		input.NextToken = output.NextToken
		nextToken = output.NextToken
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_6() {
	// Manual pagination for SQS ListQueues
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := sqs.NewFromConfig(cfg)
	
	// ruleid: rule-missing-pagination
	input := &sqs.ListQueuesInput{}
	
	var nextToken *string
	for {
		output, err := client.ListQueues(context.TODO(), input)
		if err != nil {
			log.Printf("Error listing queues: %v", err)
			break
		}
		
		for _, queueUrl := range output.QueueUrls {
			fmt.Println(queueUrl)
		}
		
		if output.NextToken == nil {
			break
		}
		
		input.NextToken = output.NextToken
		nextToken = output.NextToken
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_7() {
	// Manual pagination for SNS ListTopics
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := sns.NewFromConfig(cfg)
	
	// ruleid: rule-missing-pagination
	input := &sns.ListTopicsInput{}
	
	var nextToken *string
	for {
		output, err := client.ListTopics(context.TODO(), input)
		if err != nil {
			log.Printf("Error listing topics: %v", err)
			break
		}
		
		for _, topic := range output.Topics {
			fmt.Println(*topic.TopicArn)
		}
		
		if output.NextToken == nil {
			break
		}
		
		input.NextToken = output.NextToken
		nextToken = output.NextToken
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_8() {
	// Manual pagination for Lambda ListFunctions
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := lambda.NewFromConfig(cfg)
	
	// ruleid: rule-missing-pagination
	input := &lambda.ListFunctionsInput{}
	
	var marker *string
	for {
		output, err := client.ListFunctions(context.TODO(), input)
		if err != nil {
			log.Printf("Error listing functions: %v", err)
			break
		}
		
		for _, function := range output.Functions {
			fmt.Println(*function.FunctionName)
		}
		
		if output.NextMarker == nil {
			break
		}
		
		input.Marker = output.NextMarker
		marker = output.NextMarker
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_9() {
	// Manual pagination for CloudFormation ListStacks
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := cloudformation.NewFromConfig(cfg)
	
	// ruleid: rule-missing-pagination
	input := &cloudformation.ListStacksInput{}
	
	var nextToken *string
	for {
		output, err := client.ListStacks(context.TODO(), input)
		if err != nil {
			log.Printf("Error listing stacks: %v", err)
			break
		}
		
		for _, stack := range output.StackSummaries {
			fmt.Println(*stack.StackName)
		}
		
		if output.NextToken == nil {
			break
		}
		
		input.NextToken = output.NextToken
		nextToken = output.NextToken
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_10() {
	// Manual pagination for SecretsManager ListSecrets
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := secretsmanager.NewFromConfig(cfg)
	
	// ruleid: rule-missing-pagination
	input := &secretsmanager.ListSecretsInput{}
	
	var nextToken *string
	for {
		output, err := client.ListSecrets(context.TODO(), input)
		if err != nil {
			log.Printf("Error listing secrets: %v", err)
			break
		}
		
		for _, secret := range output.SecretList {
			fmt.Println(*secret.Name)
		}
		
		if output.NextToken == nil {
			break
		}
		
		input.NextToken = output.NextToken
		nextToken = output.NextToken
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_11() {
	// Manual pagination for RDS DescribeDBInstances
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := rds.NewFromConfig(cfg)
	
	// ruleid: rule-missing-pagination
	input := &rds.DescribeDBInstancesInput{}
	
	var marker *string
	for {
		output, err := client.DescribeDBInstances(context.TODO(), input)
		if err != nil {
			log.Printf("Error describing DB instances: %v", err)
			break
		}
		
		for _, instance := range output.DBInstances {
			fmt.Println(*instance.DBInstanceIdentifier)
		}
		
		if output.Marker == nil {
			break
		}
		
		input.Marker = output.Marker
		marker = output.Marker
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_12() {
	// Manual pagination for ElastiCache DescribeCacheClusters
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := elasticache.NewFromConfig(cfg)
	
	// ruleid: rule-missing-pagination
	input := &elasticache.DescribeCacheClustersInput{}
	
	var marker *string
	for {
		output, err := client.DescribeCacheClusters(context.TODO(), input)
		if err != nil {
			log.Printf("Error describing cache clusters: %v", err)
			break
		}
		
		for _, cluster := range output.CacheClusters {
			fmt.Println(*cluster.CacheClusterId)
		}
		
		if output.Marker == nil {
			break
		}
		
		input.Marker = output.Marker
		marker = output.Marker
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_13() {
	// Manual pagination for KMS ListKeys
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := kms.NewFromConfig(cfg)
	
	// ruleid: rule-missing-pagination
	input := &kms.ListKeysInput{}
	
	var marker *string
	for {
		output, err := client.ListKeys(context.TODO(), input)
		if err != nil {
			log.Printf("Error listing keys: %v", err)
			break
		}
		
		for _, key := range output.Keys {
			fmt.Println(*key.KeyId)
		}
		
		if output.Truncated == false {
			break
		}
		
		input.Marker = output.NextMarker
		marker = output.NextMarker
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_14() {
	// Manual pagination for ElasticBeanstalk DescribeEnvironments
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := elasticbeanstalk.NewFromConfig(cfg)
	
	// ruleid: rule-missing-pagination
	input := &elasticbeanstalk.DescribeEnvironmentsInput{}
	
	var nextToken *string
	for {
		output, err := client.DescribeEnvironments(context.TODO(), input)
		if err != nil {
			log.Printf("Error describing environments: %v", err)
			break
		}
		
		for _, env := range output.Environments {
			fmt.Println(*env.EnvironmentName)
		}
		
		if output.NextToken == nil {
			break
		}
		
		input.NextToken = output.NextToken
		nextToken = output.NextToken
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=1}
func bad_case_15() {
	// Manual pagination for API Gateway GetResources
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := apigateway.NewFromConfig(cfg)
	restApiId := "api123"
	
	// ruleid: rule-missing-pagination
	input := &apigateway.GetResourcesInput{
		RestApiId: aws.String(restApiId),
	}
	
	var position *string
	for {
		output, err := client.GetResources(context.TODO(), input)
		if err != nil {
			log.Printf("Error getting resources: %v", err)
			break
		}
		
		for _, resource := range output.Items {
			fmt.Println(*resource.Path)
		}
		
		if output.Position == nil {
			break
		}
		
		input.Position = output.Position
		position = output.Position
	}
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_1() {
	// Auto-pagination for S3 ListObjectsV2
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := s3.NewFromConfig(cfg)
	bucketName := "my-bucket"
	
	// ok: rule-missing-pagination
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	}
	
	paginator := s3.NewListObjectsV2Paginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error listing objects: %v", err)
			break
		}
		
		for _, object := range output.Contents {
			fmt.Println(*object.Key)
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_2() {
	// Auto-pagination for DynamoDB Scan
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := dynamodb.NewFromConfig(cfg)
	tableName := "users"
	
	// ok: rule-missing-pagination
	input := &dynamodb.ScanInput{
		TableName: aws.String(tableName),
	}
	
	paginator := dynamodb.NewScanPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error scanning table: %v", err)
			break
		}
		
		for _, item := range output.Items {
			fmt.Println(item)
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_3() {
	// Auto-pagination for EC2 DescribeInstances
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := ec2.NewFromConfig(cfg)
	
	// ok: rule-missing-pagination
	input := &ec2.DescribeInstancesInput{}
	
	paginator := ec2.NewDescribeInstancesPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error describing instances: %v", err)
			break
		}
		
		for _, reservation := range output.Reservations {
			for _, instance := range reservation.Instances {
				fmt.Println(*instance.InstanceId)
			}
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_4() {
	// Auto-pagination for IAM ListUsers
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := iam.NewFromConfig(cfg)
	
	// ok: rule-missing-pagination
	input := &iam.ListUsersInput{}
	
	paginator := iam.NewListUsersPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error listing users: %v", err)
			break
		}
		
		for _, user := range output.Users {
			fmt.Println(*user.UserName)
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_5() {
	// Auto-pagination for CloudWatch ListMetrics
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := cloudwatch.NewFromConfig(cfg)
	
	// ok: rule-missing-pagination
	input := &cloudwatch.ListMetricsInput{}
	
	paginator := cloudwatch.NewListMetricsPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error listing metrics: %v", err)
			break
		}
		
		for _, metric := range output.Metrics {
			fmt.Println(*metric.MetricName)
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_6() {
	// Auto-pagination for SQS ListQueues
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := sqs.NewFromConfig(cfg)
	
	// ok: rule-missing-pagination
	input := &sqs.ListQueuesInput{}
	
	paginator := sqs.NewListQueuesPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error listing queues: %v", err)
			break
		}
		
		for _, queueUrl := range output.QueueUrls {
			fmt.Println(queueUrl)
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_7() {
	// Auto-pagination for SNS ListTopics
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := sns.NewFromConfig(cfg)
	
	// ok: rule-missing-pagination
	input := &sns.ListTopicsInput{}
	
	paginator := sns.NewListTopicsPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error listing topics: %v", err)
			break
		}
		
		for _, topic := range output.Topics {
			fmt.Println(*topic.TopicArn)
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_8() {
	// Auto-pagination for Lambda ListFunctions
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := lambda.NewFromConfig(cfg)
	
	// ok: rule-missing-pagination
	input := &lambda.ListFunctionsInput{}
	
	paginator := lambda.NewListFunctionsPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error listing functions: %v", err)
			break
		}
		
		for _, function := range output.Functions {
			fmt.Println(*function.FunctionName)
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_9() {
	// Auto-pagination for CloudFormation ListStacks
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := cloudformation.NewFromConfig(cfg)
	
	// ok: rule-missing-pagination
	input := &cloudformation.ListStacksInput{}
	
	paginator := cloudformation.NewListStacksPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error listing stacks: %v", err)
			break
		}
		
		for _, stack := range output.StackSummaries {
			fmt.Println(*stack.StackName)
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_10() {
	// Auto-pagination for SecretsManager ListSecrets
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := secretsmanager.NewFromConfig(cfg)
	
	// ok: rule-missing-pagination
	input := &secretsmanager.ListSecretsInput{}
	
	paginator := secretsmanager.NewListSecretsPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error listing secrets: %v", err)
			break
		}
		
		for _, secret := range output.SecretList {
			fmt.Println(*secret.Name)
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_11() {
	// Auto-pagination for RDS DescribeDBInstances
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := rds.NewFromConfig(cfg)
	
	// ok: rule-missing-pagination
	input := &rds.DescribeDBInstancesInput{}
	
	paginator := rds.NewDescribeDBInstancesPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error describing DB instances: %v", err)
			break
		}
		
		for _, instance := range output.DBInstances {
			fmt.Println(*instance.DBInstanceIdentifier)
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_12() {
	// Auto-pagination for ElastiCache DescribeCacheClusters
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := elasticache.NewFromConfig(cfg)
	
	// ok: rule-missing-pagination
	input := &elasticache.DescribeCacheClustersInput{}
	
	paginator := elasticache.NewDescribeCacheClustersPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error describing cache clusters: %v", err)
			break
		}
		
		for _, cluster := range output.CacheClusters {
			fmt.Println(*cluster.CacheClusterId)
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_13() {
	// Auto-pagination for KMS ListKeys
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := kms.NewFromConfig(cfg)
	
	// ok: rule-missing-pagination
	input := &kms.ListKeysInput{}
	
	paginator := kms.NewListKeysPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error listing keys: %v", err)
			break
		}
		
		for _, key := range output.Keys {
			fmt.Println(*key.KeyId)
		}
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_14() {
	// Auto-pagination for ElasticBeanstalk DescribeEnvironments
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := elasticbeanstalk.NewFromConfig(cfg)
	
	// ok: rule-missing-pagination
	input := &elasticbeanstalk.DescribeEnvironmentsInput{}
	
	// Using a single call when we know there won't be many results
	output, err := client.DescribeEnvironments(context.TODO(), input)
	if err != nil {
		log.Printf("Error describing environments: %v", err)
		return
	}
	
	// Process all results at once since we know the result set is small
	for _, env := range output.Environments {
		fmt.Println(*env.EnvironmentName)
	}
}
// {/fact}

// {fact rule=missing-pagination@v1.0 defects=0}
func good_case_15() {
	// Auto-pagination for API Gateway GetResources
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	client := apigateway.NewFromConfig(cfg)
	restApiId := "api123"
	
	// ok: rule-missing-pagination
	input := &apigateway.GetResourcesInput{
		RestApiId: aws.String(restApiId),
	}
	
	paginator := apigateway.NewGetResourcesPaginator(client, input)
	
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error getting resources: %v", err)
			break
		}
		
		for _, resource := range output.Items {
			fmt.Println(*resource.Path)
		}
	}
}
// {/fact}

func main() {
	// This is just a placeholder main function
	fmt.Println("AWS SDK Pagination Examples")
}