package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// BAD CASES - Creating AWS clients inside Lambda handler functions

// bad_case_1 creates an S3 client inside the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_1() {
	lambda.Start(func(ctx context.Context) error {
		// ruleid: rule-lambda-client-reuse
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return err
		}
		s3Client := s3.NewFromConfig(cfg)
		
		// Use the client
		_, err = s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
		return err
	})
}
// {/fact}

// bad_case_2 creates a DynamoDB client inside the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_2() {
	lambda.Start(func(ctx context.Context) (string, error) {
		// ruleid: rule-lambda-client-reuse
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return "", err
		}
		dynamoClient := dynamodb.NewFromConfig(cfg)
		
		// Use the client
		_, err = dynamoClient.ListTables(ctx, &dynamodb.ListTablesInput{})
		return "Success", err
	})
}
// {/fact}

// bad_case_3 creates an SQS client inside the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_3() {
	handler := func(ctx context.Context) error {
		// ruleid: rule-lambda-client-reuse
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return err
		}
		sqsClient := sqs.NewFromConfig(cfg)
		
		// Use the client
		_, err = sqsClient.ListQueues(ctx, &sqs.ListQueuesInput{})
		return err
	}
	
	lambda.Start(handler)
}
// {/fact}

// bad_case_4 creates an SNS client inside the Lambda handler with custom options
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_4() {
	lambda.Start(func(ctx context.Context) error {
		// ruleid: rule-lambda-client-reuse
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-west-2"))
		if err != nil {
			return err
		}
		snsClient := sns.NewFromConfig(cfg)
		
		// Use the client
		_, err = snsClient.ListTopics(ctx, &sns.ListTopicsInput{})
		return err
	})
}
// {/fact}

// bad_case_5 creates multiple AWS clients inside the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_5() {
	lambda.Start(func(ctx context.Context) error {
		// ruleid: rule-lambda-client-reuse
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return err
		}
		s3Client := s3.NewFromConfig(cfg)
		
		// ruleid: rule-lambda-client-reuse
		dynamoClient := dynamodb.NewFromConfig(cfg)
		
		// Use the clients
		_, err = s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return err
		}
		_, err = dynamoClient.ListTables(ctx, &dynamodb.ListTablesInput{})
		return err
	})
}
// {/fact}

// bad_case_6 creates a client inside a nested function within the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_6() {
	lambda.Start(func(ctx context.Context) error {
		processRequest := func() error {
			// ruleid: rule-lambda-client-reuse
			cfg, err := config.LoadDefaultConfig(ctx)
			if err != nil {
				return err
			}
			sesClient := ses.NewFromConfig(cfg)
			
			// Use the client
			_, err = sesClient.ListIdentities(ctx, &ses.ListIdentitiesInput{})
			return err
		}
		
		return processRequest()
	})
}
// {/fact}

// bad_case_7 creates a client inside a conditional block within the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_7() {
	lambda.Start(func(ctx context.Context) error {
		needsClient := true
		
		if needsClient {
			// ruleid: rule-lambda-client-reuse
			cfg, err := config.LoadDefaultConfig(ctx)
			if err != nil {
				return err
			}
			ssmClient := ssm.NewFromConfig(cfg)
			
			// Use the client
			_, err = ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
				Name: aws.String("/my/parameter"),
			})
			return err
		}
		
		return nil
	})
}
// {/fact}

// bad_case_8 creates a client inside a loop within the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_8() {
	lambda.Start(func(ctx context.Context) error {
		regions := []string{"us-east-1", "us-west-2", "eu-west-1"}
		
		for _, region := range regions {
			// ruleid: rule-lambda-client-reuse
			cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
			if err != nil {
				return err
			}
			s3Client := s3.NewFromConfig(cfg)
			
			// Use the client
			_, err = s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
			if err != nil {
				return err
			}
		}
		
		return nil
	})
}
// {/fact}

// bad_case_9 creates a client with error handling but still inside the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_9() {
	lambda.Start(func(ctx context.Context) error {
		// ruleid: rule-lambda-client-reuse
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load SDK config: %v", err)
			return err
		}
		
		secretsClient := secretsmanager.NewFromConfig(cfg)
		
		// Use the client
		_, err = secretsClient.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to list secrets: %v", err)
			return err
		}
		
		return nil
	})
}
// {/fact}

// bad_case_10 creates a client with custom configuration inside the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_10() {
	lambda.Start(func(ctx context.Context) error {
		// ruleid: rule-lambda-client-reuse
		cfg, err := config.LoadDefaultConfig(ctx, 
			config.WithRegion("eu-central-1"),
			config.WithRetryMaxAttempts(5),
		)
		if err != nil {
			return err
		}
		
		dynamoClient := dynamodb.NewFromConfig(cfg)
		
		// Use the client
		_, err = dynamoClient.ListTables(ctx, &dynamodb.ListTablesInput{})
		return err
	})
}
// {/fact}

// bad_case_11 creates a client with a switch statement inside the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_11() {
	lambda.Start(func(ctx context.Context, eventType string) error {
		switch eventType {
		case "s3":
			// ruleid: rule-lambda-client-reuse
			cfg, err := config.LoadDefaultConfig(ctx)
			if err != nil {
				return err
			}
			s3Client := s3.NewFromConfig(cfg)
			
			// Use the client
			_, err = s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
			return err
		case "dynamodb":
			// ruleid: rule-lambda-client-reuse
			cfg, err := config.LoadDefaultConfig(ctx)
			if err != nil {
				return err
			}
			dynamoClient := dynamodb.NewFromConfig(cfg)
			
			// Use the client
			_, err = dynamoClient.ListTables(ctx, &dynamodb.ListTablesInput{})
			return err
		}
		
		return nil
	})
}
// {/fact}

// bad_case_12 creates a client with deferred cleanup inside the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_12() {
	lambda.Start(func(ctx context.Context) error {
		// ruleid: rule-lambda-client-reuse
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return err
		}
		
		sqsClient := sqs.NewFromConfig(cfg)
		
		// Deferred cleanup (unnecessary for AWS SDK clients)
		defer func() {
			fmt.Println("Cleaning up resources")
		}()
		
		// Use the client
		_, err = sqsClient.ListQueues(ctx, &sqs.ListQueuesInput{})
		return err
	})
}
// {/fact}

// bad_case_13 creates a client with try/catch equivalent inside the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_13() {
	lambda.Start(func(ctx context.Context) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("recovered from panic: %v", r)
			}
		}()
		
		// ruleid: rule-lambda-client-reuse
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return err
		}
		
		snsClient := sns.NewFromConfig(cfg)
		
		// Use the client
		_, err = snsClient.ListTopics(ctx, &sns.ListTopicsInput{})
		return err
	})
}
// {/fact}

// bad_case_14 creates a client with environment variable configuration inside the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_14() {
	lambda.Start(func(ctx context.Context) error {
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "us-east-1"
		}
		
		// ruleid: rule-lambda-client-reuse
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			return err
		}
		
		s3Client := s3.NewFromConfig(cfg)
		
		// Use the client
		_, err = s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
		return err
	})
}
// {/fact}

// bad_case_15 creates a client with custom endpoint inside the Lambda handler
// {fact rule=lambda-client-reuse@v1.0 defects=1}
func bad_case_15() {
	lambda.Start(func(ctx context.Context) error {
		// ruleid: rule-lambda-client-reuse
		customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
			return aws.Endpoint{
				URL: "http://localhost:4566", // LocalStack endpoint
			}, nil
		})
		
		cfg, err := config.LoadDefaultConfig(ctx, 
			config.WithRegion("us-east-1"),
			config.WithEndpointResolverWithOptions(customResolver),
		)
		if err != nil {
			return err
		}
		
		dynamoClient := dynamodb.NewFromConfig(cfg)
		
		// Use the client
		_, err = dynamoClient.ListTables(ctx, &dynamodb.ListTablesInput{})
		return err
	})
}
// {/fact}

// GOOD CASES - Properly reusing AWS clients across Lambda invocations

// Initialize clients outside the handler
var s3ClientGood *s3.Client
var dynamoClientGood *dynamodb.Client
var sqsClientGood *sqs.Client
var snsClientGood *sns.Client
var sesClientGood *ses.Client
var ssmClientGood *ssm.Client
var secretsClientGood *secretsmanager.Client

// Initialize configuration once
func init() {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		panic(fmt.Sprintf("failed to load SDK config: %v", err))
	}
	
	// Initialize clients once
	s3ClientGood = s3.NewFromConfig(cfg)
	dynamoClientGood = dynamodb.NewFromConfig(cfg)
	sqsClientGood = sqs.NewFromConfig(cfg)
	snsClientGood = sns.NewFromConfig(cfg)
	sesClientGood = ses.NewFromConfig(cfg)
	ssmClientGood = ssm.NewFromConfig(cfg)
	secretsClientGood = secretsmanager.NewFromConfig(cfg)
}

// good_case_1 reuses the S3 client initialized outside the handler
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_1() {
	lambda.Start(func(ctx context.Context) error {
		// ok: rule-lambda-client-reuse
		_, err := s3ClientGood.ListBuckets(ctx, &s3.ListBucketsInput{})
		return err
	})
}
// {/fact}

// good_case_2 reuses the DynamoDB client initialized outside the handler
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_2() {
	lambda.Start(func(ctx context.Context) (string, error) {
		// ok: rule-lambda-client-reuse
		_, err := dynamoClientGood.ListTables(ctx, &dynamodb.ListTablesInput{})
		return "Success", err
	})
}
// {/fact}

// good_case_3 reuses the SQS client initialized outside the handler
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_3() {
	handler := func(ctx context.Context) error {
		// ok: rule-lambda-client-reuse
		_, err := sqsClientGood.ListQueues(ctx, &sqs.ListQueuesInput{})
		return err
	}
	
	lambda.Start(handler)
}
// {/fact}

// good_case_4 reuses the SNS client initialized outside the handler
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_4() {
	lambda.Start(func(ctx context.Context) error {
		// ok: rule-lambda-client-reuse
		_, err := snsClientGood.ListTopics(ctx, &sns.ListTopicsInput{})
		return err
	})
}
// {/fact}

// good_case_5 reuses multiple clients initialized outside the handler
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_5() {
	lambda.Start(func(ctx context.Context) error {
		// ok: rule-lambda-client-reuse
		_, err := s3ClientGood.ListBuckets(ctx, &s3.ListBucketsInput{})
		if err != nil {
			return err
		}
		
		// ok: rule-lambda-client-reuse
		_, err = dynamoClientGood.ListTables(ctx, &dynamodb.ListTablesInput{})
		return err
	})
}
// {/fact}

// Alternative pattern with package-level variables
var (
	// Initialize once
	awsConfig, _ = config.LoadDefaultConfig(context.Background())
)

// good_case_6 uses a package-level config variable
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_6() {
	// Initialize client once outside handler
	sesClient := ses.NewFromConfig(awsConfig)
	
	lambda.Start(func(ctx context.Context) error {
		// ok: rule-lambda-client-reuse
		_, err := sesClient.ListIdentities(ctx, &ses.ListIdentitiesInput{})
		return err
	})
}
// {/fact}

// good_case_7 uses a singleton pattern for client initialization
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_7() {
	// Singleton pattern
	var ssmClient *ssm.Client
	
	// Initialize once outside handler
	ssmClient = ssm.NewFromConfig(awsConfig)
	
	lambda.Start(func(ctx context.Context) error {
		// ok: rule-lambda-client-reuse
		_, err := ssmClient.GetParameter(ctx, &ssm.GetParameterInput{
			Name: aws.String("/my/parameter"),
		})
		return err
	})
}
// {/fact}

// good_case_8 uses a function that returns a singleton client
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_8() {
	// Singleton getter function
	var s3ClientInstance *s3.Client
	
	getS3Client := func() *s3.Client {
		if s3ClientInstance == nil {
			s3ClientInstance = s3.NewFromConfig(awsConfig)
		}
		return s3ClientInstance
	}
	
	// Initialize once outside handler
	s3Client := getS3Client()
	
	lambda.Start(func(ctx context.Context) error {
		// ok: rule-lambda-client-reuse
		_, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
		return err
	})
}
// {/fact}

// good_case_9 uses a struct to encapsulate the handler and clients
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_9() {
	// Handler struct with clients
	type MyHandler struct {
		secretsClient *secretsmanager.Client
	}
	
	// Initialize once outside handler
	handler := MyHandler{
		secretsClient: secretsmanager.NewFromConfig(awsConfig),
	}
	
	// Handler method
	handleRequest := func(ctx context.Context) error {
		// ok: rule-lambda-client-reuse
		_, err := handler.secretsClient.ListSecrets(ctx, &secretsmanager.ListSecretsInput{})
		return err
	}
	
	lambda.Start(handleRequest)
}
// {/fact}

// good_case_10 uses dependency injection for clients
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_10() {
	// Initialize once outside handler
	dynamoClient := dynamodb.NewFromConfig(awsConfig)
	
	// Handler factory with dependency injection
	createHandler := func(client *dynamodb.Client) func(context.Context) error {
		return func(ctx context.Context) error {
			// ok: rule-lambda-client-reuse
			_, err := client.ListTables(ctx, &dynamodb.ListTablesInput{})
			return err
		}
	}
	
	// Create handler with injected client
	handler := createHandler(dynamoClient)
	
	lambda.Start(handler)
}
// {/fact}

// good_case_11 uses a switch statement with pre-initialized clients
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_11() {
	// Initialize clients once outside handler
	s3Client := s3.NewFromConfig(awsConfig)
	dynamoClient := dynamodb.NewFromConfig(awsConfig)
	
	lambda.Start(func(ctx context.Context, eventType string) error {
		switch eventType {
		case "s3":
			// ok: rule-lambda-client-reuse
			_, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
			return err
		case "dynamodb":
			// ok: rule-lambda-client-reuse
			_, err := dynamoClient.ListTables(ctx, &dynamodb.ListTablesInput{})
			return err
		}
		
		return nil
	})
}
// {/fact}

// good_case_12 uses lazy initialization but still outside the handler
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_12() {
	var sqsClient *sqs.Client
	var initErr error
	
	// Lazy initialization function
	initSQSClient := func() {
		if sqsClient == nil {
			cfg, err := config.LoadDefaultConfig(context.Background())
			if err != nil {
				initErr = err
				return
			}
			sqsClient = sqs.NewFromConfig(cfg)
		}
	}
	
	// Initialize once outside handler
	initSQSClient()
	
	lambda.Start(func(ctx context.Context) error {
		if initErr != nil {
			return initErr
		}
		
		// ok: rule-lambda-client-reuse
		_, err := sqsClient.ListQueues(ctx, &sqs.ListQueuesInput{})
		return err
	})
}
// {/fact}

// good_case_13 uses a client initialized with custom options outside the handler
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_13() {
	// Custom configuration
	customCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("eu-central-1"),
		config.WithRetryMaxAttempts(5),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to load custom SDK config: %v", err))
	}
	
	// Initialize once outside handler
	snsClient := sns.NewFromConfig(customCfg)
	
	lambda.Start(func(ctx context.Context) error {
		// ok: rule-lambda-client-reuse
		_, err := snsClient.ListTopics(ctx, &sns.ListTopicsInput{})
		return err
	})
}
// {/fact}

// good_case_14 uses environment variables for configuration but initializes client outside handler
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_14() {
	// Get region from environment
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	
	// Initialize with environment configuration once outside handler
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(region))
	if err != nil {
		panic(fmt.Sprintf("failed to load SDK config: %v", err))
	}
	
	s3Client := s3.NewFromConfig(cfg)
	
	lambda.Start(func(ctx context.Context) error {
		// ok: rule-lambda-client-reuse
		_, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
		return err
	})
}
// {/fact}

// good_case_15 uses a custom endpoint but initializes client outside handler
// {fact rule=lambda-client-reuse@v1.0 defects=0}
func good_case_15() {
	// Custom endpoint resolver
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL: "http://localhost:4566", // LocalStack endpoint
		}, nil
	})
	
	// Initialize with custom endpoint once outside handler
	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion("us-east-1"),
		config.WithEndpointResolverWithOptions(customResolver),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to load SDK config: %v", err))
	}
	
	dynamoClient := dynamodb.NewFromConfig(cfg)
	
	lambda.Start(func(ctx context.Context) error {
		// ok: rule-lambda-client-reuse
		_, err := dynamoClient.ListTables(ctx, &dynamodb.ListTablesInput{})
		return err
	})
}
// {/fact}

func main() {
	// This function is not used in AWS Lambda environment
	// It's here just to make the code compilable
	fmt.Println("This is a collection of AWS Lambda handler examples")
}