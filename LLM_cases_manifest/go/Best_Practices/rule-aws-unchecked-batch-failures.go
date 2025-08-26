package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go/aws/session"
	lambdaService "github.com/aws/aws-sdk-go/service/lambda"
)

// True Positives (Vulnerable Code)

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_1() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create batch write request with multiple items
	writeRequests := []types.WriteRequest{
		{
			PutRequest: &types.PutRequest{
				Item: map[string]types.AttributeValue{
					"id":   &types.AttributeValueMemberS{Value: "1"},
					"name": &types.AttributeValueMemberS{Value: "Item 1"},
				},
			},
		},
		{
			PutRequest: &types.PutRequest{
				Item: map[string]types.AttributeValue{
					"id":   &types.AttributeValueMemberS{Value: "2"},
					"name": &types.AttributeValueMemberS{Value: "Item 2"},
				},
			},
		},
	}

	// Batch write without checking for unprocessed items
	input := &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]types.WriteRequest{
			"MyTable": writeRequests,
		},
	}

	// ruleid: rule-aws-unchecked-batch-failures
	_, err = client.BatchWriteItem(context.TODO(), input)
	if err != nil {
		log.Printf("Error in BatchWriteItem: %v", err)
		return
	}
	// No check for unprocessed items
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_2() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create batch get request
	keys := []map[string]types.AttributeValue{
		{
			"id": &types.AttributeValueMemberS{Value: "1"},
		},
		{
			"id": &types.AttributeValueMemberS{Value: "2"},
		},
	}

	// Batch get without checking for unprocessed keys
	input := &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			"MyTable": {
				Keys: keys,
			},
		},
	}

	// ruleid: rule-aws-unchecked-batch-failures
	response, err := client.BatchGetItem(context.TODO(), input)
	if err != nil {
		log.Printf("Error in BatchGetItem: %v", err)
		return
	}
	
	// Process the results but don't check for unprocessed keys
	for tableName, items := range response.Responses {
		log.Printf("Table %s has %d items", tableName, len(items))
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_3() {
	// Initialize SQS client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := sqs.NewFromConfig(cfg)

	// Create batch delete request
	entries := []types.DeleteMessageBatchRequestEntry{
		{
			Id:            aws.String("msg1"),
			ReceiptHandle: aws.String("receipt-handle-1"),
		},
		{
			Id:            aws.String("msg2"),
			ReceiptHandle: aws.String("receipt-handle-2"),
		},
	}

	// Batch delete without checking for failures
	input := &sqs.DeleteMessageBatchInput{
		QueueUrl: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue"),
		Entries:  entries,
	}

	// ruleid: rule-aws-unchecked-batch-failures
	_, err = client.DeleteMessageBatch(context.TODO(), input)
	if err != nil {
		log.Printf("Error in DeleteMessageBatch: %v", err)
		return
	}
	// No check for failed entries
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_4() {
	// Initialize SQS client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := sqs.NewFromConfig(cfg)

	// Create batch send request
	entries := []types.SendMessageBatchRequestEntry{
		{
			Id:          aws.String("msg1"),
			MessageBody: aws.String("Message 1"),
		},
		{
			Id:          aws.String("msg2"),
			MessageBody: aws.String("Message 2"),
		},
	}

	// Batch send without checking for failures
	input := &sqs.SendMessageBatchInput{
		QueueUrl: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue"),
		Entries:  entries,
	}

	// ruleid: rule-aws-unchecked-batch-failures
	result, err := client.SendMessageBatch(context.TODO(), input)
	if err != nil {
		log.Printf("Error in SendMessageBatch: %v", err)
		return
	}
	
	// Process successful entries but don't check for failed ones
	log.Printf("Sent %d messages successfully", len(result.Successful))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_5() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := s3.NewFromConfig(cfg)

	// Create batch delete objects request
	objects := []types.ObjectIdentifier{
		{
			Key: aws.String("file1.txt"),
		},
		{
			Key: aws.String("file2.txt"),
		},
	}

	// Batch delete without checking for errors
	input := &s3.DeleteObjectsInput{
		Bucket: aws.String("my-bucket"),
		Delete: &types.Delete{
			Objects: objects,
		},
	}

	// ruleid: rule-aws-unchecked-batch-failures
	_, err = client.DeleteObjects(context.TODO(), input)
	if err != nil {
		log.Printf("Error in DeleteObjects: %v", err)
		return
	}
	// No check for errors in the response
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_6() {
	// Initialize Lambda client
	sess := session.Must(session.NewSession())
	client := lambdaService.New(sess)

	// Create batch invoke request
	input := &lambdaService.InvokeAsyncInput{
		FunctionName: aws.String("my-function"),
		InvokeArgs:   strings.NewReader(`{"key": "value"}`),
	}

	// Multiple invocations without checking status
	for i := 0; i < 5; i++ {
		// ruleid: rule-aws-unchecked-batch-failures
		result, err := client.InvokeAsync(input)
		if err != nil {
			log.Printf("Error invoking Lambda: %v", err)
			continue
		}
		
		// Not checking if the status code indicates success
		log.Printf("Invocation %d completed", i)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_7() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create batch write request with multiple items for different tables
	requestItems := map[string][]types.WriteRequest{
		"Table1": {
			{
				PutRequest: &types.PutRequest{
					Item: map[string]types.AttributeValue{
						"id": &types.AttributeValueMemberS{Value: "1"},
					},
				},
			},
		},
		"Table2": {
			{
				PutRequest: &types.PutRequest{
					Item: map[string]types.AttributeValue{
						"id": &types.AttributeValueMemberS{Value: "2"},
					},
				},
			},
		},
	}

	// Batch write without checking for unprocessed items
	input := &dynamodb.BatchWriteItemInput{
		RequestItems: requestItems,
	}

	// ruleid: rule-aws-unchecked-batch-failures
	response, err := client.BatchWriteItem(context.TODO(), input)
	if err != nil {
		log.Printf("Error in BatchWriteItem: %v", err)
		return
	}
	
	// Process the response but don't check for unprocessed items
	log.Printf("Batch write completed with response: %v", response)
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_8() {
	// Initialize SQS client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := sqs.NewFromConfig(cfg)

	// Create batch change message visibility request
	entries := []types.ChangeMessageVisibilityBatchRequestEntry{
		{
			Id:                aws.String("msg1"),
			ReceiptHandle:     aws.String("receipt-handle-1"),
			VisibilityTimeout: aws.Int32(60),
		},
		{
			Id:                aws.String("msg2"),
			ReceiptHandle:     aws.String("receipt-handle-2"),
			VisibilityTimeout: aws.Int32(120),
		},
	}

	// Batch change visibility without checking for failures
	input := &sqs.ChangeMessageVisibilityBatchInput{
		QueueUrl: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue"),
		Entries:  entries,
	}

	// ruleid: rule-aws-unchecked-batch-failures
	_, err = client.ChangeMessageVisibilityBatch(context.TODO(), input)
	if err != nil {
		log.Printf("Error in ChangeMessageVisibilityBatch: %v", err)
		return
	}
	// No check for failed entries
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_9() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create transaction write request with multiple items
	transactItems := []types.TransactWriteItem{
		{
			Put: &types.Put{
				TableName: aws.String("Table1"),
				Item: map[string]types.AttributeValue{
					"id": &types.AttributeValueMemberS{Value: "1"},
				},
			},
		},
		{
			Update: &types.Update{
				TableName: aws.String("Table2"),
				Key: map[string]types.AttributeValue{
					"id": &types.AttributeValueMemberS{Value: "2"},
				},
				UpdateExpression: aws.String("SET #status = :s"),
				ExpressionAttributeNames: map[string]string{
					"#status": "status",
				},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":s": &types.AttributeValueMemberS{Value: "updated"},
				},
			},
		},
	}

	// Transaction write without checking for cancellations
	input := &dynamodb.TransactWriteItemsInput{
		TransactItems: transactItems,
	}

	// ruleid: rule-aws-unchecked-batch-failures
	_, err = client.TransactWriteItems(context.TODO(), input)
	if err != nil {
		log.Printf("Error in TransactWriteItems: %v", err)
		return
	}
	// No check for cancellation reasons
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_10() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create transaction get request with multiple items
	transactItems := []types.TransactGetItem{
		{
			Get: &types.Get{
				TableName: aws.String("Table1"),
				Key: map[string]types.AttributeValue{
					"id": &types.AttributeValueMemberS{Value: "1"},
				},
			},
		},
		{
			Get: &types.Get{
				TableName: aws.String("Table2"),
				Key: map[string]types.AttributeValue{
					"id": &types.AttributeValueMemberS{Value: "2"},
				},
			},
		},
	}

	// Transaction get without checking for failures
	input := &dynamodb.TransactGetItemsInput{
		TransactItems: transactItems,
	}

	// ruleid: rule-aws-unchecked-batch-failures
	result, err := client.TransactGetItems(context.TODO(), input)
	if err != nil {
		log.Printf("Error in TransactGetItems: %v", err)
		return
	}
	
	// Process the results but don't check for failures
	log.Printf("Got %d items", len(result.Responses))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_11() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := s3.NewFromConfig(cfg)

	// Create batch delete objects request with versioning
	objects := []types.ObjectIdentifier{
		{
			Key:       aws.String("file1.txt"),
			VersionId: aws.String("v1"),
		},
		{
			Key:       aws.String("file2.txt"),
			VersionId: aws.String("v2"),
		},
	}

	// Batch delete without checking for errors
	input := &s3.DeleteObjectsInput{
		Bucket: aws.String("my-bucket"),
		Delete: &types.Delete{
			Objects: objects,
		},
	}

	// ruleid: rule-aws-unchecked-batch-failures
	result, err := client.DeleteObjects(context.TODO(), input)
	if err != nil {
		log.Printf("Error in DeleteObjects: %v", err)
		return
	}
	
	// Process the response but don't check for errors
	log.Printf("Delete operation completed with %d responses", len(result.Deleted))
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_12() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create batch write request with multiple delete operations
	writeRequests := []types.WriteRequest{
		{
			DeleteRequest: &types.DeleteRequest{
				Key: map[string]types.AttributeValue{
					"id": &types.AttributeValueMemberS{Value: "1"},
				},
			},
		},
		{
			DeleteRequest: &types.DeleteRequest{
				Key: map[string]types.AttributeValue{
					"id": &types.AttributeValueMemberS{Value: "2"},
				},
			},
		},
	}

	// Batch write without checking for unprocessed items
	input := &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]types.WriteRequest{
			"MyTable": writeRequests,
		},
	}

	// ruleid: rule-aws-unchecked-batch-failures
	_, err = client.BatchWriteItem(context.TODO(), input)
	if err != nil {
		log.Printf("Error in BatchWriteItem: %v", err)
		return
	}
	// No check for unprocessed items
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_13() {
	// Initialize SQS client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := sqs.NewFromConfig(cfg)

	// Create batch send request with attributes
	entries := []types.SendMessageBatchRequestEntry{
		{
			Id:          aws.String("msg1"),
			MessageBody: aws.String("Message 1"),
			MessageAttributes: map[string]types.MessageAttributeValue{
				"Attribute1": {
					DataType:    aws.String("String"),
					StringValue: aws.String("Value1"),
				},
			},
		},
		{
			Id:          aws.String("msg2"),
			MessageBody: aws.String("Message 2"),
			MessageAttributes: map[string]types.MessageAttributeValue{
				"Attribute2": {
					DataType:    aws.String("String"),
					StringValue: aws.String("Value2"),
				},
			},
		},
	}

	// Batch send without checking for failures
	input := &sqs.SendMessageBatchInput{
		QueueUrl: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue"),
		Entries:  entries,
	}

	// ruleid: rule-aws-unchecked-batch-failures
	_, err = client.SendMessageBatch(context.TODO(), input)
	if err != nil {
		log.Printf("Error in SendMessageBatch: %v", err)
		return
	}
	// No check for failed entries
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_14() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create batch get request with projection expression
	keys := []map[string]types.AttributeValue{
		{
			"id": &types.AttributeValueMemberS{Value: "1"},
		},
		{
			"id": &types.AttributeValueMemberS{Value: "2"},
		},
	}

	// Batch get without checking for unprocessed keys
	input := &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			"MyTable": {
				Keys:                keys,
				ProjectionExpression: aws.String("id, name, #status"),
				ExpressionAttributeNames: map[string]string{
					"#status": "status",
				},
			},
		},
	}

	// ruleid: rule-aws-unchecked-batch-failures
	_, err = client.BatchGetItem(context.TODO(), input)
	if err != nil {
		log.Printf("Error in BatchGetItem: %v", err)
		return
	}
	// No check for unprocessed keys
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=1}
func bad_case_15() {
	// Initialize SQS client for a loop of batch operations
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := sqs.NewFromConfig(cfg)

	// Create multiple batches
	for i := 0; i < 3; i++ {
		entries := []types.DeleteMessageBatchRequestEntry{
			{
				Id:            aws.String(fmt.Sprintf("msg%d-1", i)),
				ReceiptHandle: aws.String(fmt.Sprintf("receipt-handle-%d-1", i)),
			},
			{
				Id:            aws.String(fmt.Sprintf("msg%d-2", i)),
				ReceiptHandle: aws.String(fmt.Sprintf("receipt-handle-%d-2", i)),
			},
		}

		input := &sqs.DeleteMessageBatchInput{
			QueueUrl: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue"),
			Entries:  entries,
		}

		// ruleid: rule-aws-unchecked-batch-failures
		_, err = client.DeleteMessageBatch(context.TODO(), input)
		if err != nil {
			log.Printf("Error in batch %d: %v", i, err)
			continue
		}
		// No check for failed entries in any batch
	}
}
// {/fact}

// True Negatives (Safe Code)

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_1() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create batch write request with multiple items
	writeRequests := []types.WriteRequest{
		{
			PutRequest: &types.PutRequest{
				Item: map[string]types.AttributeValue{
					"id":   &types.AttributeValueMemberS{Value: "1"},
					"name": &types.AttributeValueMemberS{Value: "Item 1"},
				},
			},
		},
		{
			PutRequest: &types.PutRequest{
				Item: map[string]types.AttributeValue{
					"id":   &types.AttributeValueMemberS{Value: "2"},
					"name": &types.AttributeValueMemberS{Value: "Item 2"},
				},
			},
		},
	}

	// Batch write with checking for unprocessed items
	input := &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]types.WriteRequest{
			"MyTable": writeRequests,
		},
	}

	// ok: rule-aws-unchecked-batch-failures
	response, err := client.BatchWriteItem(context.TODO(), input)
	if err != nil {
		log.Printf("Error in BatchWriteItem: %v", err)
		return
	}
	
	// Check for unprocessed items
	if len(response.UnprocessedItems) > 0 {
		log.Printf("Warning: Some items were not processed: %v", response.UnprocessedItems)
		// Handle unprocessed items, e.g., retry
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_2() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create batch get request
	keys := []map[string]types.AttributeValue{
		{
			"id": &types.AttributeValueMemberS{Value: "1"},
		},
		{
			"id": &types.AttributeValueMemberS{Value: "2"},
		},
	}

	// Batch get with checking for unprocessed keys
	input := &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			"MyTable": {
				Keys: keys,
			},
		},
	}

	// ok: rule-aws-unchecked-batch-failures
	response, err := client.BatchGetItem(context.TODO(), input)
	if err != nil {
		log.Printf("Error in BatchGetItem: %v", err)
		return
	}
	
	// Process the results and check for unprocessed keys
	for tableName, items := range response.Responses {
		log.Printf("Table %s has %d items", tableName, len(items))
	}
	
	if len(response.UnprocessedKeys) > 0 {
		log.Printf("Warning: Some keys were not processed: %v", response.UnprocessedKeys)
		// Handle unprocessed keys, e.g., retry
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_3() {
	// Initialize SQS client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := sqs.NewFromConfig(cfg)

	// Create batch delete request
	entries := []types.DeleteMessageBatchRequestEntry{
		{
			Id:            aws.String("msg1"),
			ReceiptHandle: aws.String("receipt-handle-1"),
		},
		{
			Id:            aws.String("msg2"),
			ReceiptHandle: aws.String("receipt-handle-2"),
		},
	}

	// Batch delete with checking for failures
	input := &sqs.DeleteMessageBatchInput{
		QueueUrl: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue"),
		Entries:  entries,
	}

	// ok: rule-aws-unchecked-batch-failures
	result, err := client.DeleteMessageBatch(context.TODO(), input)
	if err != nil {
		log.Printf("Error in DeleteMessageBatch: %v", err)
		return
	}
	
	// Check for failed entries
	if len(result.Failed) > 0 {
		log.Printf("Warning: Some messages failed to delete: %v", result.Failed)
		// Handle failed entries, e.g., retry
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_4() {
	// Initialize SQS client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := sqs.NewFromConfig(cfg)

	// Create batch send request
	entries := []types.SendMessageBatchRequestEntry{
		{
			Id:          aws.String("msg1"),
			MessageBody: aws.String("Message 1"),
		},
		{
			Id:          aws.String("msg2"),
			MessageBody: aws.String("Message 2"),
		},
	}

	// Batch send with checking for failures
	input := &sqs.SendMessageBatchInput{
		QueueUrl: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue"),
		Entries:  entries,
	}

	// ok: rule-aws-unchecked-batch-failures
	result, err := client.SendMessageBatch(context.TODO(), input)
	if err != nil {
		log.Printf("Error in SendMessageBatch: %v", err)
		return
	}
	
	// Process successful entries and check for failed ones
	log.Printf("Sent %d messages successfully", len(result.Successful))
	
	if len(result.Failed) > 0 {
		log.Printf("Warning: Some messages failed to send: %v", result.Failed)
		// Handle failed entries, e.g., retry
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_5() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := s3.NewFromConfig(cfg)

	// Create batch delete objects request
	objects := []types.ObjectIdentifier{
		{
			Key: aws.String("file1.txt"),
		},
		{
			Key: aws.String("file2.txt"),
		},
	}

	// Batch delete with checking for errors
	input := &s3.DeleteObjectsInput{
		Bucket: aws.String("my-bucket"),
		Delete: &types.Delete{
			Objects: objects,
		},
	}

	// ok: rule-aws-unchecked-batch-failures
	result, err := client.DeleteObjects(context.TODO(), input)
	if err != nil {
		log.Printf("Error in DeleteObjects: %v", err)
		return
	}
	
	// Check for errors in the response
	if len(result.Errors) > 0 {
		log.Printf("Warning: Some objects failed to delete: %v", result.Errors)
		// Handle errors, e.g., retry
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_6() {
	// Initialize Lambda client
	sess := session.Must(session.NewSession())
	client := lambdaService.New(sess)

	// Create batch invoke request
	input := &lambdaService.InvokeAsyncInput{
		FunctionName: aws.String("my-function"),
		InvokeArgs:   strings.NewReader(`{"key": "value"}`),
	}

	// Multiple invocations with checking status
	for i := 0; i < 5; i++ {
		// ok: rule-aws-unchecked-batch-failures
		result, err := client.InvokeAsync(input)
		if err != nil {
			log.Printf("Error invoking Lambda: %v", err)
			continue
		}
		
		// Check if the status code indicates success
		if *result.Status != 202 {
			log.Printf("Warning: Invocation %d failed with status %d", i, *result.Status)
			// Handle failure, e.g., retry
		} else {
			log.Printf("Invocation %d completed successfully", i)
		}
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_7() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create batch write request with multiple items for different tables
	requestItems := map[string][]types.WriteRequest{
		"Table1": {
			{
				PutRequest: &types.PutRequest{
					Item: map[string]types.AttributeValue{
						"id": &types.AttributeValueMemberS{Value: "1"},
					},
				},
			},
		},
		"Table2": {
			{
				PutRequest: &types.PutRequest{
					Item: map[string]types.AttributeValue{
						"id": &types.AttributeValueMemberS{Value: "2"},
					},
				},
			},
		},
	}

	// Batch write with checking for unprocessed items
	input := &dynamodb.BatchWriteItemInput{
		RequestItems: requestItems,
	}

	// ok: rule-aws-unchecked-batch-failures
	response, err := client.BatchWriteItem(context.TODO(), input)
	if err != nil {
		log.Printf("Error in BatchWriteItem: %v", err)
		return
	}
	
	// Check for unprocessed items
	if len(response.UnprocessedItems) > 0 {
		log.Printf("Warning: Some items were not processed: %v", response.UnprocessedItems)
		
		// Retry unprocessed items
		retryInput := &dynamodb.BatchWriteItemInput{
			RequestItems: response.UnprocessedItems,
		}
		_, err = client.BatchWriteItem(context.TODO(), retryInput)
		if err != nil {
			log.Printf("Error in retry BatchWriteItem: %v", err)
		}
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_8() {
	// Initialize SQS client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := sqs.NewFromConfig(cfg)

	// Create batch change message visibility request
	entries := []types.ChangeMessageVisibilityBatchRequestEntry{
		{
			Id:                aws.String("msg1"),
			ReceiptHandle:     aws.String("receipt-handle-1"),
			VisibilityTimeout: aws.Int32(60),
		},
		{
			Id:                aws.String("msg2"),
			ReceiptHandle:     aws.String("receipt-handle-2"),
			VisibilityTimeout: aws.Int32(120),
		},
	}

	// Batch change visibility with checking for failures
	input := &sqs.ChangeMessageVisibilityBatchInput{
		QueueUrl: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue"),
		Entries:  entries,
	}

	// ok: rule-aws-unchecked-batch-failures
	result, err := client.ChangeMessageVisibilityBatch(context.TODO(), input)
	if err != nil {
		log.Printf("Error in ChangeMessageVisibilityBatch: %v", err)
		return
	}
	
	// Check for failed entries
	if len(result.Failed) > 0 {
		log.Printf("Warning: Failed to change visibility for some messages: %v", result.Failed)
		// Handle failed entries, e.g., retry
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_9() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create transaction write request with multiple items
	transactItems := []types.TransactWriteItem{
		{
			Put: &types.Put{
				TableName: aws.String("Table1"),
				Item: map[string]types.AttributeValue{
					"id": &types.AttributeValueMemberS{Value: "1"},
				},
			},
		},
		{
			Update: &types.Update{
				TableName: aws.String("Table2"),
				Key: map[string]types.AttributeValue{
					"id": &types.AttributeValueMemberS{Value: "2"},
				},
				UpdateExpression: aws.String("SET #status = :s"),
				ExpressionAttributeNames: map[string]string{
					"#status": "status",
				},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":s": &types.AttributeValueMemberS{Value: "updated"},
				},
			},
		},
	}

	// Transaction write with error handling
	input := &dynamodb.TransactWriteItemsInput{
		TransactItems: transactItems,
		ClientRequestToken: aws.String("idempotency-token"),
	}

	// ok: rule-aws-unchecked-batch-failures
	_, err = client.TransactWriteItems(context.TODO(), input)
	
	// Check for transaction cancellation errors
	var txCanceled *types.TransactionCanceledException
	if errors.As(err, &txCanceled) {
		log.Printf("Transaction was canceled: %v", txCanceled.CancellationReasons)
		// Handle cancellation reasons
		for i, reason := range txCanceled.CancellationReasons {
			if reason != nil && reason.Code != nil {
				log.Printf("Item %d was canceled because: %s - %s", i, *reason.Code, *reason.Message)
			}
		}
		return
	} else if err != nil {
		log.Printf("Error in TransactWriteItems: %v", err)
		return
	}
	
	log.Printf("Transaction completed successfully")
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_10() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create transaction get request with multiple items
	transactItems := []types.TransactGetItem{
		{
			Get: &types.Get{
				TableName: aws.String("Table1"),
				Key: map[string]types.AttributeValue{
					"id": &types.AttributeValueMemberS{Value: "1"},
				},
			},
		},
		{
			Get: &types.Get{
				TableName: aws.String("Table2"),
				Key: map[string]types.AttributeValue{
					"id": &types.AttributeValueMemberS{Value: "2"},
				},
			},
		},
	}

	// Transaction get with error handling
	input := &dynamodb.TransactGetItemsInput{
		TransactItems: transactItems,
	}

	// ok: rule-aws-unchecked-batch-failures
	result, err := client.TransactGetItems(context.TODO(), input)
	
	// Check for transaction errors
	if err != nil {
		var txCanceled *types.TransactionCanceledException
		if errors.As(err, &txCanceled) {
			log.Printf("Transaction was canceled: %v", txCanceled.CancellationReasons)
			// Handle cancellation reasons
			for i, reason := range txCanceled.CancellationReasons {
				if reason != nil && reason.Code != nil {
					log.Printf("Item %d was canceled because: %s - %s", i, *reason.Code, *reason.Message)
				}
			}
		} else {
			log.Printf("Error in TransactGetItems: %v", err)
		}
		return
	}
	
	// Process the results and check for empty responses
	for i, response := range result.Responses {
		if len(response.Item) == 0 {
			log.Printf("Warning: Item %d was not found", i)
		} else {
			log.Printf("Item %d was retrieved successfully", i)
		}
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_11() {
	// Initialize S3 client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := s3.NewFromConfig(cfg)

	// Create batch delete objects request with versioning
	objects := []types.ObjectIdentifier{
		{
			Key:       aws.String("file1.txt"),
			VersionId: aws.String("v1"),
		},
		{
			Key:       aws.String("file2.txt"),
			VersionId: aws.String("v2"),
		},
	}

	// Batch delete with checking for errors
	input := &s3.DeleteObjectsInput{
		Bucket: aws.String("my-bucket"),
		Delete: &types.Delete{
			Objects: objects,
		},
	}

	// ok: rule-aws-unchecked-batch-failures
	result, err := client.DeleteObjects(context.TODO(), input)
	if err != nil {
		log.Printf("Error in DeleteObjects: %v", err)
		return
	}
	
	// Check for errors in the response
	if result.Errors != nil && len(result.Errors) > 0 {
		log.Printf("Warning: Some objects failed to delete:")
		for _, e := range result.Errors {
			log.Printf("  Key: %s, Version: %s, Error: %s - %s", 
				*e.Key, 
				aws.ToString(e.VersionId), 
				*e.Code, 
				*e.Message)
		}
		// Handle errors, e.g., retry
	} else {
		log.Printf("All objects deleted successfully")
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_12() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create batch write request with multiple delete operations
	writeRequests := []types.WriteRequest{
		{
			DeleteRequest: &types.DeleteRequest{
				Key: map[string]types.AttributeValue{
					"id": &types.AttributeValueMemberS{Value: "1"},
				},
			},
		},
		{
			DeleteRequest: &types.DeleteRequest{
				Key: map[string]types.AttributeValue{
					"id": &types.AttributeValueMemberS{Value: "2"},
				},
			},
		},
	}

	// Batch write with checking for unprocessed items
	input := &dynamodb.BatchWriteItemInput{
		RequestItems: map[string][]types.WriteRequest{
			"MyTable": writeRequests,
		},
	}

	// ok: rule-aws-unchecked-batch-failures
	response, err := client.BatchWriteItem(context.TODO(), input)
	if err != nil {
		log.Printf("Error in BatchWriteItem: %v", err)
		return
	}
	
	// Check for unprocessed items and retry if needed
	for len(response.UnprocessedItems) > 0 {
		log.Printf("Some items were not processed, retrying...")
		retryInput := &dynamodb.BatchWriteItemInput{
			RequestItems: response.UnprocessedItems,
		}
		response, err = client.BatchWriteItem(context.TODO(), retryInput)
		if err != nil {
			log.Printf("Error in retry BatchWriteItem: %v", err)
			break
		}
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_13() {
	// Initialize SQS client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := sqs.NewFromConfig(cfg)

	// Create batch send request with attributes
	entries := []types.SendMessageBatchRequestEntry{
		{
			Id:          aws.String("msg1"),
			MessageBody: aws.String("Message 1"),
			MessageAttributes: map[string]types.MessageAttributeValue{
				"Attribute1": {
					DataType:    aws.String("String"),
					StringValue: aws.String("Value1"),
				},
			},
		},
		{
			Id:          aws.String("msg2"),
			MessageBody: aws.String("Message 2"),
			MessageAttributes: map[string]types.MessageAttributeValue{
				"Attribute2": {
					DataType:    aws.String("String"),
					StringValue: aws.String("Value2"),
				},
			},
		},
	}

	// Batch send with checking for failures
	input := &sqs.SendMessageBatchInput{
		QueueUrl: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue"),
		Entries:  entries,
	}

	// ok: rule-aws-unchecked-batch-failures
	result, err := client.SendMessageBatch(context.TODO(), input)
	if err != nil {
		log.Printf("Error in SendMessageBatch: %v", err)
		return
	}
	
	// Check for failed entries
	if len(result.Failed) > 0 {
		log.Printf("Warning: Some messages failed to send:")
		for _, failure := range result.Failed {
			log.Printf("  ID: %s, Code: %s, Message: %s", 
				*failure.Id, 
				*failure.Code, 
				*failure.Message)
		}
		
		// Retry failed messages
		var retryEntries []types.SendMessageBatchRequestEntry
		for _, failure := range result.Failed {
			for _, entry := range entries {
				if *entry.Id == *failure.Id {
					retryEntries = append(retryEntries, entry)
					break
				}
			}
		}
		
		if len(retryEntries) > 0 {
			retryInput := &sqs.SendMessageBatchInput{
				QueueUrl: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue"),
				Entries:  retryEntries,
			}
			_, err = client.SendMessageBatch(context.TODO(), retryInput)
			if err != nil {
				log.Printf("Error in retry SendMessageBatch: %v", err)
			}
		}
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_14() {
	// Initialize DynamoDB client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := dynamodb.NewFromConfig(cfg)

	// Create batch get request with projection expression
	keys := []map[string]types.AttributeValue{
		{
			"id": &types.AttributeValueMemberS{Value: "1"},
		},
		{
			"id": &types.AttributeValueMemberS{Value: "2"},
		},
	}

	// Batch get with checking for unprocessed keys
	input := &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			"MyTable": {
				Keys:                keys,
				ProjectionExpression: aws.String("id, name, #status"),
				ExpressionAttributeNames: map[string]string{
					"#status": "status",
				},
			},
		},
	}

	// ok: rule-aws-unchecked-batch-failures
	response, err := client.BatchGetItem(context.TODO(), input)
	if err != nil {
		log.Printf("Error in BatchGetItem: %v", err)
		return
	}
	
	// Process the results and check for unprocessed keys
	for tableName, items := range response.Responses {
		for i, item := range items {
			log.Printf("Table %s, Item %d: %v", tableName, i, item)
		}
	}
	
	// Handle unprocessed keys with exponential backoff
	maxRetries := 3
	for retries := 0; len(response.UnprocessedKeys) > 0 && retries < maxRetries; retries++ {
		log.Printf("Some keys were not processed, retrying (attempt %d)...", retries+1)
		
		// Exponential backoff
		time.Sleep(time.Duration(1<<uint(retries)) * time.Second)
		
		retryInput := &dynamodb.BatchGetItemInput{
			RequestItems: response.UnprocessedKeys,
		}
		
		response, err = client.BatchGetItem(context.TODO(), retryInput)
		if err != nil {
			log.Printf("Error in retry BatchGetItem: %v", err)
			break
		}
		
		// Process the results from the retry
		for tableName, items := range response.Responses {
			for i, item := range items {
				log.Printf("Retry %d, Table %s, Item %d: %v", retries+1, tableName, i, item)
			}
		}
	}
	
	if len(response.UnprocessedKeys) > 0 {
		log.Printf("Warning: After all retries, some keys still unprocessed: %v", response.UnprocessedKeys)
	}
}
// {/fact}

// {fact rule=guru-cfn-lint@v1.0 defects=0}
func good_case_15() {
	// Initialize SQS client for a loop of batch operations
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	client := sqs.NewFromConfig(cfg)

	// Create multiple batches
	for i := 0; i < 3; i++ {
		entries := []types.DeleteMessageBatchRequestEntry{
			{
				Id:            aws.String(fmt.Sprintf("msg%d-1", i)),
				ReceiptHandle: aws.String(fmt.Sprintf("receipt-handle-%d-1", i)),
			},
			{
				Id:            aws.String(fmt.Sprintf("msg%d-2", i)),
				ReceiptHandle: aws.String(fmt.Sprintf("receipt-handle-%d-2", i)),
			},
		}

		input := &sqs.DeleteMessageBatchInput{
			QueueUrl: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue"),
			Entries:  entries,
		}

		// ok: rule-aws-unchecked-batch-failures
		result, err := client.DeleteMessageBatch(context.TODO(), input)
		if err != nil {
			log.Printf("Error in batch %d: %v", i, err)
			continue
		}
		
		// Check for failed entries in each batch
		if len(result.Failed) > 0 {
			log.Printf("Batch %d: Some messages failed to delete:", i)
			for _, failure := range result.Failed {
				log.Printf("  ID: %s, Code: %s, Message: %s", 
					*failure.Id, 
					*failure.Code, 
					*failure.Message)
			}
			
			// Create a new batch with just the failed entries
			var retryEntries []types.DeleteMessageBatchRequestEntry
			for _, failure := range result.Failed {
				for _, entry := range entries {
					if *entry.Id == *failure.Id {
						retryEntries = append(retryEntries, entry)
						break
					}
				}
			}
			
			if len(retryEntries) > 0 {
				retryInput := &sqs.DeleteMessageBatchInput{
					QueueUrl: aws.String("https://sqs.us-west-2.amazonaws.com/123456789012/MyQueue"),
					Entries:  retryEntries,
				}
				_, retryErr := client.DeleteMessageBatch(context.TODO(), retryInput)
				if retryErr != nil {
					log.Printf("Error in retry batch %d: %v", i, retryErr)
				}
			}
		} else {
			log.Printf("Batch %d: All messages deleted successfully", i)
		}
	}
}
// {/fact}

func main() {
	// This is just a placeholder function to make the code compilable
	fmt.Println("AWS Batch Operations Example")
}