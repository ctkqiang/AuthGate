package aws

// Package aws (dynamodb.go) provides DynamoDB database operations.
//
// All functions require a prior call to [Initialize] so that the
// Account singleton holds a valid AWS SDK configuration. The DynamoDB
// client is constructed lazily on first use via ensureDynamoClient()
// and shared across all subsequent calls.
//
// Operations supported:
//   - Insert  — put a single item into a table
//   - Delete  — remove an item by its primary key
//   - Update  — apply a partial update to an existing item

import (
	"authgate/internal/utilities"
	"context"
	"fmt"
	"strings"

	aws_v2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	aws_dynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// dynamoClient is a lazy-initialised singleton DynamoDB client derived
// from the global Account config. It is safe for concurrent use once
// built.
var dynamoClient *aws_dynamodb.Client

// ensureDynamoClient builds the DynamoDB client exactly once.
func ensureDynamoClient() *aws_dynamodb.Client {
	if dynamoClient != nil {
		return dynamoClient
	}

	dynamoClient = aws_dynamodb.NewFromConfig(GetAccount().Config())

	return dynamoClient
}

// Insert writes a single item into the DynamoDB table named by
// tableName. The item map supports arbitrarily nested Go types
// (string, int, float64, bool, map, slice) and is marshalled to
// DynamoDB AttributeValues via the attributevalue package.
func Insert(ctx context.Context, tableName string, item map[string]interface{}) (bool, error) {
	db := ensureDynamoClient()

	av, err := attributevalue.MarshalMap(item)
	if err != nil {
		return false, fmt.Errorf("dynamodb Insert(%s): marshal: %w", tableName, err)
	}

	_, err = db.PutItem(ctx, &aws_dynamodb.PutItemInput{
		TableName: aws_v2.String(tableName),
		Item:      av,
	})
	if err != nil {
		return false, fmt.Errorf("dynamodb Insert(%s): put: %w", tableName, err)
	}

	utilities.LogProgress(
		"dynamodb",
		"Insert",
		fmt.Sprintf("table=%s keys=%d",
			tableName,
			len(av),
		),
	)

	return true, nil
}

// DeleteById removes a single item from a DynamoDB table by its primary key.
// Only the exact key fields are needed; all other attributes are irrelevant.
//
// DynamoDB DeleteItem is idempotent — deleting a non-existent key succeeds
// silently and returns true.
func DeleteById(ctx context.Context, tableName string, key map[string]interface{}) (bool, error) {
	if len(key) == 0 {
		return false, fmt.Errorf("dynamodb DeleteById(%s): empty key", tableName)
	}

	db := ensureDynamoClient()

	keyAV, err := attributevalue.MarshalMap(key)
	if err != nil {
		return false, fmt.Errorf("dynamodb DeleteById(%s): marshal key: %w", tableName, err)
	}

	_, err = db.DeleteItem(ctx, &aws_dynamodb.DeleteItemInput{
		TableName: aws_v2.String(tableName),
		Key:       keyAV,
	})
	if err != nil {
		return false, fmt.Errorf("dynamodb DeleteById(%s): delete: %w", tableName, err)
	}

	utilities.LogProgress(
		"dynamodb",
		"DeleteById",
		fmt.Sprintf("table=%s keys=%d", tableName, len(keyAV)),
	)

	return true, nil
}

// Update applies a partial update to a single DynamoDB item identified by
// its primary key. Only the fields present in the update map are modified;
// other attributes remain unchanged.
//
// The update map values follow the same type rules as [Insert]: Go scalar
// types, slices, nested maps, and time.Time are all supported.
func Update(ctx context.Context, tableName string, key map[string]interface{}, update map[string]interface{}) (bool, error) {
	if len(update) == 0 {
		return false, fmt.Errorf("dynamodb Update(%s): empty update map", tableName)
	}

	db := ensureDynamoClient()

	keyAV, err := attributevalue.MarshalMap(key)
	if err != nil {
		return false, fmt.Errorf("dynamodb Update(%s): marshal key: %w", tableName, err)
	}

	// Build the SET expression and the corresponding ExpressionAttributeNames
	// and ExpressionAttributeValues maps.
	setClauses := make([]string, 0, len(update))
	exprNames := make(map[string]string, len(update))
	exprValues := make(map[string]types.AttributeValue, len(update))

	for field, val := range update {
		placeholder := fmt.Sprintf("#%s", field)
		valuePlaceholder := fmt.Sprintf(":%s", field)

		setClauses = append(setClauses, fmt.Sprintf("%s = %s", placeholder, valuePlaceholder))
		exprNames[placeholder] = field

		av, err := attributevalue.Marshal(val)
		if err != nil {
			return false, fmt.Errorf("dynamodb Update(%s): marshal field %s: %w", tableName, field, err)
		}
		exprValues[valuePlaceholder] = av
	}

	updateExpr := "SET " + strings.Join(setClauses, ", ")

	_, err = db.UpdateItem(ctx, &aws_dynamodb.UpdateItemInput{
		TableName:                 aws_v2.String(tableName),
		Key:                       keyAV,
		UpdateExpression:          aws_v2.String(updateExpr),
		ExpressionAttributeNames:  exprNames,
		ExpressionAttributeValues: exprValues,
	})
	if err != nil {
		return false, fmt.Errorf("dynamodb Update(%s): update: %w", tableName, err)
	}

	utilities.LogProgress(
		"dynamodb",
		"Update",
		fmt.Sprintf("table=%s fields=%d", tableName, len(update)),
	)

	return true, nil
}

// GetById retrieves a single item from a DynamoDB table by its primary key.
// The returned map uses native Go types (string, float64, bool, []interface{},
// map[string]interface{}) converted from DynamoDB AttributeValues.
//
// Returns nil, nil when the item does not exist.
func GetById(ctx context.Context, tableName string, key map[string]interface{}) (map[string]interface{}, error) {
	var item map[string]interface{}
	if len(key) == 0 {
		return nil, fmt.Errorf("dynamodb GetById(%s): empty key", tableName)
	}

	db := ensureDynamoClient()

	keyAV, err := attributevalue.MarshalMap(key)
	if err != nil {
		return nil, fmt.Errorf("dynamodb GetById(%s): marshal key: %w", tableName, err)
	}

	resp, err := db.GetItem(ctx, &aws_dynamodb.GetItemInput{
		TableName: aws_v2.String(tableName),
		Key:       keyAV,
	})
	if err != nil {
		return nil, fmt.Errorf("dynamodb GetById(%s): get: %w", tableName, err)
	}

	if len(resp.Item) == 0 {
		utilities.LogProgress("dynamodb", "GetById",
			fmt.Sprintf("table=%s not found", tableName))
		return nil, nil
	}

	if err := attributevalue.UnmarshalMap(resp.Item, &item); err != nil {
		return nil, fmt.Errorf("dynamodb GetById(%s): unmarshal: %w", tableName, err)
	}

	utilities.LogProgress(
		"dynamodb",
		"GetById",
		fmt.Sprintf("table=%s fields=%d",
			tableName,
			len(item),
		),
	)

	return item, nil
}
