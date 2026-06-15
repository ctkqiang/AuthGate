// Package aliyun (tablestore.go) provides Alibaba Cloud TableStore
// database operations, mirroring the DynamoDB interface in aws/dynamodb.go.
//
// All functions require a prior call to [Initialize] so that the
// Account singleton holds valid Alibaba Cloud credentials. The TableStore
// client is constructed lazily on first use via ensureTableStoreClient()
// and shared across all subsequent calls.
//
// The TableStore endpoint is constructed automatically from the instance
// name and region configured in config.toml:
//
//	https://{tablestore_instance}.{region}.ots.aliyuncs.com
//
// Operations supported:
//   - Insert     — put a single row into a table
//   - GetById    — retrieve a row by its primary key
//   - DeleteById — remove a row by its primary key
//   - Update     — apply a partial update to an existing row
package aliyun

import (
	"authgate/internal/utilities"
	"context"
	"fmt"

	tablestore "github.com/aliyun/aliyun-tablestore-go-sdk/tablestore"
)

// tableStoreClient is a lazy-initialised singleton TableStore client
// derived from the global Account config. It is safe for concurrent
// use once built.
var tableStoreClient *tablestore.TableStoreClient

// ensureTableStoreClient builds the TableStore client exactly once.
// The endpoint is constructed as https://{instance}.{region}.ots.aliyuncs.com.
func ensureTableStoreClient() *tablestore.TableStoreClient {
	if tableStoreClient != nil {
		return tableStoreClient
	}
	acct := GetAccount()
	endpoint := fmt.Sprintf("https://%s.%s.ots.aliyuncs.com",
		acct.TableStoreInstance(), acct.Region())
	tableStoreClient = tablestore.NewClient(
		endpoint,
		acct.TableStoreInstance(),
		acct.AccessKeyID(),
		acct.AccessKeySecret(),
	)
	return tableStoreClient
}

// buildPrimaryKey extracts the "username" field from item to construct
// a TableStore primary key. Returns an error if username is missing or
// empty.
func buildPrimaryKey(item map[string]interface{}) (*tablestore.PrimaryKey, error) {
	raw, ok := item["username"]
	if !ok || raw == nil {
		return nil, fmt.Errorf("tablestore: primary key \"username\" is required")
	}
	username, ok := raw.(string)
	if !ok || username == "" {
		return nil, fmt.Errorf("tablestore: primary key \"username\" must be a non-empty string")
	}
	pk := new(tablestore.PrimaryKey)
	pk.AddPrimaryKeyColumn("username", username)
	return pk, nil
}

// Insert writes a complete row into the TableStore table. The supplied
// item map MUST contain a "username" key (string), which serves as the
// partition key. All other key-value pairs become attribute columns.
//
// This is an upsert — if a row with the same primary key already exists,
// it is replaced entirely.
func Insert(ctx context.Context, tableName string, item map[string]interface{}) (bool, error) {
	if tableName == "" {
		return false, fmt.Errorf("tablestore Insert: table name is required")
	}

	pk, err := buildPrimaryKey(item)
	if err != nil {
		return false, fmt.Errorf("tablestore Insert(%s): %w", tableName, err)
	}

	client := ensureTableStoreClient()

	putRowReq := new(tablestore.PutRowRequest)
	putRowChange := new(tablestore.PutRowChange)
	putRowChange.TableName = tableName
	putRowChange.PrimaryKey = pk

	for key, val := range item {
		if key == "username" {
			continue // already in primary key
		}
		putRowChange.AddColumn(key, val)
	}

	putRowReq.PutRowChange = putRowChange
	_, err = client.PutRow(putRowReq)
	if err != nil {
		return false, fmt.Errorf("tablestore Insert(%s): put: %w", tableName, err)
	}

	utilities.LogProgress("tablestore", "Insert",
		fmt.Sprintf("table=%s columns=%d", tableName, len(item)))
	return true, nil
}

// GetById retrieves a single row from TableStore by its primary key
// (username). The returned map uses native Go types (string, int64,
// float64, bool, []byte) converted from TableStore column values.
//
// Returns nil, nil when the row does not exist.
func GetById(ctx context.Context, tableName string, key map[string]interface{}) (map[string]interface{}, error) {
	if tableName == "" {
		return nil, fmt.Errorf("tablestore GetById: table name is required")
	}

	pk, err := buildPrimaryKey(key)
	if err != nil {
		return nil, fmt.Errorf("tablestore GetById(%s): %w", tableName, err)
	}

	client := ensureTableStoreClient()

	getRowReq := new(tablestore.GetRowRequest)
	criteria := new(tablestore.SingleRowQueryCriteria)
	criteria.PrimaryKey = pk
	criteria.TableName = tableName
	getRowReq.SingleRowQueryCriteria = criteria

	resp, err := client.GetRow(getRowReq)
	if err != nil {
		return nil, fmt.Errorf("tablestore GetById(%s): get: %w", tableName, err)
	}

	if len(resp.Columns) == 0 {
		utilities.LogProgress("tablestore", "GetById",
			fmt.Sprintf("table=%s not found", tableName))
		return nil, nil
	}

	item := make(map[string]interface{}, len(resp.Columns)+1)
	for _, col := range resp.Columns {
		item[col.ColumnName] = col.Value
	}
	// Include the primary key value (username) in the result.
	for _, pkCol := range pk.PrimaryKeys {
		if _, exists := item[pkCol.ColumnName]; !exists {
			item[pkCol.ColumnName] = pkCol.Value
		}
	}

	utilities.LogProgress("tablestore", "GetById",
		fmt.Sprintf("table=%s fields=%d", tableName, len(item)))
	return item, nil
}

// DeleteById removes a single row from TableStore by its primary key
// (username). Deleting a non-existent row succeeds silently and returns
// true (idempotent behaviour matching DynamoDB's DeleteItem).
func DeleteById(ctx context.Context, tableName string, key map[string]interface{}) (bool, error) {
	if tableName == "" {
		return false, fmt.Errorf("tablestore DeleteById: table name is required")
	}

	pk, err := buildPrimaryKey(key)
	if err != nil {
		return false, fmt.Errorf("tablestore DeleteById(%s): %w", tableName, err)
	}

	client := ensureTableStoreClient()

	deleteRowReq := new(tablestore.DeleteRowRequest)
	deleteRowChange := new(tablestore.DeleteRowChange)
	deleteRowChange.TableName = tableName
	deleteRowChange.PrimaryKey = pk
	deleteRowReq.DeleteRowChange = deleteRowChange

	_, err = client.DeleteRow(deleteRowReq)
	if err != nil {
		return false, fmt.Errorf("tablestore DeleteById(%s): delete: %w", tableName, err)
	}

	utilities.LogProgress("tablestore", "DeleteById",
		fmt.Sprintf("table=%s", tableName))
	return true, nil
}

// Update applies a partial update to a single TableStore row identified
// by its primary key (username). Only the fields present in the update
// map are modified; other attributes remain unchanged.
//
// The update map values must be of types supported by TableStore: string,
// int64, float64, bool, []byte. Complex types (maps, slices) will be
// rejected by the SDK.
func Update(ctx context.Context, tableName string, key map[string]interface{}, update map[string]interface{}) (bool, error) {
	if tableName == "" {
		return false, fmt.Errorf("tablestore Update: table name is required")
	}
	if len(update) == 0 {
		return false, fmt.Errorf("tablestore Update(%s): empty update map", tableName)
	}

	pk, err := buildPrimaryKey(key)
	if err != nil {
		return false, fmt.Errorf("tablestore Update(%s): %w", tableName, err)
	}

	client := ensureTableStoreClient()

	updateRowReq := new(tablestore.UpdateRowRequest)
	updateRowChange := new(tablestore.UpdateRowChange)
	updateRowChange.TableName = tableName
	updateRowChange.PrimaryKey = pk

	for field, val := range update {
		updateRowChange.PutColumn(field, val)
	}

	updateRowReq.UpdateRowChange = updateRowChange
	_, err = client.UpdateRow(updateRowReq)
	if err != nil {
		return false, fmt.Errorf("tablestore Update(%s): update: %w", tableName, err)
	}

	utilities.LogProgress("tablestore", "Update",
		fmt.Sprintf("table=%s fields=%d", tableName, len(update)))
	return true, nil
}
