// Package persistence provides the user-persistence layer that bridges
// the handler package to cloud database backends (DynamoDB / TableStore)
// without creating import cycles.
//
// The entry point [PersistUser] is wired into the handler via
// handler.PersistUserFunc in main.go.
package persistence

import (
	"authgate/internal/aliyun"
	"authgate/internal/aws"
	"authgate/internal/model"
	"authgate/internal/security"
	"authgate/internal/utilities"
	"context"
	"fmt"
	"time"
)

// LookupUser detects the active database backend and retrieves a user
// record by username. Returns nil if the user does not exist or no
// backend is configured.
func LookupUser(ctx context.Context, username string) (map[string]interface{}, error) {
	awsCfg, _ := security.AWSCredentials()
	aliCfg, _ := security.AliyunCredentials()

	key := map[string]interface{}{"username": username}

	switch {
	case awsCfg.AccessKeyID != "" && awsCfg.Region != "" && awsCfg.DynamoDBTable != "" && aws.Ready():
		utilities.LogProgress("persistence", "LookupUser",
			fmt.Sprintf("provider=aws table=%s username=%s", awsCfg.DynamoDBTable, username))
		return aws.GetById(ctx, awsCfg.DynamoDBTable, key)

	case aliCfg.AccessKeyID != "" && aliCfg.Region != "" && aliCfg.TableStoreTable != "" && aliyun.Ready():
		utilities.LogProgress("persistence", "LookupUser",
			fmt.Sprintf("provider=aliyun table=%s username=%s", aliCfg.TableStoreTable, username))
		return aliyun.GetById(ctx, aliCfg.TableStoreTable, key)

	default:
		utilities.LogProgress("persistence", "LookupUser",
			"no database backend configured")
		return nil, nil
	}
}

// PersistUser detects the active database backend (AWS DynamoDB or
// Alibaba Cloud TableStore) and inserts the user record. If no backend
// is configured the function succeeds silently.
//
// AWS has priority when both providers are configured.
func PersistUser(ctx context.Context, user model.User, jwtResp model.JwtResponse) error {
	awsCfg, _ := security.AWSCredentials()
	aliCfg, _ := security.AliyunCredentials()

	item := map[string]interface{}{
		"username":      user.Username,
		"email":         user.Email,
		"password":      user.Password,
		"access_token":  jwtResp.AccessToken,
		"refresh_token": jwtResp.RefreshToken,
		"created_at":    time.Now().UTC().Format(time.RFC3339),
	}

	switch {
	case awsCfg.AccessKeyID != "" && awsCfg.Region != "" && awsCfg.DynamoDBTable != "" && aws.Ready():
		utilities.LogProgress("persistence", "PersistUser",
			fmt.Sprintf("provider=aws table=%s", awsCfg.DynamoDBTable))
		_, err := aws.Insert(ctx, awsCfg.DynamoDBTable, item)
		return err

	case aliCfg.AccessKeyID != "" && aliCfg.Region != "" && aliCfg.TableStoreTable != "" && aliyun.Ready():
		utilities.LogProgress("persistence", "PersistUser",
			fmt.Sprintf("provider=aliyun table=%s", aliCfg.TableStoreTable))
		_, err := aliyun.Insert(ctx, aliCfg.TableStoreTable, item)
		return err

	default:
		utilities.LogProgress("persistence", "PersistUser",
			"no database backend configured — user not persisted")
		return nil
	}
}
