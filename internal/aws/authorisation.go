// Package aws (authorisation.go) provides the STS-verified authentication
// singleton. Initialize() must be called once at startup; GetAccount()
// returns the cached config for all downstream clients.
package aws

import (
	"authgate/internal/security"
	"authgate/internal/utilities"
	"context"
	"fmt"
	"sync"
	"time"

	aws_v2 "github.com/aws/aws-sdk-go-v2/aws"
	aws_config "github.com/aws/aws-sdk-go-v2/config"
	aws_credentials "github.com/aws/aws-sdk-go-v2/credentials"
	aws_sts "github.com/aws/aws-sdk-go-v2/service/sts"
)

type Account struct {
	cfg      aws_v2.Config  // reusable AWS SDK config for all service clients
	identity CallerIdentity // verified caller identity from STS
	ready    bool           // true after successful Init()
	mu       sync.RWMutex   // protects all fields
	initErr  error          // captured error from the Init process
}

type CallerIdentity struct {
	AccountID  string    // 12-digit AWS account ID
	ARN        string    // IAM role or user ARN, e.g. arn:aws:sts::123456789012:assumed-role/admin
	UserID     string    // unique user/role ID, e.g. AROA...
	Verified   bool      // true if STS returned a valid identity
	VerifiedAt time.Time // timestamp of last successful STS verification
}

var (
	globalAccount *Account
	globalMu      sync.Mutex
)

func Initialize(ctx context.Context) error {
	var options []func(*aws_config.LoadOptions) error

	globalMu.Lock()
	defer globalMu.Unlock()

	account := &Account{}

	authKeys, err := security.AWSCredentials()
	if err != nil {
		return err
	}

	options = append(options,
		aws_config.WithRegion(authKeys.Region),
		aws_config.WithCredentialsProvider(
			aws_credentials.NewStaticCredentialsProvider(
				authKeys.AccessKeyID,
				authKeys.SecretAccessKey,
				"", // session token not required for permanent IAM credentials
			),
		),
	)

	awsConfiguration, err := aws_config.LoadDefaultConfig(ctx, options...)
	if err != nil {
		account.initErr = fmt.Errorf("failed to load AWS configuration: %w", err)
		globalAccount = account
		return account.initErr
	}

	account.cfg = awsConfiguration

	stsClient := aws_sts.NewFromConfig(awsConfiguration)
	identity, err := stsClient.GetCallerIdentity(ctx, &aws_sts.GetCallerIdentityInput{})
	if err != nil {
		account.initErr = fmt.Errorf("failed to get caller identity: %w", err)
		globalAccount = account
		return account.initErr
	}

	account.identity = CallerIdentity{
		AccountID:  aws_v2.ToString(identity.Account),
		ARN:        aws_v2.ToString(identity.Arn),
		UserID:     aws_v2.ToString(identity.UserId),
		Verified:   true,
		VerifiedAt: time.Now(),
	}

	utilities.LogProgress("aws", "init", "success",
		fmt.Sprintf("AWS account initialized successfully | account_id=%s user_id=%s arn=%s verified_at=%s",
			account.identity.AccountID,
			account.identity.UserID,
			account.identity.ARN,
			account.identity.VerifiedAt.Format(time.RFC3339),
		),
	)

	account.ready = true
	globalAccount = account

	return nil
}

// GetAccount returns the process-wide authenticated Account singleton.
// Panics if Initialize() has not been called successfully.
func GetAccount() *Account {
	globalMu.Lock()
	acct := globalAccount
	globalMu.Unlock()

	if acct == nil {
		panic("aws: Initialize() must be called before GetAccount()")
	}
	return acct
}

// Ready reports whether Initialize() has completed successfully and the
// Account singleton is safe to use. Callers that must avoid panics should
// guard GetAccount() with Ready().
func Ready() bool {
	globalMu.Lock()
	defer globalMu.Unlock()
	return globalAccount != nil && globalAccount.ready
}

// Config returns the shared AWS SDK configuration from the Account.
func (a *Account) Config() aws_v2.Config {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

// AWSAuthorisation is reserved for future OAuth2 / Cognito authorisation
// middleware.  Currently a no-op — all endpoints are unauthenticated and
// rely on IAM role permissions at the SDK level.
func AWSAuthorisation() {}
