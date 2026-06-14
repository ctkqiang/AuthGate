// Package aliyun (authorisation.go) provides the STS-verified authentication
// singleton. Initialize() must be called once at startup; GetAccount()
// returns the cached config for all downstream clients.
package aliyun

import (
	"authgate/internal/security"
	"authgate/internal/utilities"
	"fmt"
	"sync"
	"time"

	aliyun_sts "github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
)

// Account holds the authenticated Alibaba Cloud SDK configuration and
// verified caller identity. Create one via [Initialize] and retrieve it
// with [GetAccount].
type Account struct {
	region    string
	keyID     string
	keySecret string
	endpoint  string
	identity  CallerIdentity // verified caller identity from STS
	ready     bool           // true after successful Init()
	mu        sync.RWMutex   // protects all fields
	initErr   error          // captured error from the Init process
}

// CallerIdentity holds the verified caller information returned by the
// Alibaba Cloud STS GetCallerIdentity API.
type CallerIdentity struct {
	AccountID  string    // 12-digit Alibaba Cloud account ID
	ARN        string    // RAM role or user ARN, e.g. acs:ram::123456789012:user/admin
	UserID     string    // unique user/role ID
	Verified   bool      // true if STS returned a valid identity
	VerifiedAt time.Time // timestamp of last successful STS verification
}

var (
	globalAccount *Account
	globalMu      sync.Mutex
)

// Initialize validates the Alibaba Cloud credentials from config.toml,
// verifies them via STS GetCallerIdentity, and caches the result in a
// process-wide singleton. Must be called once at startup before any
// downstream client (OSS, FC, etc.) uses GetAccount().
func Initialize() error {
	globalMu.Lock()
	defer globalMu.Unlock()

	account := &Account{}

	authKeys, err := security.AliyunCredentials()
	if err != nil {
		return err
	}

	account.region = authKeys.Region
	account.keyID = authKeys.AccessKeyID
	account.keySecret = authKeys.SecretAccessKey
	account.endpoint = authKeys.Endpoint

	// Verify credentials by calling STS GetCallerIdentity.
	stsClient, err := aliyun_sts.NewClientWithAccessKey(
		account.region,
		account.keyID,
		account.keySecret,
	)
	if err != nil {
		account.initErr = fmt.Errorf("failed to create STS client: %w", err)
		globalAccount = account
		return account.initErr
	}

	request := aliyun_sts.CreateGetCallerIdentityRequest()
	request.Scheme = "https"

	response, err := stsClient.GetCallerIdentity(request)
	if err != nil {
		account.initErr = fmt.Errorf("failed to get caller identity: %w", err)
		globalAccount = account
		return account.initErr
	}

	account.identity = CallerIdentity{
		AccountID:  response.AccountId,
		ARN:        response.Arn,
		UserID:     response.UserId,
		Verified:   true,
		VerifiedAt: time.Now(),
	}

	utilities.LogProgress("aliyun", "init", "success",
		fmt.Sprintf("Alibaba Cloud account initialized successfully | account_id=%s user_id=%s arn=%s verified_at=%s",
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
		panic("aliyun: Initialize() must be called before GetAccount()")
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

// Region returns the Alibaba Cloud region configured for this account.
func (a *Account) Region() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.region
}

// AccessKeyID returns the AccessKey ID used for authentication.
func (a *Account) AccessKeyID() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.keyID
}

// AccessKeySecret returns the AccessKey secret used for authentication.
func (a *Account) AccessKeySecret() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.keySecret
}

// Endpoint returns the OSS endpoint configured for this account.
func (a *Account) Endpoint() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.endpoint
}

// Identity returns the verified caller identity. Panics if the account
// has not been successfully initialized.
func (a *Account) Identity() CallerIdentity {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if !a.ready {
		panic("aliyun: Account not initialized")
	}
	return a.identity
}

// AliyunAuthorisation is reserved for future RAM / STS authorisation
// middleware. Currently a no-op — all endpoints are unauthenticated and
// rely on AccessKey permissions at the SDK level.
func AliyunAuthorisation() {}
