package handler

import (
	"context"
	"sync"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// BlacklistFunc is injected by main.go. It stores a revoked token JTI
// with its expiry so the blacklist entry can be cleaned up after expiry.
var BlacklistFunc func(ctx context.Context, jti string, expiresAt time.Time) error

// IsBlacklistedFunc is injected by main.go. It checks whether a JTI
// has been revoked.
var IsBlacklistedFunc func(ctx context.Context, jti string) (bool, error)

// in-memory fallback when no DB backend is configured.
var (
	inMemBlacklist   = make(map[string]time.Time)
	inMemBlacklistMu sync.RWMutex
)

func init() {
	BlacklistFunc = func(_ context.Context, jti string, expiresAt time.Time) error {
		inMemBlacklistMu.Lock()
		inMemBlacklist[jti] = expiresAt
		inMemBlacklistMu.Unlock()
		return nil
	}
	IsBlacklistedFunc = func(_ context.Context, jti string) (bool, error) {
		inMemBlacklistMu.RLock()
		exp, ok := inMemBlacklist[jti]
		inMemBlacklistMu.RUnlock()
		if !ok {
			return false, nil
		}
		if time.Now().After(exp) {
			inMemBlacklistMu.Lock()
			delete(inMemBlacklist, jti)
			inMemBlacklistMu.Unlock()
			return false, nil
		}
		return true, nil
	}
}

// RevokeToken parses a token string to extract its JTI and expiry,
// then stores it in the blacklist.
func RevokeToken(tokenStr string) error {
	parser := jwtlib.Parser{}
	token, _, err := parser.ParseUnverified(tokenStr, jwtlib.MapClaims{})
	if err != nil {
		return err
	}
	claims, ok := token.Claims.(jwtlib.MapClaims)
	if !ok {
		return nil
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil
	}
	expF, _ := claims["exp"].(float64)
	exp := time.Unix(int64(expF), 0)
	return BlacklistFunc(context.Background(), jti, exp)
}

// IsTokenRevoked checks if a token string's JTI is in the blacklist.
func IsTokenRevoked(tokenStr string) bool {
	parser := jwtlib.Parser{}
	token, _, err := parser.ParseUnverified(tokenStr, jwtlib.MapClaims{})
	if err != nil {
		return false
	}
	claims, ok := token.Claims.(jwtlib.MapClaims)
	if !ok {
		return false
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return false
	}
	revoked, err := IsBlacklistedFunc(context.Background(), jti)
	if err != nil {
		return false
	}
	return revoked
}
