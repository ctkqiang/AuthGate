package model

import (
	"errors"
	"time"
)

// JWT represents a JSON Web Token with security-oriented fields.
// It follows RFC 7519 and includes standard registered claims plus
// binding fields (IP, UserAgent) to mitigate token theft.
type JWT struct {
	// JWTID (jti) provides a unique identifier for the token,
	// used to prevent replay attacks.
	JWTID string `json:"jti"`

	// AccessToken is the primary bearer token for API authentication.
	AccessToken string `json:"access_token"`

	// RefreshToken allows obtaining a new access token without
	// re-authentication.
	RefreshToken string `json:"refresh_token"`

	// ExpiresIn indicates the lifetime of the access token in seconds.
	ExpiresIn int `json:"expires_in"`

	// TokenType is typically "Bearer".
	TokenType string `json:"token_type"`

	// Scopes defines the permissions granted by this token.
	Scopes []string `json:"scopes"`

	// --- RFC 7519 registered claims ---

	// Issuer (iss) identifies the principal that issued the JWT.
	Issuer string `json:"issuer,omitempty"`

	// Subject (sub) identifies the principal that is the subject of the JWT.
	Subject string `json:"subject,omitempty"`

	// Audience (aud) identifies the recipients the JWT is intended for.
	Audience string `json:"audience,omitempty"`

	// IssuedAt (iat) identifies the time at which the JWT was issued.
	IssuedAt int64 `json:"issued_at,omitempty"`

	// NotBefore (nbf) identifies the time before which the JWT MUST NOT
	// be accepted for processing.
	NotBefore int64 `json:"not_before,omitempty"`

	// CreatedAt stores the token creation timestamp (application-level).
	CreatedAt int64 `json:"created_at"`

	// --- Token binding (bearer token theft mitigation) ---

	// IPAddress binds the token to the client's IP at issuance time.
	IPAddress string `json:"ip_address,omitempty"`

	// UserAgent binds the token to the client's user-agent at issuance time.
	UserAgent string `json:"user_agent,omitempty"`
}

// IsExpired checks whether the token has expired based on ExpiresIn.
func (j JWT) IsExpired() bool {
	if j.CreatedAt == 0 || j.ExpiresIn <= 0 {
		return true
	}
	return time.Now().Unix() > j.CreatedAt+int64(j.ExpiresIn)
}

// IsNotBeforeValid checks whether the token's NotBefore constraint
// has been satisfied.
func (j JWT) IsNotBeforeValid() bool {
	if j.NotBefore == 0 {
		return true
	}
	return time.Now().Unix() >= j.NotBefore
}

// Validate performs a basic structural validation of the JWT.
// It checks for required fields and temporal constraints.
func (j JWT) Validate() error {
	if j.AccessToken == "" {
		return errors.New("access token is required")
	}
	if j.IsExpired() {
		return errors.New("token has expired")
	}
	if !j.IsNotBeforeValid() {
		return errors.New("token is not yet valid (nbf)")
	}
	return nil
}

// WithIPBinding returns a copy of the JWT with the IP address bound.
// This enables token theft detection at the middleware level.
func (j JWT) WithIPBinding(ip string) JWT {
	j.IPAddress = ip
	return j
}

// WithUserAgentBinding returns a copy of the JWT with the User-Agent bound.
func (j JWT) WithUserAgentBinding(ua string) JWT {
	j.UserAgent = ua
	return j
}
