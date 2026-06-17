package model

import (
	"crypto/rsa"
	"errors"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// JWT represents a JSON Web Token with security-oriented fields following
// RFC 7519. It includes standard registered claims plus token-binding fields
// (IP address and User-Agent) to mitigate bearer-token theft.
type JWT struct {
	JWTID        string   `json:"jti"`
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	ExpiresIn    int      `json:"expires_in"`
	TokenType    string   `json:"token_type"`
	Scopes       []string `json:"scopes"`

	Issuer    string `json:"issuer,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Audience  string `json:"audience,omitempty"`
	IssuedAt  int64  `json:"issued_at,omitempty"`
	NotBefore int64  `json:"not_before,omitempty"`
	CreatedAt int64  `json:"created_at"`

	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// IsExpired reports whether the token has passed its expiry window.
//
// Returns:
//   - bool: true if CreatedAt is unset, ExpiresIn is non-positive, or the
//     current Unix time exceeds CreatedAt + ExpiresIn.
func (j JWT) IsExpired() bool {
	if j.CreatedAt == 0 || j.ExpiresIn <= 0 {
		return true
	}
	return time.Now().Unix() > j.CreatedAt+int64(j.ExpiresIn)
}

// IsNotBeforeValid reports whether the token's NotBefore constraint has been
// satisfied relative to the current wall-clock time.
//
// Returns:
//   - bool: true if NotBefore is unset or in the past.
func (j JWT) IsNotBeforeValid() bool {
	if j.NotBefore == 0 {
		return true
	}
	return time.Now().Unix() >= j.NotBefore
}

// Validate performs basic structural validation: access token presence,
// expiry, and NotBefore.
//
// Returns:
//   - error: nil if the token is structurally valid; otherwise a descriptive
//     error.
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

// WithIPBinding returns a shallow copy of the JWT with the IPAddress field set.
//
// Parameters:
//   - ip: the client IP address to bind.
//
// Returns:
//   - JWT: a copy with IPAddress populated.
func (j JWT) WithIPBinding(ip string) JWT {
	j.IPAddress = ip
	return j
}

// WithUserAgentBinding returns a shallow copy of the JWT with the UserAgent
// field set.
//
// Parameters:
//   - ua: the client User-Agent header to bind.
//
// Returns:
//   - JWT: a copy with UserAgent populated.
func (j JWT) WithUserAgentBinding(ua string) JWT {
	j.UserAgent = ua
	return j
}

// NewAccessToken creates a short-lived (3600s) access token bound to the
// given subject, IP, and User-Agent. The JWTID is a random UUID v4.
//
// Parameters:
//   - subject: the principal identifier (username).
//   - ip: the client IP address for theft detection.
//   - ua: the client User-Agent for theft detection.
//
// Returns:
//   - JWT: a populated access token ready for signing.
func NewAccessToken(subject string, ip, ua string) JWT {
	now := time.Now().Unix()
	return JWT{
		JWTID:     uuid.NewString(),
		ExpiresIn: 3600,
		TokenType: "Bearer",
		Scopes:    []string{"api:access"},
		Issuer:    "authgate",
		Subject:   subject,
		IssuedAt:  now,
		NotBefore: now,
		CreatedAt: now,
		IPAddress: ip,
		UserAgent: ua,
	}
}

// NewRefreshToken creates a long-lived (604800s ≈ 7 days) refresh token bound
// to the given subject, IP, and User-Agent.
//
// Parameters:
//   - subject: the principal identifier (username).
//   - ip: the client IP address for theft detection.
//   - ua: the client User-Agent for theft detection.
//
// Returns:
//   - JWT: a populated refresh token ready for signing.
func NewRefreshToken(subject string, ip, ua string) JWT {
	now := time.Now().Unix()
	return JWT{
		JWTID:        uuid.NewString(),
		ExpiresIn:    604800,
		TokenType:    "Bearer",
		Scopes:       []string{"token:refresh"},
		Issuer:       "authgate",
		Subject:      subject,
		IssuedAt:     now,
		NotBefore:    now,
		CreatedAt:    now,
		IPAddress:    ip,
		UserAgent:    ua,
	}
}

// Sign serialises the JWT claims into a signed compact JWS string using the
// RS256 algorithm and the supplied RSA private key.
//
// Parameters:
//   - privateKey: the RSA private key used for signing.
//
// Returns:
//   - string: the compact JWS token.
//   - error: nil on success; otherwise a signing error.
func (j JWT) Sign(privateKey *rsa.PrivateKey) (string, error) {
	claims := jwtlib.MapClaims{
		"jti":        j.JWTID,
		"sub":        j.Subject,
		"iss":        j.Issuer,
		"iat":        j.IssuedAt,
		"nbf":        j.NotBefore,
		"exp":        j.CreatedAt + int64(j.ExpiresIn),
		"created_at": j.CreatedAt,
		"token_type": j.TokenType,
		"scopes":     j.Scopes,
		"ip_address": j.IPAddress,
		"user_agent": j.UserAgent,
	}
	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
