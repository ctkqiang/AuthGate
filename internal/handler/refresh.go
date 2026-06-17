package handler

import (
	"authgate/internal/model"
	"authgate/internal/utilities"
	"errors"
	"fmt"
	"strings"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// Refresh validates a refresh token against the RS256 public key, checks that
// it carries the "token:refresh" scope, verifies it has not been revoked via
// the token blacklist, and issues a new access and refresh token pair.
//
// Parameters:
//   - refreshTokenStr: the compact JWS refresh token string.
//   - ip: the client IP address for the new token binding.
//   - ua: the client User-Agent for the new token binding.
//
// Returns:
//   - model.JwtResponse: the newly issued token pair.
//   - error: nil on success; "token has been revoked", "invalid or expired
//     refresh token", or scope/key errors otherwise.
func Refresh(refreshTokenStr, ip, ua string) (model.JwtResponse, error) {
	if refreshTokenStr == "" {
		return model.JwtResponse{}, errors.New("refresh token is required")
	}

	if IsTokenRevoked(refreshTokenStr) {
		return model.JwtResponse{}, errors.New("token has been revoked")
	}

	if model.PublicKey == nil {
		return model.JwtResponse{}, errors.New("verification key not loaded")
	}

	token, err := jwtlib.Parse(refreshTokenStr, func(t *jwtlib.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtlib.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return model.PublicKey, nil
	})
	if err != nil || !token.Valid {
		return model.JwtResponse{}, errors.New("invalid or expired refresh token")
	}

	claims, ok := token.Claims.(jwtlib.MapClaims)
	if !ok {
		return model.JwtResponse{}, errors.New("invalid token claims")
	}

	scopes, _ := claims["scopes"].([]interface{})
	hasRefreshScope := false
	for _, s := range scopes {
		if scope, ok := s.(string); ok && scope == "token:refresh" {
			hasRefreshScope = true
			break
		}
	}
	if !hasRefreshScope {
		return model.JwtResponse{}, errors.New("token does not have refresh scope")
	}

	subject, _ := claims["sub"].(string)
	if subject == "" {
		return model.JwtResponse{}, errors.New("token missing subject")
	}

	if model.PrivateKey == nil {
		return model.JwtResponse{}, errors.New("signing key not loaded")
	}

	accessJWT := model.NewAccessToken(subject, ip, ua)
	accessTokenStr, err := accessJWT.Sign(model.PrivateKey)
	if err != nil {
		return model.JwtResponse{}, fmt.Errorf("failed to sign access token: %w", err)
	}

	newRefreshJWT := model.NewRefreshToken(subject, ip, ua)
	newRefreshTokenStr, err := newRefreshJWT.Sign(model.PrivateKey)
	if err != nil {
		return model.JwtResponse{}, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	utilities.LogProgress("handler", "Refresh", fmt.Sprintf("user=%s", subject))

	return model.JwtResponse{
		AccessToken:  accessTokenStr,
		RefreshToken: newRefreshTokenStr,
		ExpiresIn:    accessJWT.ExpiresIn,
		EventType:    model.EventTypeAuthRefresh,
		Actor: &model.Actor{
			Idenitifier: subject,
			IpAddress:   ip,
			UserAgent:   ua,
		},
	}, nil
}

// ValidateAccessToken parses and validates an RS256-signed access token
// against the configured public key. It checks the token has not been revoked
// (blacklist) and returns the embedded subject claim.
//
// Parameters:
//   - accessTokenStr: the compact JWS token string, optionally with "Bearer "
//     prefix.
//
// Returns:
//   - string: the subject claim (username) from the token.
//   - error: nil on success; "token has been revoked", "invalid or expired
//     access token", or key errors otherwise.
func ValidateAccessToken(accessTokenStr string) (string, error) {
	if accessTokenStr == "" {
		return "", errors.New("access token is required")
	}

	tokenStr := accessTokenStr
	if strings.HasPrefix(tokenStr, "Bearer ") {
		tokenStr = tokenStr[7:]
	}

	if IsTokenRevoked(tokenStr) {
		return "", errors.New("token has been revoked")
	}

	if model.PublicKey == nil {
		return "", errors.New("verification key not loaded")
	}

	token, err := jwtlib.Parse(tokenStr, func(t *jwtlib.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtlib.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return model.PublicKey, nil
	})
	if err != nil || !token.Valid {
		return "", errors.New("invalid or expired access token")
	}

	claims, ok := token.Claims.(jwtlib.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	subject, _ := claims["sub"].(string)
	if subject == "" {
		return "", errors.New("token missing subject")
	}

	return subject, nil
}
