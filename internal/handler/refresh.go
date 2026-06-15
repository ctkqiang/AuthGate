package handler

import (
	"authgate/internal/model"
	"authgate/internal/utilities"
	"errors"
	"fmt"
	"strings"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// Refresh validates the refresh token, checks its scope and expiry, then
// issues a new access token bound to the client IP and User-Agent.
func Refresh(refreshTokenStr, ip, ua string) (model.JwtResponse, error) {
	if refreshTokenStr == "" {
		return model.JwtResponse{}, errors.New("refresh token is required")
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

	utilities.LogProgress("handler", "Refresh",
		fmt.Sprintf("user=%s", subject))

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

// ValidateAccessToken parses and validates an access token, returning its
// subject on success. Used by middleware and protected endpoints.
func ValidateAccessToken(accessTokenStr string) (string, error) {
	if accessTokenStr == "" {
		return "", errors.New("access token is required")
	}

	tokenStr := accessTokenStr
	if strings.HasPrefix(tokenStr, "Bearer ") {
		tokenStr = tokenStr[7:]
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
