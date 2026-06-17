package handler

import (
	"authgate/internal/model"
	"authgate/internal/security"
	"authgate/internal/utilities"
	"context"
	"errors"
	"fmt"
)

// Login validates credentials against the stored user record by looking up
// the username via LookupUserFunc and comparing the supplied password against
// the stored bcrypt hash. On success it issues a signed RS256 access token
// (3600s TTL) and refresh token (604800s TTL) bound to the client IP and
// User-Agent.
//
// Parameters:
//   - req: the EmailPasswordAuthRequest decoded from the login request body.
//   - ip: the client IP address for token binding.
//   - ua: the client User-Agent header for token binding.
//
// Returns:
//   - model.JwtResponse: access token, refresh token, expiry, event type,
//     and actor metadata.
//   - error: nil on success; "invalid username or password" for bad
//     credentials, "internal error" for database failures, or key-loading
//     errors.
func Login(req model.EmailPasswordAuthRequest, ip, ua string) (model.JwtResponse, error) {
	if req.Username == "" {
		return model.JwtResponse{}, errors.New("username is required")
	}
	if req.Password == "" {
		return model.JwtResponse{}, errors.New("password is required")
	}

	if LookupUserFunc == nil {
		return model.JwtResponse{}, errors.New("no database backend configured")
	}

	record, err := LookupUserFunc(context.Background(), req.Username)
	if err != nil {
		utilities.Error("handler: lookup user failed: %v", err)
		return model.JwtResponse{}, errors.New("internal error")
	}
	if record == nil {
		return model.JwtResponse{}, errors.New("invalid username or password")
	}

	storedPassword, _ := record["password"].(string)
	if !security.CheckPassword(storedPassword, req.Password) {
		return model.JwtResponse{}, errors.New("invalid username or password")
	}

	if model.PrivateKey == nil {
		return model.JwtResponse{}, errors.New("signing key not loaded")
	}

	subject := req.Username

	accessJWT := model.NewAccessToken(subject, ip, ua)
	accessTokenStr, err := accessJWT.Sign(model.PrivateKey)
	if err != nil {
		return model.JwtResponse{}, fmt.Errorf("failed to sign access token: %w", err)
	}

	refreshJWT := model.NewRefreshToken(subject, ip, ua)
	refreshTokenStr, err := refreshJWT.Sign(model.PrivateKey)
	if err != nil {
		return model.JwtResponse{}, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	jwtResp := model.JwtResponse{
		AccessToken:  accessTokenStr,
		RefreshToken: refreshTokenStr,
		ExpiresIn:    accessJWT.ExpiresIn,
		EventType:    model.EventTypeAuthLogin,
		Actor: &model.Actor{
			Idenitifier: subject,
			IpAddress:   ip,
			UserAgent:   ua,
		},
	}

	utilities.LogProgress("handler", "Login",
		fmt.Sprintf("user=%s", subject))

	return jwtResp, nil
}
