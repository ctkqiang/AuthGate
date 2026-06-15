package handler

import (
	"authgate/internal/model"
	"authgate/internal/utilities"
	"context"
	"errors"
	"fmt"
)

// Login validates credentials against the stored user record and issues
// fresh access and refresh JWT tokens bound to the client IP and User-Agent.
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
	if storedPassword != req.Password {
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
