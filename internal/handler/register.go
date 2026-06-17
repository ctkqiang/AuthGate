package handler

import (
	"authgate/internal/model"
	"authgate/internal/security"
	"errors"
	"fmt"
)

// Registration validates user input, hashes the password with bcrypt, and
// issues a signed RS256 access token (3600s TTL) and refresh token (604800s
// TTL) bound to the client IP address and User-Agent header.
//
// Parameters:
//   - user: the model.User decoded from the registration request body.
//   - ip: the client IP address for token binding.
//   - ua: the client User-Agent header for token binding.
//
// Returns:
//   - model.JwtResponse: contains access token, refresh token, expiry,
//     event type, and actor metadata.
//   - error: nil on success; validation, key-loading, or signing errors
//     otherwise.
func Registration(user model.User, ip, ua string) (model.JwtResponse, error) {
	if user.Username == "" {
		return model.JwtResponse{}, errors.New("username is required")
	}
	if user.Email == "" {
		return model.JwtResponse{}, errors.New("email is required")
	}
	if user.Password == "" {
		return model.JwtResponse{}, errors.New("password is required")
	}

	hashed, err := security.HashPassword(user.Password)
	if err != nil {
		return model.JwtResponse{}, fmt.Errorf("failed to hash password: %w", err)
	}

	userCredential := model.User{
		Username: user.Username,
		Email:    user.Email,
		Password: hashed,
		Gender:   user.Gender,
		Locale:   user.Locale,
	}
	_ = userCredential

	if model.PrivateKey == nil {
		return model.JwtResponse{}, errors.New("signing key not loaded")
	}

	subject := user.Username

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

	return model.JwtResponse{
		AccessToken:  accessTokenStr,
		RefreshToken: refreshTokenStr,
		ExpiresIn:    accessJWT.ExpiresIn,
		EventType:    model.EventTypeAuthRegister,
		Actor: &model.Actor{
			Idenitifier: subject,
			IpAddress:   ip,
			UserAgent:   ua,
		},
	}, nil
}
