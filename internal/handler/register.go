package handler

import (
	"authgate/internal/model"
	"errors"
	"fmt"
)

// Registration validates user input, builds user credentials, generates
// signed access and refresh JWT tokens, and returns a JwtResponse.
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

	userCredential := model.User{
		Username: user.Username,
		Email:    user.Email,
		Password: user.Password,
		Gender:   user.Gender,
		Locale:   user.Locale,
	}
	_ = userCredential // reserved for persistence layer integration

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
