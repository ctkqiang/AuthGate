package authentication

import (
	"authgate/internal/model"
	"errors"
)

func Registration(username string, email string, password string) (model.JwtResponse, error) {
	if username == "" {
		return model.JwtResponse{}, errors.New("username is required")
	}
	if email == "" {
		return model.JwtResponse{}, errors.New("email is required")
	}
	if password == "" {
		return model.JwtResponse{}, errors.New("password is required")
	}

	// TODO

	return model.JwtResponse{}, nil
}
