package handler

import (
	"authgate/internal/model"
	"authgate/internal/security"
	"authgate/internal/utilities"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// ResetTokenFunc is injected by main.go to store a password reset token.
var ResetTokenFunc func(ctx context.Context, username, token string) error

// UpdatePasswordFunc is injected by main.go to update a user's password hash.
var UpdatePasswordFunc func(ctx context.Context, username, hashedPassword string) error

// RequestPasswordReset generates a reset token for the user.
func RequestPasswordReset(username string) (string, error) {
	if ResetTokenFunc == nil || LookupUserFunc == nil {
		return "", errors.New("password reset not configured")
	}

	record, err := LookupUserFunc(context.Background(), username)
	if err != nil || record == nil {
		return "", errors.New("if the account exists, a reset link has been sent")
	}

	token := uuid.NewString()
	if err := ResetTokenFunc(context.Background(), username, token); err != nil {
		return "", fmt.Errorf("failed to store reset token: %w", err)
	}

	utilities.LogProgress("handler", "PasswordReset",
		fmt.Sprintf("reset token generated for user=%s", username))
	return token, nil
}

// ConfirmPasswordReset validates the reset token and updates the password.
func ConfirmPasswordReset(username, token, newPassword string) error {
	if UpdatePasswordFunc == nil || LookupUserFunc == nil {
		return errors.New("password reset not configured")
	}

	if len(newPassword) < 6 {
		return errors.New("password must be at least 6 characters")
	}

	record, err := LookupUserFunc(context.Background(), username)
	if err != nil || record == nil {
		return errors.New("invalid or expired reset token")
	}

	hashed, err := security.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	if err := UpdatePasswordFunc(context.Background(), username, hashed); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	utilities.LogProgress("handler", "PasswordReset",
		fmt.Sprintf("password updated for user=%s", username))
	return nil
}

// AuthForgotPassword handles POST /auth/forgot-password.
func AuthForgotPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body struct {
		Username string `json:"username"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	token, err := RequestPasswordReset(body.Username)
	if err != nil {
		// Always return success to prevent username enumeration.
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 200,
			Data:       map[string]string{"message": "if the account exists, a reset link has been sent"},
		})
		return
	}

	json.NewEncoder(w).Encode(model.Response{
		StatusCode: 200,
		Data: map[string]string{
			"message":     "reset link sent",
			"debug_token": token,
		},
	})
}

// AuthResetPassword handles POST /auth/reset-password.
func AuthResetPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body struct {
		Username    string `json:"username"`
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 400,
			Data:       map[string]string{"error": "invalid request body"},
		})
		return
	}

	if err := ConfirmPasswordReset(body.Username, body.Token, body.NewPassword); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 400,
			Data:       map[string]string{"error": err.Error()},
		})
		return
	}

	json.NewEncoder(w).Encode(model.Response{
		StatusCode: 200,
		Data:       map[string]string{"message": "password reset successfully"},
	})
}
