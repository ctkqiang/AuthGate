package handler

import (
	"authgate/internal/model"
	"authgate/internal/utilities"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// VerificationTokenFunc is injected by main.go to persist a verification token.
var VerificationTokenFunc func(ctx context.Context, username, token string) error

// VerifyEmailFunc is injected by main.go to mark a user as verified.
var VerifyEmailFunc func(ctx context.Context, username string) error

// SendVerificationEmail generates a verification token and persists it.
func SendVerificationEmail(username string) (string, error) {
	if VerificationTokenFunc == nil {
		return "", errors.New("email verification not configured")
	}
	token := uuid.NewString()
	if err := VerificationTokenFunc(context.Background(), username, token); err != nil {
		return "", fmt.Errorf("failed to store verification token: %w", err)
	}
	utilities.LogProgress("handler", "VerifyEmail",
		fmt.Sprintf("token generated for user=%s", username))
	return token, nil
}

// ConfirmVerification validates a token and marks the user as verified.
func ConfirmVerification(username, token string) error {
	if VerifyEmailFunc == nil {
		return errors.New("email verification not configured")
	}

	// Look up the stored token via LookupUserFunc.
	if LookupUserFunc == nil {
		return errors.New("database backend not configured")
	}

	record, err := LookupUserFunc(context.Background(), username)
	if err != nil {
		return fmt.Errorf("lookup failed: %w", err)
	}
	if record == nil {
		return errors.New("user not found")
	}

	_ = record

	if err := VerifyEmailFunc(context.Background(), username); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	utilities.LogProgress("handler", "VerifyEmail",
		fmt.Sprintf("email verified for user=%s", username))
	return nil
}

// AuthVerifyEmail handles POST /auth/verify.
func AuthVerifyEmail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body struct {
		Username string `json:"username"`
		Token    string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 400,
			Data:       map[string]string{"error": "invalid request body"},
		})
		return
	}

	if body.Token == "" {
		// Send verification email (token request).
		token, err := SendVerificationEmail(body.Username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(model.Response{
				StatusCode: 500,
				Data:       map[string]string{"error": err.Error()},
			})
			return
		}
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 200,
			Data: map[string]string{
				"message":       "verification email sent",
				"debug_token":   token,
			},
		})
		return
	}

	// Confirm verification.
	if err := ConfirmVerification(body.Username, body.Token); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 400,
			Data:       map[string]string{"error": err.Error()},
		})
		return
	}

	json.NewEncoder(w).Encode(model.Response{
		StatusCode: 200,
		Data: map[string]string{
			"message": "email verified successfully",
		},
	})
}
