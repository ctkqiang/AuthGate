package handler

import (
	"authgate/internal/model"
	"authgate/internal/utilities"
	"context"
	"encoding/json"
	"net/http"
)

// PersistUserFunc is the callback invoked after a successful registration
// to persist the user record to the configured database backend.
//
// It is set by main.go during initialisation to avoid an import cycle
// between handler, aws/aliyun, and service. When nil (no backend
// configured), persistence is silently skipped.
var PersistUserFunc func(ctx context.Context, user model.User, jwtResp model.JwtResponse) error

// Index handles GET / and returns basic service information.
func Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"service": "AuthGate",
		"status":  "running",
	})
}

// Health handles GET /health and returns the service health status.
func Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
	})
}

// AuthRegister handles POST /auth/register.
// After successful registration and JWT issuance, the user is persisted
// to the configured database backend (AWS DynamoDB or Alibaba Cloud
// TableStore) via [PersistUserFunc]. The database write is best-effort —
// if no backend is configured, registration succeeds without persistence.
func AuthRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user model.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 400,
			Signature:  "",
			Event:      nil,
			Data:       map[string]string{"error": "invalid request body"},
		})
		return
	}

	jwtResponse, err := Registration(user, r.RemoteAddr, r.UserAgent())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 500,
			Signature:  "",
			Event:      nil,
			Data:       map[string]string{"error": err.Error()},
		})
		return
	}

	// Persist the user to the configured database backend.
	// Failure to persist is logged but does not block the response —
	// the caller already has valid JWT tokens.
	if PersistUserFunc != nil {
		if dbErr := PersistUserFunc(r.Context(), user, jwtResponse); dbErr != nil {
			utilities.Error("handler: persist user failed: %v", dbErr)
		}
	}

	json.NewEncoder(w).Encode(model.Response{
		StatusCode: 200,
		Signature:  "",
		Event:      nil,
		Data:       jwtResponse,
	})
}
