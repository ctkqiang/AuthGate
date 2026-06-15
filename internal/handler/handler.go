package handler

import (
	"authgate/internal/model"
	"authgate/internal/utilities"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// PersistUserFunc is the callback invoked after a successful registration
// to persist the user record to the configured database backend.
//
// It is set by main.go during initialisation to avoid an import cycle
// between handler, aws/aliyun, and service. When nil (no backend
// configured), persistence is silently skipped.
var PersistUserFunc func(ctx context.Context, user model.User, jwtResp model.JwtResponse) error

// LookupUserFunc is the callback invoked during login to retrieve a user
// record by username from the configured database backend.
//
// It is set by main.go during initialisation. When nil (no backend
// configured), login always fails with "user not found".
var LookupUserFunc func(ctx context.Context, username string) (map[string]interface{}, error)

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

// AuthLogin handles POST /auth/login.
func AuthLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req model.EmailPasswordAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 400,
			Data:       map[string]string{"error": "invalid request body"},
		})
		return
	}

	jwtResponse, err := Login(req, r.RemoteAddr, r.UserAgent())
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 401,
			Data:       map[string]string{"error": err.Error()},
		})
		return
	}

	json.NewEncoder(w).Encode(model.Response{
		StatusCode: 200,
		Data:       jwtResponse,
	})
}

// AuthLogout handles POST /auth/logout.
func AuthLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	utilities.LogProgress("handler", "AuthLogout",
		fmt.Sprintf("token=%s", utilities.Mask(body.AccessToken)))

	json.NewEncoder(w).Encode(model.Response{
		StatusCode: 200,
		Data: map[string]string{
			"message": "logged out successfully",
		},
	})
}

// AuthRefresh handles POST /auth/refresh.
func AuthRefresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 400,
			Data:       map[string]string{"error": "invalid request body"},
		})
		return
	}

	jwtResponse, err := Refresh(body.RefreshToken, r.RemoteAddr, r.UserAgent())
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 401,
			Data:       map[string]string{"error": err.Error()},
		})
		return
	}

	json.NewEncoder(w).Encode(model.Response{
		StatusCode: 200,
		Data:       jwtResponse,
	})
}

// AuthWithProvider handles POST /auth/provider/[name].
func AuthWithProvider(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	provider := extractProvider(r.URL.Path)
	if provider == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 400,
			Data:       map[string]string{"error": "provider name required in path"},
		})
		return
	}

	jwtResponse, err := AuthenticateWithProvider(provider, r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(model.Response{
			StatusCode: 401,
			Data:       map[string]string{"error": err.Error()},
		})
		return
	}

	json.NewEncoder(w).Encode(model.Response{
		StatusCode: 200,
		Data:       jwtResponse,
	})
}

// extractProvider strips the "/auth/provider/" prefix from path and
// returns the provider identifier.
func extractProvider(path string) string {
	const prefix = "/auth/provider/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	name := path[len(prefix):]
	if name == "" {
		return ""
	}
	return name
}
