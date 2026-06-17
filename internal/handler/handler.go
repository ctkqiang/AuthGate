// Package handler provides HTTP handlers and business logic for the AuthGate
// authentication gateway. It exposes registration, login, logout, token refresh,
// third-party provider authentication, email verification, password reset, and
// health check endpoints.
//
// Handlers are environment-agnostic — they write to standard http.ResponseWriter
// and are dispatched from local net/http, AWS Lambda, and Alibaba Cloud FC via
// the shared route table in the service package.
//
// Callback injection pattern:
//
// This package avoids import cycles with aws, aliyun, and persistence by
// accepting function pointers (PersistUserFunc, LookupUserFunc, SecurityLogFunc,
// HealthCheckFunc) that main.go wires at startup.
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

// PersistUserFunc is invoked after a successful registration to persist the
// user record to the configured database backend.
//
// Parameters:
//   - ctx: request-scoped context for cancellation.
//   - user: the model.User populated from the registration request body.
//   - jwtResp: the signed JwtResponse containing access and refresh tokens.
//
// Returns:
//   - error: nil on success; non-nil on persistence failure (logged, not blocking).
var PersistUserFunc func(ctx context.Context, user model.User, jwtResp model.JwtResponse) error

// LookupUserFunc is invoked during login to retrieve a stored user record by
// username from the configured database backend.
//
// Parameters:
//   - ctx: request-scoped context for cancellation.
//   - username: the claimed username from the login request.
//
// Returns:
//   - map[string]interface{}: the stored record, or nil if the user does not exist.
//   - error: nil on success; non-nil on database error.
var LookupUserFunc func(ctx context.Context, username string) (map[string]interface{}, error)

// HealthCheckFunc is invoked by the /health endpoint to report upstream
// dependency status. Set by main.go; when nil, /health returns only the
// service-local healthy status.
//
// Parameters:
//   (none)
//
// Returns:
//   - map[string]string: key-value pairs describing each dependency, e.g.
//     {"dynamodb": "healthy", "s3": "healthy"}.
var HealthCheckFunc func() map[string]string

// Index handles GET /.
// Returns basic service identity and running status.
//
// Parameters:
//   - w: http.ResponseWriter for the response body.
//   - r: *http.Request containing the incoming HTTP request.
func Index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"service": "AuthGate",
		"status":  "running",
	})
}

// Health handles GET /health.
// Returns the service health status along with upstream dependency checks
// when HealthCheckFunc has been configured.
//
// Parameters:
//   - w: http.ResponseWriter for the response body.
//   - r: *http.Request containing the incoming HTTP request.
func Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	result := map[string]string{"status": "healthy"}
	if HealthCheckFunc != nil {
		for k, v := range HealthCheckFunc() {
			result[k] = v
		}
	}
	json.NewEncoder(w).Encode(result)
}

// AuthRegister handles POST /auth/register.
// Decodes the request body into a model.User, calls Registration to validate
// and issue signed JWTs, and best-effort persists the user via PersistUserFunc.
//
// Parameters:
//   - w: http.ResponseWriter for the response body.
//   - r: *http.Request containing the incoming HTTP request with JSON body.
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
// Decodes the request body into an EmailPasswordAuthRequest, calls Login to
// validate credentials against the stored user record, and returns signed JWTs
// on success.
//
// Parameters:
//   - w: http.ResponseWriter for the response body.
//   - r: *http.Request containing the incoming HTTP request with JSON body.
func AuthLogin(w http.ResponseWriter, r *http.Request) {
	var req model.EmailPasswordAuthRequest
	w.Header().Set("Content-Type", "application/json")

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
// Revokes the supplied access token by adding its JTI to the token blacklist.
// Because JWTs are stateless, the client is also expected to discard the token.
//
// Parameters:
//   - w: http.ResponseWriter for the response body.
//   - r: *http.Request containing the incoming HTTP request with JSON body.
func AuthLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var body struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	if body.AccessToken != "" {
		if err := RevokeToken(body.AccessToken); err != nil {
			utilities.Error("handler: revoke token failed: %v", err)
		}
	}

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
// Validates the supplied refresh token (RS256 signature, scope, expiry,
// blacklist) and issues a new access and refresh token pair.
//
// Parameters:
//   - w: http.ResponseWriter for the response body.
//   - r: *http.Request containing the incoming HTTP request with JSON body.
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
// Extracts the provider identifier from the URL path and delegates to
// AuthenticateWithProvider for third-party identity verification and JWT
// issuance.
//
// Parameters:
//   - w: http.ResponseWriter for the response body.
//   - r: *http.Request containing the incoming HTTP request with JSON body.
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

// extractProvider strips the "/auth/provider/" prefix from the URL path and
// returns the provider identifier string (e.g. "google").
//
// Parameters:
//   - path: the full request URL path.
//
// Returns:
//   - string: the provider name, or empty string if the path does not match
//     the "/auth/provider/" prefix.
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
