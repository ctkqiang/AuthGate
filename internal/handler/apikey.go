package handler

import (
	"authgate/internal/model"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

// API keys for service-to-service auth. Loaded from env, fallback to defaults.
var apiKeys map[string]string

func init() {
	apiKeys = make(map[string]string)
	loadAPIKeysFromEnv()
}

func loadAPIKeysFromEnv() {
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "AUTHGATE_API_KEY_") {
			continue
		}
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimPrefix(parts[0], "AUTHGATE_API_KEY_")
		name = strings.ToLower(name)
		apiKeys[name] = parts[1]
	}
}

// APIKeyMiddleware wraps a handler and requires a valid X-API-Key header.
// If no API keys are configured, the middleware passes through.
func APIKeyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(apiKeys) == 0 {
			next(w, r)
			return
		}

		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}
		if key == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.Response{
				StatusCode: 401,
				Data:       map[string]string{"error": "API key required"},
			})
			return
		}

		valid := false
		for _, v := range apiKeys {
			if subtle.ConstantTimeCompare([]byte(key), []byte(v)) == 1 {
				valid = true
				break
			}
		}

		if !valid {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(model.Response{
				StatusCode: 401,
				Data:       map[string]string{"error": "invalid API key"},
			})
			return
		}

		next(w, r)
	}
}
