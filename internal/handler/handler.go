package handler

import (
	"authgate/internal/model"
	"encoding/json"
	"net/http"
)

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

	json.NewEncoder(w).Encode(model.Response{
		StatusCode: 200,
		Signature:  "",
		Event:      nil,
		Data:       jwtResponse,
	})
}
