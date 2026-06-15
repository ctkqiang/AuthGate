package model

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
)

// APIGatewayEvent represents an API Gateway proxy integration event.
// It is the input format that AWS Lambda receives from API Gateway
// (REST API, HTTP API, or Function URL).
type APIGatewayEvent struct {
	HTTPMethod string            `json:"httpMethod"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

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

func AuthRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	actor := &Actor{
		Idenitifier: uuid.New().String(),
		IpAddress:   r.RemoteAddr,
		UserAgent:   r.UserAgent(),
	}

	jwtResponse := JwtResponse{
		AccessToken:  "",
		RefreshToken: "",
		ExpiresIn:    3600,
		EventType:    EventTypeAuthRegister,
		Actor:        actor,
	}

	json.NewEncoder(w).Encode(Response{
		StatusCode: 200,
		Signature:  "",
		Event:      nil,
		Data:       jwtResponse,
	})
}
