package handler

import (
	"authgate/internal/model"
	"authgate/internal/security"
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func init() {
	priv, pub, _ := security.GenerateRSAKeyPair()
	model.PrivateKey, _ = security.ParsePrivateKeyPEM(priv)
	model.PublicKey, _ = security.ParsePublicKeyPEM(pub)
}

// BenchmarkRegistration measures JWT signing throughput for registration.
func BenchmarkRegistration(b *testing.B) {
	user := model.User{Username: "bench", Email: "bench@test.com", Password: "pass123"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Registration(user, "127.0.0.1", "Benchmark/1.0")
	}
}

// BenchmarkLogin_PasswordCheck measures bcrypt comparison (dominant cost).
func BenchmarkLogin_PasswordCheck(b *testing.B) {
	hash, _ := security.HashPassword("secret123")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		security.CheckPassword(hash, "secret123")
	}
}

// BenchmarkPasswordHash measures bcrypt hashing cost.
func BenchmarkPasswordHash(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		security.HashPassword("secret123")
	}
}

// BenchmarkJWT_Sign measures RS256 signing throughput.
func BenchmarkJWT_Sign(b *testing.B) {
	j := model.NewAccessToken("alice", "127.0.0.1", "bench")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j.Sign(model.PrivateKey)
	}
}

// BenchmarkJWTAccessToken_Validate measures RS256 verification throughput.
func BenchmarkJWTAccessToken_Validate(b *testing.B) {
	j := model.NewAccessToken("alice", "127.0.0.1", "bench")
	signed, _ := j.Sign(model.PrivateKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateAccessToken(signed)
	}
}

// BenchmarkAuthRegister_HTTP measures full HTTP handler throughput.
func BenchmarkAuthRegister_HTTP(b *testing.B) {
	body := `{"Username":"bench","Email":"bench@test.com","Password":"pass123"}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/auth/register", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		AuthRegister(w, req)
	}
}

// BenchmarkHealth_HTTP measures lightweight health check throughput.
func BenchmarkHealth_HTTP(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		Health(w, req)
	}
}

// BenchmarkSecurityMiddleware_SQLi measures threat detection throughput.
func BenchmarkSecurityMiddleware_SQLi(b *testing.B) {
	handler := SecurityMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	body := `{"username":"admin' OR '1'='1 --","password":"x"}`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, req)
	}
}

// BenchmarkRateTracker measures rate tracking throughput.
func BenchmarkRateTracker(b *testing.B) {
	rt := security.NewRateTracker(60 * time.Second)
	evt := security.RateEvent{IP: "10.0.0.1", Path: "/api"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rt.Record(evt)
	}
}
