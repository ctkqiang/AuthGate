package handler

import (
	"authgate/internal/model"
	"authgate/internal/security"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func init() {
	// Generate a test key pair so JWT signing works.
	priv, pub, _ := security.GenerateRSAKeyPair()
	privKey, _ := security.ParsePrivateKeyPEM(priv)
	pubKey, _ := security.ParsePublicKeyPEM(pub)
	model.PrivateKey = privKey
	model.PublicKey = pubKey
}

func TestIndex(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	Index(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["service"] != "AuthGate" {
		t.Fatalf("expected AuthGate, got %s", body["service"])
	}
}

func TestHealth(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	Health(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "healthy" {
		t.Fatalf("expected healthy, got %s", body["status"])
	}
}

func TestMetrics(t *testing.T) {
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	Metrics(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestRegistration_Validation(t *testing.T) {
	_, err := Registration(model.User{}, "", "")
	if err == nil || err.Error() != "username is required" {
		t.Fatalf("expected username required, got %v", err)
	}

	_, err = Registration(model.User{Username: "test"}, "", "")
	if err == nil || err.Error() != "email is required" {
		t.Fatalf("expected email required, got %v", err)
	}

	_, err = Registration(model.User{Username: "test", Email: "t@t.com"}, "", "")
	if err == nil || err.Error() != "password is required" {
		t.Fatalf("expected password required, got %v", err)
	}
}

func TestRegistration_Success(t *testing.T) {
	resp, err := Registration(model.User{
		Username: "testuser",
		Email:    "test@test.com",
		Password: "secret123",
	}, "127.0.0.1", "GoTest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected access token")
	}
	if resp.RefreshToken == "" {
		t.Fatal("expected refresh token")
	}
	if resp.ExpiresIn != 3600 {
		t.Fatalf("expected 3600, got %d", resp.ExpiresIn)
	}
	if resp.EventType != model.EventTypeAuthRegister {
		t.Fatalf("expected auth_register event, got %s", resp.EventType)
	}
	if resp.Actor.Idenitifier != "testuser" {
		t.Fatalf("expected testuser actor, got %s", resp.Actor.Idenitifier)
	}
}

func TestPasswordHashing(t *testing.T) {
	hash, err := security.HashPassword("secret123")
	if err != nil {
		t.Fatalf("hash failed: %v", err)
	}
	if hash == "secret123" {
		t.Fatal("password was not hashed")
	}
	if !security.CheckPassword(hash, "secret123") {
		t.Fatal("valid password rejected")
	}
	if security.CheckPassword(hash, "wrong") {
		t.Fatal("wrong password accepted")
	}
}

func TestLogin_Validation(t *testing.T) {
	_, err := Login(model.EmailPasswordAuthRequest{}, "", "")
	if err == nil || err.Error() != "username is required" {
		t.Fatalf("expected username required, got %v", err)
	}

	_, err = Login(model.EmailPasswordAuthRequest{Username: "x"}, "", "")
	if err == nil || err.Error() != "password is required" {
		t.Fatalf("expected password required, got %v", err)
	}
}

func TestAuthRegister_Handler(t *testing.T) {
	body := `{"Username":"bob","Email":"bob@test.com","Password":"pass123"}`
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	AuthRegister(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp model.Response
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
}

func TestAuthRegister_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	AuthRegister(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestRefresh_MissingToken(t *testing.T) {
	_, err := Refresh("", "", "")
	if err == nil || err.Error() != "refresh token is required" {
		t.Fatalf("expected refresh token required, got %v", err)
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	_, err := Refresh("not.a.valid.token", "", "")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestValidateAccessToken_Empty(t *testing.T) {
	_, err := ValidateAccessToken("")
	if err == nil || err.Error() != "access token is required" {
		t.Fatalf("expected access token required, got %v", err)
	}
}

func TestValidateAccessToken_Invalid(t *testing.T) {
	_, err := ValidateAccessToken("invalid.token.here")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestValidateAccessToken_Signed(t *testing.T) {
	access := model.NewAccessToken("alice", "127.0.0.1", "test")
	signed, err := access.Sign(model.PrivateKey)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	sub, err := ValidateAccessToken(signed)
	if err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	if sub != "alice" {
		t.Fatalf("expected alice, got %s", sub)
	}
}

func TestRefresh_ValidToken(t *testing.T) {
	refresh := model.NewRefreshToken("charlie", "127.0.0.1", "test")
	signed, err := refresh.Sign(model.PrivateKey)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	resp, err := Refresh(signed, "127.0.0.1", "test")
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	if resp.AccessToken == "" || resp.RefreshToken == "" {
		t.Fatal("expected tokens in response")
	}
	if resp.EventType != model.EventTypeAuthRefresh {
		t.Fatalf("expected auth_refresh event, got %s", resp.EventType)
	}
}

func TestTokenBlacklist_RevokeAndCheck(t *testing.T) {
	access := model.NewAccessToken("dave", "127.0.0.1", "test")
	signed, _ := access.Sign(model.PrivateKey)

	if IsTokenRevoked(signed) {
		t.Fatal("token should not be revoked yet")
	}

	if err := RevokeToken(signed); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	if !IsTokenRevoked(signed) {
		t.Fatal("token should be revoked")
	}

	// ValidateAccessToken should also reject revoked tokens.
	_, err := ValidateAccessToken(signed)
	if err == nil || err.Error() != "token has been revoked" {
		t.Fatalf("expected revoked error, got %v", err)
	}
}

func TestRefresh_RevokedToken(t *testing.T) {
	refresh := model.NewRefreshToken("eve", "127.0.0.1", "test")
	signed, _ := refresh.Sign(model.PrivateKey)

	if err := RevokeToken(signed); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	_, err := Refresh(signed, "127.0.0.1", "test")
	if err == nil || err.Error() != "token has been revoked" {
		t.Fatalf("expected revoked error, got %v", err)
	}
}

func TestExtractProvider(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/auth/provider/google", "google"},
		{"/auth/provider/github", "github"},
		{"/auth/provider/", ""},
		{"/auth/login", ""},
		{"/", ""},
	}
	for _, tt := range tests {
		result := extractProvider(tt.path)
		if result != tt.expected {
			t.Errorf("extractProvider(%s) = %s, want %s", tt.path, result, tt.expected)
		}
	}
}

func TestSecurityMiddleware_PassThrough(t *testing.T) {
	called := false
	handler := SecurityMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(200)
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Fatal("handler was not called")
	}
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestSecurityMiddleware_SQLInjectionDetection(t *testing.T) {
	var capturedMatches []security.ThreatMatch
	SecurityLogFunc = func(method, path, srcIP, ua string, matches []security.ThreatMatch) {
		capturedMatches = matches
	}

	handler := SecurityMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	body := `{"username":"admin' OR '1'='1 --","password":"x"}`
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if len(capturedMatches) == 0 {
		t.Fatal("expected threat matches for SQL injection")
	}

	hasSQLi := false
	for _, m := range capturedMatches {
		if m.Category == "SQL_INJECTION" {
			hasSQLi = true
			break
		}
	}
	if !hasSQLi {
		t.Fatal("expected SQL_INJECTION match")
	}
}

func TestAPIKeyMiddleware_NoKeysConfigured(t *testing.T) {
	apiKeys = map[string]string{} // reset

	called := false
	handler := APIKeyMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Fatal("handler should be called when no API keys configured")
	}
}

func TestAPIKeyMiddleware_ValidKey(t *testing.T) {
	apiKeys = map[string]string{"testservice": "sk-test-123"}

	called := false
	handler := APIKeyMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("X-API-Key", "sk-test-123")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Fatal("handler should be called with valid API key")
	}
}

func TestAPIKeyMiddleware_InvalidKey(t *testing.T) {
	apiKeys = map[string]string{"testservice": "sk-test-123"}

	handler := APIKeyMiddleware(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called with invalid key")
	})

	req := httptest.NewRequest("GET", "/health", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRateTracker(t *testing.T) {
	rt := security.NewRateTracker(60 * time.Second)

	// < 100 from same IP → path should not trigger blocking
	var blocked bool
	for i := 0; i < 50; i++ {
		matches := rt.Record(security.RateEvent{IP: "10.0.0.1", Path: "/api"})
		for _, m := range matches {
			if m.Severity >= security.SeverityHigh {
				blocked = true
			}
		}
	}
	if blocked {
		t.Fatal("50 requests should not trigger rate block")
	}
}

func TestForgotPassword_Handler(t *testing.T) {
	req := httptest.NewRequest("POST", "/auth/forgot-password",
		bytes.NewBufferString(`{"username":"alice"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	AuthForgotPassword(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestAuthLogout_Handler(t *testing.T) {
	access := model.NewAccessToken("frank", "127.0.0.1", "test")
	signed, _ := access.Sign(model.PrivateKey)

	body := `{"access_token":"` + signed + `"}`
	req := httptest.NewRequest("POST", "/auth/logout", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	AuthLogout(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !IsTokenRevoked(signed) {
		t.Fatal("token should be revoked after logout")
	}
}
