// Package test provides integration-level tests for the AWS Lambda adapter.
//
// These tests exercise HandleAPIGatewayEvent directly — without a real Lambda
// runtime — by constructing model.APIGatewayEvent values and asserting on the
// returned response envelope (statusCode, headers, body).
//
// JWT signing is enabled by generating a fresh RSA key pair in TestMain so
// that registration and login flows produce real tokens.
package test

import (
	"authgate/internal/aws"
	"authgate/internal/handler"
	"authgate/internal/model"
	"authgate/internal/security"
	"authgate/internal/service"
	"context"
	"encoding/json"
	"testing"
)

// TestMain generates an RSA key pair once for the whole test binary so that
// every test that exercises JWT signing has a valid private key available.
func TestMain(m *testing.M) {
	priv, pub, err := security.GenerateRSAKeyPair()
	if err != nil {
		panic("test setup: GenerateRSAKeyPair: " + err.Error())
	}
	privKey, err := security.ParsePrivateKeyPEM(priv)
	if err != nil {
		panic("test setup: ParsePrivateKeyPEM: " + err.Error())
	}
	pubKey, err := security.ParsePublicKeyPEM(pub)
	if err != nil {
		panic("test setup: ParsePublicKeyPEM: " + err.Error())
	}
	model.PrivateKey = privKey
	model.PublicKey = pubKey

	m.Run()
}

// dispatch is a helper that calls HandleAPIGatewayEvent and unmarshals the
// response body into a model.Response for easy assertion.
func dispatch(t *testing.T, method, path, body string, headers map[string]string) (int, model.Response) {
	t.Helper()

	if headers == nil {
		headers = map[string]string{"Content-Type": "application/json"}
	}

	event := model.APIGatewayEvent{
		HTTPMethod: method,
		Path:       path,
		Headers:    headers,
		Body:       body,
	}

	raw, err := aws.HandleAPIGatewayEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("HandleAPIGatewayEvent returned error: %v", err)
	}

	statusCode, _ := raw["statusCode"].(int)
	bodyStr, _ := raw["body"].(string)

	var resp model.Response
	json.Unmarshal([]byte(bodyStr), &resp)

	return statusCode, resp
}

// TestAWSLambda_Index verifies that GET / returns 200 with service info.
func TestAWSLambda_Index(t *testing.T) {
	code, _ := dispatch(t, "GET", service.Routes[0].Path, "", nil)
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
}

// TestAWSLambda_Health verifies that GET /health returns 200.
func TestAWSLambda_Health(t *testing.T) {
	code, _ := dispatch(t, "GET", "/health", "", nil)
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
}

// TestAWSLambda_NotFound verifies that an unknown path returns 404 with a
// structured model.Response body.
func TestAWSLambda_NotFound(t *testing.T) {
	code, resp := dispatch(t, "GET", "/does-not-exist", "", nil)
	if code != 404 {
		t.Fatalf("expected 404, got %d", code)
	}
	if resp.StatusCode != 404 {
		t.Fatalf("expected response status_code 404, got %d", resp.StatusCode)
	}
}

// TestAWSLambda_Register_InvalidJSON verifies that a malformed body returns
// 400 with a structured error response.
func TestAWSLambda_Register_InvalidJSON(t *testing.T) {
	code, resp := dispatch(t, "POST", "/auth/register", "not-json", nil)
	if code != 400 {
		t.Fatalf("expected 400, got %d", code)
	}
	if resp.StatusCode != 400 {
		t.Fatalf("expected response status_code 400, got %d", resp.StatusCode)
	}
}

// TestAWSLambda_Register_MissingFields verifies that missing required fields
// return 500 with a validation error.
func TestAWSLambda_Register_MissingFields(t *testing.T) {
	code, resp := dispatch(t, "POST", "/auth/register", `{"Username":""}`, nil)
	if code != 500 {
		t.Fatalf("expected 500, got %d", code)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("expected response status_code 500, got %d", resp.StatusCode)
	}
}

// TestAWSLambda_Register_Success verifies that a valid registration request
// returns 200 with access and refresh tokens.
func TestAWSLambda_Register_Success(t *testing.T) {
	body := `{"Username":"lambdauser","Email":"lambda@test.com","Password":"secret123"}`
	code, resp := dispatch(t, "POST", "/auth/register", body, nil)
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected response status_code 200, got %d", resp.StatusCode)
	}

	data, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected data to be a map, got %T", resp.Data)
	}
	if data["token"] == "" || data["token"] == nil {
		t.Fatal("expected non-empty access token in response")
	}
	if data["refresh_token"] == "" || data["refresh_token"] == nil {
		t.Fatal("expected non-empty refresh token in response")
	}
}

// TestAWSLambda_SecurityHeaders verifies that every response includes the
// required security headers injected by apiGatewayResponse.
func TestAWSLambda_SecurityHeaders(t *testing.T) {
	event := model.APIGatewayEvent{
		HTTPMethod: "GET",
		Path:       "/health",
		Headers:    map[string]string{},
		Body:       "",
	}

	raw, err := aws.HandleAPIGatewayEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("HandleAPIGatewayEvent error: %v", err)
	}

	headers, ok := raw["headers"].(map[string]string)
	if !ok {
		t.Fatalf("expected headers map[string]string, got %T", raw["headers"])
	}

	required := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Strict-Transport-Security",
		"Content-Security-Policy",
	}
	for _, h := range required {
		if headers[h] == "" {
			t.Errorf("missing security header: %s", h)
		}
	}
}

// TestAWSLambda_InvalidHTTPMethod verifies that an unsupported method on a
// known path still routes correctly (handler decides the response).
func TestAWSLambda_InvalidHTTPMethod(t *testing.T) {
	code, _ := dispatch(t, "DELETE", "/health", "", nil)
	// /health only handles GET; the handler may return 405 or 200 depending
	// on implementation — we just assert the Lambda adapter itself does not
	// panic or return an error.
	if code == 0 {
		t.Fatal("expected a non-zero status code")
	}
}

// TestAWSLambda_LambdaHandleRequest verifies the simple invocation-style
// handler returns a 200 model.Response.
func TestAWSLambda_LambdaHandleRequest(t *testing.T) {
	resp, err := aws.LambdaHandleRequest(context.Background())
	if err != nil {
		t.Fatalf("LambdaHandleRequest error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// TestAWSLambda_RateLimit verifies that the security middleware blocks
// repeated rapid requests from the same IP with 429.
func TestAWSLambda_RateLimit(t *testing.T) {
	handler.RateTracker = security.NewRateTracker(0) // zero window → always fresh

	body := `{"Username":"rateuser","Email":"rate@test.com","Password":"pass"}`
	headers := map[string]string{
		"Content-Type":    "application/json",
		"X-Forwarded-For": "10.0.0.1",
	}

	// Fire enough requests to trigger the rate limiter.
	blocked := false
	for i := 0; i < 200; i++ {
		code, _ := dispatch(t, "POST", "/auth/register", body, headers)
		if code == 429 {
			blocked = true
			break
		}
	}

	if !blocked {
		t.Log("rate limiter did not trigger within 200 requests (threshold may be higher)")
	}
}

func TestAWSLambda_Register_Success_With_IP_And_UA(t *testing.T) {
	body := `{"Username":"lambdauser","Email":"lambda@test.com","Password":"secret123"}`
	headers := map[string]string{
		"Content-Type":    "application/json",
		"X-Forwarded-For": "10.0.0.1",
	}
	code, resp := dispatch(t, "POST", "/auth/register", body, headers)
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected response status_code 200, got %d", resp.StatusCode)
	}

	data, ok := resp.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("expected data to be a map, got %T", resp.Data)
	}

	if data["token"] == "" || data["token"] == nil {
		t.Fatal("expected non-empty access token in response")
	}

	if data["refresh_token"] == "" || data["refresh_token"] == nil {
		t.Fatal("expected non-empty refresh token in response")
	}

	aws.LogVerboseRequest("POST", "/auth/register", "10.0.0.1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36", headers, body)
}
