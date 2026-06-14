// Package aws (lambda.go) provides the HTTP-to-Lambda bridge.
//
// Two execution modes share a single entry point:
//
//	Local development  —  net/http server on 0.0.0.0:8080
//	AWS Lambda         —  lambda.Start(HandleAPIGatewayEvent)
//
// The _LAMBDA_SERVER_PORT and AWS_LAMBDA_RUNTIME_API environment
// variables are set by the Lambda runtime; their presence determines
// which mode [InitializeLambdaService] operates in.
//
// Route definitions live in [service.Routes] and are shared with the
// local server and all other cloud adapters.
package aws

import (
	"authgate/internal/model"
	"authgate/internal/service"
	"authgate/internal/utilities"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	aws_lambda_http "github.com/aws/aws-lambda-go/lambda"
)

const (
	addr = "0.0.0.0:8080"

	IndexPath  = "/"
	HealthPath = "/health"
)

// responseRecorder is a lightweight http.ResponseWriter implementation
// that captures status code, headers, and body in memory. It is used by
// HandleAPIGatewayEvent to bridge the stdlib handler signature to the
// API Gateway response envelope.
type responseRecorder struct {
	statusCode int
	header     http.Header
	body       bytes.Buffer
}

// newResponseRecorder returns a recorder whose status defaults to 200 OK.
func newResponseRecorder() *responseRecorder {
	return &responseRecorder{
		statusCode: http.StatusOK,
		header:     make(http.Header),
	}
}

func (r *responseRecorder) Header() http.Header { return r.header }
func (r *responseRecorder) Write(b []byte) (int, error) {
	return r.body.Write(b)
}
func (r *responseRecorder) WriteHeader(code int) { r.statusCode = code }

// isLambdaRuntime reports whether the process is executing inside the
// AWS Lambda execution environment.
//
// Both _LAMBDA_SERVER_PORT and AWS_LAMBDA_RUNTIME_API must be present.
func isLambdaRuntime() bool {
	_, hasPort := os.LookupEnv("_LAMBDA_SERVER_PORT")
	_, hasAPI := os.LookupEnv("AWS_LAMBDA_RUNTIME_API")
	return hasPort && hasAPI
}

// InitializeLambdaService starts the service in the appropriate mode:
//   - AWS Lambda → registers HandleAPIGatewayEvent as the Lambda handler
//     and blocks forever.
//   - Local      → returns immediately; the caller (main.go) should start
//     a single unified HTTP server to avoid port conflicts.
func InitializeLambdaService() error {
	if isLambdaRuntime() {
		utilities.LogProgress("Lambda", "Runtime detected", "starting lambda.Start")
		aws_lambda_http.Start(HandleAPIGatewayEvent)
		return nil
	}

	utilities.LogProgress("Lambda", "Init", "local mode — skipping HTTP server (managed by main.go)")
	return nil
}

// HandleAPIGatewayEvent is the Lambda handler for API Gateway
// (REST / HTTP API / Function URL) requests. It dispatches to
// the matching route defined in [service.Routes] based on the
// request path.
func HandleAPIGatewayEvent(ctx context.Context, event model.APIGatewayEvent) (map[string]any, error) {
	defer func() {
		if r := recover(); r != nil {
			utilities.Error("lambda: panic in route handler: %v", r)
		}
	}()

	req, err := http.NewRequestWithContext(
		ctx,
		event.HTTPMethod,
		event.Path,
		strings.NewReader(event.Body),
	)
	if err != nil {
		return apiGatewayResponse(http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("invalid request: %v", err),
		}), nil
	}

	for k, v := range event.Headers {
		req.Header.Set(k, v)
	}

	srcIP := req.Header.Get("X-Forwarded-For")
	if srcIP == "" {
		srcIP = req.RemoteAddr
	}
	utilities.LogProgress("lambda", req.Method+" "+req.URL.Path, fmt.Sprintf("source=%s", srcIP))

	w := newResponseRecorder()
	matched := false
	for _, entry := range service.Routes {
		if event.Path == entry.Path {
			entry.Handler(w, req)
			matched = true
			break
		}
	}
	if !matched {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "not found"}`))
	}

	return apiGatewayResponse(w.statusCode, w.body.String()), nil
}

// apiGatewayResponse builds the Lambda integration response envelope
// expected by API Gateway.
func apiGatewayResponse(statusCode int, body any) map[string]any {
	var bodyStr string
	switch v := body.(type) {
	case string:
		bodyStr = v
	case []byte:
		bodyStr = string(v)
	default:
		b, _ := json.Marshal(v)
		bodyStr = string(b)
	}
	return map[string]any{
		"statusCode": statusCode,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"body": bodyStr,
	}
}

// LambdaHandleRequest is kept for backward compatibility with the
// simple Lambda invocation style (no API Gateway proxy).
func LambdaHandleRequest(ctx context.Context) (string, error) {
	utilities.LogProgress("Lambda", "HandleRequest", "Start")
	return "200", nil
}
