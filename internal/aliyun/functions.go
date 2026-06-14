// Package aliyun (functions.go) provides the HTTP-to-FC bridge.
//
// Two execution modes share a single entry point:
//
//	Local development    —  net/http server on 0.0.0.0:8080
//	Alibaba Cloud FC     —  fc.StartHttp(router) via HTTP trigger
//
// The FC runtime sets FC_SERVICE_NAME, FC_FUNCTION_NAME and companion
// environment variables; their presence determines which mode
// [InitializeFCService] operates in.
//
// Route definitions live in [service.Routes] and are shared with the
// local server and all other cloud adapters.
package aliyun

import (
	"authgate/internal/service"
	"authgate/internal/utilities"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	aliyun_fc "github.com/aliyun/fc-runtime-go-sdk/fc"
)

const (
	addr = "0.0.0.0:8080"

	IndexPath  = "/"
	HealthPath = "/health"
)

// responseRecorder is a lightweight http.ResponseWriter implementation
// that captures status code, headers, and body in memory. It is used
// by the FC HTTP handler to bridge the stdlib handler signature to the
// FC response envelope.
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

// isFCRuntime reports whether the process is executing inside the
// Alibaba Cloud Function Compute execution environment.
//
// FC_FUNCTION_NAME is the most reliable indicator; it is always set
// by the FC runtime for both event and HTTP triggers.
func isFCRuntime() bool {
	_, ok := os.LookupEnv("FC_FUNCTION_NAME")
	return ok
}

// InitializeFCService starts the service in the appropriate mode:
//   - Alibaba Cloud FC → registers the HTTP handler via fc.StartHttp
//     and blocks forever.
//   - Local            → returns immediately; the caller (main.go) should
//     start a single unified HTTP server to avoid port conflicts.
func InitializeFCService() error {
	if isFCRuntime() {
		utilities.LogProgress("FC", "Runtime detected", "starting fc.StartHttp")
		aliyun_fc.StartHttp(http.HandlerFunc(fcHTTPHandler))
		return nil
	}

	utilities.LogProgress("FC", "Init", "local mode — skipping HTTP server (managed by main.go)")
	return nil
}

// fcHTTPHandler is the top-level HTTP handler registered with
// fc.StartHttp. It dispatches to the matching route defined in
// [service.Routes] based on the request path and handles panics
// gracefully.
func fcHTTPHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			utilities.Error("fc: panic in route handler: %v", rec)
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		}
	}()

	srcIP := r.Header.Get("X-Forwarded-For")
	if srcIP == "" {
		srcIP = r.RemoteAddr
	}
	utilities.LogProgress("fc", r.Method+" "+r.URL.Path, fmt.Sprintf("source=%s", srcIP))

	for _, entry := range service.Routes {
		if r.URL.Path == entry.Path {
			entry.Handler(w, r)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
}

// HandleFCRequest is a generic event-style handler for non-HTTP FC
// triggers (e.g. OSS events, Scheduled Tasks, Message Queue).
//
// Deprecated in favour of the HTTP-trigger approach (fc.StartHttp);
// kept for backward compatibility with existing event-driven functions.
func HandleFCRequest(ctx context.Context, event json.RawMessage) (map[string]any, error) {
	defer func() {
		if r := recover(); r != nil {
			utilities.Error("fc: panic in HandleFCRequest: %v", r)
		}
	}()

	utilities.LogProgress("fc", "HandleFCRequest", fmt.Sprintf("event=%s", string(event)))

	source := os.Getenv("FC_EVENT_SOURCE")
	if source == "" {
		source = "unknown"
	}

	return map[string]any{
		"statusCode": http.StatusOK,
		"headers": map[string]string{
			"Content-Type": "application/json",
		},
		"body": fmt.Sprintf(`{"source":"%s","message":"event acknowledged"}`, source),
	}, nil
}

// fcResponse builds the FC HTTP trigger response envelope. While
// fc.StartHttp writes directly to the http.ResponseWriter, this
// helper is provided for parity with the AWS lambda.go pattern
// and for use in unit tests.
func fcResponse(statusCode int, body any) map[string]any {
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