// Package handler (middleware.go) provides request-level security
// inspection that scans every incoming request for attack patterns
// (SQL injection, XSS, path traversal, command injection, SSRF, etc.)
// and routes findings to the configured security log callback.
//
// SecurityLogFunc is injected by main.go to avoid import cycles with
// the aws/aliyun packages. In local mode it is nil and threats are
// logged to stderr only.
package handler

import (
	"authgate/internal/security"
	"authgate/internal/utilities"
	"bytes"
	"io"
	"net/http"
	"strings"
)

// SecurityLogFunc is the callback invoked when security threats are
// detected in a request. It receives the HTTP method, path, source IP,
// user agent, and the list of detected threat matches.
//
// Set by main.go to route events to CloudWatch (AWS) or CloudMonitor
// (Aliyun). When nil (local mode), threats are logged to stderr only.
var SecurityLogFunc func(method, path, srcIP, ua string, matches []security.ThreatMatch)

// SecurityMiddleware wraps an http.HandlerFunc with threat detection.
// Detected threats are logged to the active cloud platform's monitoring
// service (CloudWatch on AWS Lambda, CloudMonitor on Aliyun FC).
// Requests are never blocked — this is detection-only.
func SecurityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		srcIP := r.Header.Get("X-Forwarded-For")
		if srcIP == "" {
			srcIP = r.RemoteAddr
		}
		ua := r.UserAgent()

		// Read and buffer the body so we can scan it without consuming it.
		bodyBytes, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			bodyBytes = nil
		}
		body := string(bodyBytes)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Collect headers into a flat map.
		headers := make(map[string]string, len(r.Header))
		for k := range r.Header {
			headers[k] = r.Header.Get(k)
		}

		matches := security.ScanRequest(body, r.URL.Path, r.URL.RawQuery, headers)

		if len(matches) > 0 {
			// Route to the active cloud platform via injected callback.
			if SecurityLogFunc != nil {
				SecurityLogFunc(r.Method, r.URL.Path, srcIP, ua, matches)
			}

			// Always log locally so developers see it immediately.
			utilities.LogProgress("Security",
				r.Method+" "+r.URL.Path,
				joinMatchSummary(matches),
			)
		}

		next(w, r)
	}
}

// joinMatchSummary builds a compact human-readable string from threat
// matches for use in progress-log entries.
func joinMatchSummary(matches []security.ThreatMatch) string {
	parts := make([]string, 0, len(matches))
	for _, m := range matches {
		parts = append(parts, m.Category+"="+m.Severity.String())
	}
	return strings.Join(parts, " ")
}
