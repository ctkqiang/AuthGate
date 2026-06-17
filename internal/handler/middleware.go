package handler

import (
	"authgate/internal/security"
	"authgate/internal/utilities"
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SecurityLogFunc receives detected threat matches for cloud monitoring.
var SecurityLogFunc func(method, path, srcIP, ua string, matches []security.ThreatMatch)

// RateTracker is the global sliding-window rate monitor.
var RateTracker *security.RateTracker
var rateOnce sync.Once

func initRateTracker() {
	rateOnce.Do(func() {
		if RateTracker == nil {
			RateTracker = security.NewRateTracker(60 * time.Second)
		}
	})
}

// SecurityMiddleware wraps an http.HandlerFunc with threat detection
// and rate monitoring. When a rate threshold is breached, the request
// is blocked with HTTP 429 Too Many Requests.
func SecurityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		srcIP := r.Header.Get("X-Forwarded-For")
		if srcIP == "" {
			srcIP = r.RemoteAddr
		}
		ua := r.UserAgent()

		// ── 1. Rate tracking ──
		initRateTracker()
		rateMatches := RateTracker.Record(security.RateEvent{IP: srcIP, Path: r.URL.Path})

		// Block on HIGH or CRITICAL rate thresholds.
		for _, m := range rateMatches {
			if m.Severity >= security.SeverityHigh {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				io.WriteString(w, `{"status_code":429,"data":{"error":"rate limit exceeded","category":"`+m.Category+`"}}`)
				metricsRecord("rate_blocked", 1)
				return
			}
		}

		// ── 2. Body scan ──
		bodyBytes, err := io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			bodyBytes = nil
		}
		body := string(bodyBytes)
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		headers := make(map[string]string, len(r.Header))
		for k := range r.Header {
			headers[k] = r.Header.Get(k)
		}

		patternMatches := security.ScanRequest(body, r.URL.Path, r.URL.RawQuery, headers)

		// ── 3. Merge & log ──
		all := append(rateMatches, patternMatches...)

		if len(all) > 0 {
			if SecurityLogFunc != nil {
				SecurityLogFunc(r.Method, r.URL.Path, srcIP, ua, all)
			}
			utilities.LogProgress("Security",
				r.Method+" "+r.URL.Path,
				joinMatchSummary(all),
			)
		}

		next(w, r)
	}
}

func joinMatchSummary(matches []security.ThreatMatch) string {
	parts := make([]string, 0, len(matches))
	for _, m := range matches {
		parts = append(parts, m.Category+"="+m.Severity.String())
	}
	return strings.Join(parts, " ")
}
