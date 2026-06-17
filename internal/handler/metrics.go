package handler

import (
	"encoding/json"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

var (
	metricsStartTime = time.Now()

	metricsReqTotal    int64
	metricsReqErr4xx   int64
	metricsReqErr5xx   int64
	metricsRateBlocked int64
	metricsThreatsSeen int64
)

func metricsRecord(name string, delta int64) {
	switch name {
	case "request":
		atomic.AddInt64(&metricsReqTotal, delta)
	case "4xx":
		atomic.AddInt64(&metricsReqErr4xx, delta)
	case "5xx":
		atomic.AddInt64(&metricsReqErr5xx, delta)
	case "rate_blocked":
		atomic.AddInt64(&metricsRateBlocked, delta)
	case "threat":
		atomic.AddInt64(&metricsThreatsSeen, delta)
	}
}

// RecordRequest increments the total request counter.
func RecordRequest() { metricsRecord("request", 1) }

// RecordError4xx increments the 4xx error counter.
func RecordError4xx() { metricsRecord("4xx", 1) }

// RecordError5xx increments the 5xx error counter.
func RecordError5xx() { metricsRecord("5xx", 1) }

// RecordThreat increments the threat counter.
func RecordThreat() { metricsRecord("threat", 1) }

// Metrics handles GET /metrics and returns Prometheus-compatible metrics.
func Metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"uptime_seconds":      int64(time.Since(metricsStartTime).Seconds()),
		"requests_total":      atomic.LoadInt64(&metricsReqTotal),
		"errors_4xx":          atomic.LoadInt64(&metricsReqErr4xx),
		"errors_5xx":          atomic.LoadInt64(&metricsReqErr5xx),
		"rate_blocked":        atomic.LoadInt64(&metricsRateBlocked),
		"threats_detected":    atomic.LoadInt64(&metricsThreatsSeen),
		"goroutines":          runtime.NumGoroutine(),
		"heap_alloc_mb":       float64(m.Alloc) / 1024 / 1024,
		"gc_pause_total_ms":   float64(m.PauseTotalNs) / 1e6,
	})
}
