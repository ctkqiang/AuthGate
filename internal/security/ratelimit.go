// Package security (ratelimit.go) provides a sliding-window rate
// tracker that detects abusive request patterns — same endpoint hit
// 100+ times per second, same IP flooding a single route, or overall
// request storms.  When a threshold is crossed a ThreatMatch is
// returned so the caller can log it through CloudWatch / CloudMonitor.
//
// This is detection-only; it does NOT block requests.  Blocking is a
// separate concern (WAF / API Gateway throttle / middleware).
package security

import (
	"sync"
	"time"
)

// RateEvent represents a single request for rate tracking.
type RateEvent struct {
	IP   string
	Path string
}

// RateTracker holds per-IP and per-path counters in sliding windows.
// Public methods are safe for concurrent use.
type RateTracker struct {
	mu sync.Mutex

	perIP    map[string]*slidingWindow
	perPath  map[string]*slidingWindow
	perIPPath map[string]*slidingWindow
	global   *slidingWindow
}

// slidingWindow counts events in the last `window` duration with
// second-granularity buckets.
type slidingWindow struct {
	window  time.Duration
	buckets []int
	head    int
	lastTS  time.Time
}

func newSlidingWindow(window time.Duration, buckets int) *slidingWindow {
	return &slidingWindow{
		window:  window,
		buckets: make([]int, buckets),
		lastTS:  time.Now(),
	}
}

func (sw *slidingWindow) add(ts time.Time) {
	elapsed := ts.Sub(sw.lastTS)
	steps := int(elapsed.Seconds())
	if steps < 0 {
		steps = 0
	}
	if steps >= len(sw.buckets) {
		for i := range sw.buckets {
			sw.buckets[i] = 0
		}
		sw.head = 0
	} else {
		for i := 0; i < steps; i++ {
			sw.head = (sw.head + 1) % len(sw.buckets)
			sw.buckets[sw.head] = 0
		}
	}
	sw.buckets[sw.head]++
	sw.lastTS = ts
}

func (sw *slidingWindow) sum() int {
	total := 0
	for _, v := range sw.buckets {
		total += v
	}
	return total
}

// NewRateTracker creates a tracker with windows sized for the given
// duration.  Default bucket count is duration-in-seconds capped at 60.
func NewRateTracker(window time.Duration) *RateTracker {
	buckets := int(window.Seconds())
	if buckets < 1 {
		buckets = 1
	}
	if buckets > 120 {
		buckets = 120
	}
	return &RateTracker{
		perIP:     make(map[string]*slidingWindow),
		perPath:   make(map[string]*slidingWindow),
		perIPPath: make(map[string]*slidingWindow),
		global:    newSlidingWindow(window, buckets),
	}
}

// Record registers a request event and returns threat matches for any
// thresholds that have been breached.  An empty slice means no rate
// anomaly was detected.
func (rt *RateTracker) Record(evt RateEvent) []ThreatMatch {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	rt.global.add(now)

	swIP := rt.ensure(rt.perIP, evt.IP)
	swIP.add(now)

	swPath := rt.ensure(rt.perPath, evt.Path)
	swPath.add(now)

	key := evt.IP + "|" + evt.Path
	swIPPath := rt.ensure(rt.perIPPath, key)
	swIPPath.add(now)

	var matches []ThreatMatch

	// ── Thresholds ──

	// Same IP → same endpoint >= 100 in window
	if n := swIPPath.sum(); n >= 100 {
		matches = append(matches, ThreatMatch{
			Category: "RATE_BURST_IP_PATH",
			Severity: SeverityHigh,
			Pattern:  ">=100 req/win from same IP to same path",
			Location: "rate:" + evt.IP + "→" + evt.Path,
			Sample:   rateSample(evt, n),
		})
	}
	// Same IP across all endpoints >= 500 in window
	if n := swIP.sum(); n >= 500 {
		matches = append(matches, ThreatMatch{
			Category: "RATE_BURST_IP",
			Severity: SeverityHigh,
			Pattern:  ">=500 req/win from same IP (any path)",
			Location: "rate:" + evt.IP,
			Sample:   rateSample(evt, n),
		})
	}
	// Same endpoint (any IP) >= 1000 in window
	if n := swPath.sum(); n >= 1000 {
		matches = append(matches, ThreatMatch{
			Category: "RATE_BURST_PATH",
			Severity: SeverityMedium,
			Pattern:  ">=1000 req/win to same path (any IP)",
			Location: "rate:" + evt.Path,
			Sample:   rateSample(evt, n),
		})
	}
	// Global rate >= 5000 in window
	if n := rt.global.sum(); n >= 5000 {
		matches = append(matches, ThreatMatch{
			Category: "RATE_STORM",
			Severity: SeverityCritical,
			Pattern:  ">=5000 total req/win",
			Location: "rate:global",
			Sample:   rateSample(evt, n),
		})
	}
	// Same IP → same endpoint >= 10/sec sustained (instantaneous)
	if n := swIPPath.sum(); n >= 10 && n < 100 {
		matches = append(matches, ThreatMatch{
			Category: "RATE_ELEVATED_IP_PATH",
			Severity: SeverityLow,
			Pattern:  ">=10 req/win from same IP to same path",
			Location: "rate:" + evt.IP + "→" + evt.Path,
			Sample:   rateSample(evt, n),
		})
	}

	return matches
}

func (rt *RateTracker) ensure(m map[string]*slidingWindow, key string) *slidingWindow {
	sw, ok := m[key]
	if !ok {
		sw = newSlidingWindow(rt.global.window, len(rt.global.buckets))
		m[key] = sw
	}
	return sw
}

func rateSample(evt RateEvent, count int) string {
	return evt.IP + " → " + evt.Path + " count=" + itoa(count)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
