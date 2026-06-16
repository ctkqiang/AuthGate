// Package utilities provides structured, colour-coded logging compatible
// with AWS CloudWatch Logs and Alibaba Cloud Log Service (SLS).
//
// Log entries are written to stdout so they are captured by Lambda / FC
// runtimes automatically.  The structured block format (Logf) includes
// goroutine correlation IDs, memory stats, and elapsed time for tracing
// request lifecycles and detecting leaks.
//
// CloudWatch Logs Insights query examples:
//
//	All errors:    filter Status = "FAIL" | sort @timestamp desc
//	By component:  filter Component = "Security" | stats count() by Operation
//	Slow ops:      filter Elapsed ~= /[0-9]+s/
//
//	SLS query examples:
//	event: security.threat | SELECT severity, count(*) GROUP BY severity
package utilities

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ── Constants ──────────────────────────────────────────────────────

const (
	APP_NAME = "AuthGate"
	VERSION  = "1.0.0"
	TZ       = "CST"
)

// LogLevel controls the minimum severity emitted.
type LogLevel int

const (
	DEBUG    LogLevel = iota // verbose diagnostics (local dev only)
	INFO                     // general operational messages (default)
	WARN                     // recoverable issues, degraded mode
	ERROR                    // failures requiring attention
	VERBOSE                  // per-request metrics, audit trails
)

func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case VERBOSE:
		return "VERBOSE"
	default:
		return "UNKNOWN"
	}
}

// ── ANSI colour codes ──────────────────────────────────────────────

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPink   = "\033[35m"
	colorGreen  = "\033[32m"
	colorBold   = "\033[1m"
	colorNoBold = "\033[22m"
)

// ── Global state ───────────────────────────────────────────────────

var (
	CurrentLevel  = INFO
	startTime     = time.Now()
	errorCallback func(string)
	goroutineSeq  int
	goroutineMu   sync.Mutex
)

// ── Public API ─────────────────────────────────────────────────────

// SetLogLevel parses a string level name and sets the global threshold.
// Defaults to INFO on unrecognised input. Called automatically from
// init() via the LOG_LEVEL env var.
func SetLogLevel(s string) {
	switch strings.ToUpper(s) {
	case "DEBUG":
		CurrentLevel = DEBUG
	case "INFO":
		CurrentLevel = INFO
	case "WARN":
		CurrentLevel = WARN
	case "ERROR":
		CurrentLevel = ERROR
	case "VERBOSE":
		CurrentLevel = VERBOSE
	default:
		CurrentLevel = INFO
	}
}

// RegisterErrorCallback sets a callback invoked on every ERROR log line.
func RegisterErrorCallback(cb func(string)) { errorCallback = cb }

// Bold wraps text with ANSI bold escapes for emphasis inside log lines.
func Bold(text string) string { return colorBold + text + colorNoBold }

// Error emits an ERROR-level log.  Visible at INFO+.
func Error(format string, a ...interface{}) { Log(ERROR, format, a...) }

// Info emits an INFO-level log.
func Info(format string, a ...interface{}) { Log(INFO, format, a...) }

// Debug emits a DEBUG-level log.  Only visible when LOG_LEVEL=DEBUG.
func Debug(format string, a ...interface{}) { Log(DEBUG, format, a...) }

// Warn emits a WARN-level log.  Only visible at WARN+.
func Warn(format string, a ...interface{}) { Log(WARN, format, a...) }

// Log is the simple single-line logger.  Prefer Logf for structured
// operation logs; use Log for ad-hoc messages.
func Log(level LogLevel, format string, a ...interface{}) {
	if level < CurrentLevel {
		return
	}
	msg := fmt.Sprintf(format, a...)
	line := fmt.Sprintf("[%s] [%s] [%s] %s",
		APP_NAME, time.Now().Format("2006-01-02 15:04:05"), level.String(), msg)
	c := levelColor(level)
	if c != "" {
		fmt.Printf("%s%s%s\n", c, line, colorReset)
	} else {
		fmt.Println(line)
	}
	if level == ERROR && errorCallback != nil {
		errorCallback(line)
	}
}

// Logf emits a structured block log entry with standard fields (Status,
// Type, Memory, Routine, Elapsed) followed by caller-supplied key=value
// details.  This is the primary log function for operations.
func Logf(component, operation string, level LogLevel, status string, elapsed time.Duration, details ...string) {
	if level < CurrentLevel {
		return
	}
	id := nextTaskID()
	funcName := callerName(3)
	heapMB := heapAllocMB()

	header := fmt.Sprintf("[%s@%s]::%s:: (%s:%s>>%s::%s)",
		APP_NAME, nowCompact(), level.String(), component, operation, id, funcName)

	rows := [][]string{
		{"Status", status},
		{"Type", "ACTION"},
		{"Memory", fmt.Sprintf("%.2fMB", heapMB)},
		{"Routine", id},
		{"Elapsed", fmtElapsed(elapsed)},
	}
	for _, d := range details {
		k, v, ok := strings.Cut(d, "=")
		if ok {
			rows = append(rows, []string{strings.TrimSpace(k), strings.TrimSpace(v)})
		} else {
			rows = append(rows, []string{d, ""})
		}
	}

	c := levelColor(level)
	fmt.Print(buildBlock(header, c, rows))

	if level == ERROR && errorCallback != nil {
		errorCallback(header + " " + status)
	}
}

// LogProgress emits an INFO-level IN_PROGRESS log for intermediate
// checkpoints (startup phases, long-running steps, etc.).
func LogProgress(component, operation, msg string, details ...string) {
	resolved := msg
	if strings.Contains(msg, "%") && len(details) > 0 {
		verbCount := strings.Count(msg, "%s") + strings.Count(msg, "%d") + strings.Count(msg, "%v")
		if verbCount > 0 && verbCount <= len(details) {
			args := make([]interface{}, verbCount)
			for i := 0; i < verbCount; i++ {
				args[i] = details[i]
			}
			resolved = fmt.Sprintf(msg, args...)
			details = details[verbCount:]
		}
	}
	all := append([]string{"Progress=" + resolved}, details...)
	Logf(component, operation, INFO, "IN_PROGRESS", 0, all...)
}

// LogStart emits a START marker for an operation.
func LogStart(component, operation string) {
	Logf(component, operation, INFO, "START", 0)
}

// LogSuccess emits an OK marker with elapsed time.
func LogSuccess(component, operation string, elapsed time.Duration, details ...string) {
	Logf(component, operation, INFO, "OK", elapsed, details...)
}

// LogError emits a FAIL marker with the error message.
func LogError(component, operation string, err error, elapsed time.Duration, details ...string) {
	all := append([]string{"Error=" + err.Error()}, details...)
	Logf(component, operation, ERROR, "FAIL", elapsed, all...)
}

// LogWarn emits a WARN marker.
func LogWarn(component, operation, msg string, elapsed time.Duration, details ...string) {
	all := append([]string{"Warn=" + msg}, details...)
	Logf(component, operation, WARN, "WARN", elapsed, all...)
}

// Mask redacts a sensitive value, showing the first few characters
// followed by [REDACTED].  Useful for tokens, keys, and PII in logs.
func Mask(s string) string {
	runes := []rune(s)
	if len(runes) <= 4 {
		return "****"
	}
	n := 10
	if len(runes) <= n {
		n = len(runes) / 3
	}
	return string(runes[:n]) + "[REDACTED]"
}

// RetryWithBackoff executes an operation up to maxAttempts times with a
// fixed backoff between attempts. Returns the last error on exhaustion.
func RetryWithBackoff(name string, maxAttempts int, backoff time.Duration, fn func() error) error {
	var last error
	for i := 0; i < maxAttempts; i++ {
		if err := fn(); err == nil {
			return nil
		} else {
			last = err
			Warn("%s attempt %d/%d failed: %v — retrying in %v", name, i+1, maxAttempts, err, backoff)
			time.Sleep(backoff)
		}
	}
	return fmt.Errorf("%s: exhausted %d retries: %w", name, maxAttempts, last)
}

// ── Internal helpers ───────────────────────────────────────────────

func init() { SetLogLevel(os.Getenv("LOG_LEVEL")) }

func levelColor(l LogLevel) string {
	switch l {
	case DEBUG:
		return colorYellow
	case INFO:
		return colorBlue
	case WARN:
		return colorPink
	case ERROR:
		return colorRed
	case VERBOSE:
		return colorGreen
	default:
		return ""
	}
}

func nowCompact() string {
	t := time.Now()
	return fmt.Sprintf("%d%02d%02d:%02d:%02d:%02d%s",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), TZ)
}

func nextTaskID() string {
	goroutineMu.Lock()
	id := goroutineSeq
	goroutineSeq++
	goroutineMu.Unlock()
	return fmt.Sprintf("TASK-%03d", id)
}

func callerName(depth int) string {
	pc, _, _, ok := runtime.Caller(depth)
	if !ok {
		return "Unknown"
	}
	name := runtime.FuncForPC(pc).Name()
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i+1:]
	}
	return name
}

func heapAllocMB() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.Alloc) / 1024 / 1024
}

func fmtElapsed(d time.Duration) string {
	switch {
	case d == 0:
		return "0μs"
	case d < time.Microsecond:
		return fmt.Sprintf("%.2fμs", float64(d.Nanoseconds())/1000.0)
	case d < time.Millisecond:
		return fmt.Sprintf("%.2fμs", float64(d.Microseconds()))
	case d < time.Second:
		return fmt.Sprintf("%.2fms", float64(d.Milliseconds()))
	default:
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}

func buildBlock(header, color string, rows [][]string) string {
	var sb strings.Builder
	keyW := 0
	for _, r := range rows {
		if len(r) == 2 && len(r[0]) > keyW {
			keyW = len(r[0])
		}
	}
	sb.WriteString(color)
	sb.WriteString(colorBold)
	sb.WriteString(header)
	sb.WriteString(colorReset)
	sb.WriteString("\n")
	for _, r := range rows {
		if len(r) == 2 {
			fmt.Fprintf(&sb, "%s  | %-*s : %s%s\n", color, keyW, r[0], r[1], colorReset)
		}
	}
	return sb.String()
}
