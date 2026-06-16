// Package security (monitor.go) provides request-level threat detection
// for SQL injection, XSS, path traversal, command injection, SSRF, and
// other common attack vectors. It is designed to run in cloud runtimes
// (AWS Lambda / Aliyun FC) and feed structured security events to
// CloudWatch / CloudMonitor for alarming.
package security

import (
	"regexp"
	"strings"
)

// ThreatSeverity classifies detected patterns by risk level.
type ThreatSeverity int

const (
	SeverityLow    ThreatSeverity = iota // informational (unusual but not malicious)
	SeverityMedium                       // suspicious pattern, worth reviewing
	SeverityHigh                         // likely attack, escalate immediately
	SeverityCritical                     // confirmed exploit pattern
)

func (s ThreatSeverity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ThreatMatch describes a single detected pattern in a request.
type ThreatMatch struct {
	Category string        // e.g. "SQL_INJECTION", "XSS", "PATH_TRAVERSAL"
	Severity ThreatSeverity
	Pattern  string        // the regex or keyword that matched
	Location string        // "body", "path", "query", "header:X-Forwarded-For"
	Sample   string        // redacted snippet of the matched content (max 80 chars)
}

// patternGroup groups related detection patterns under a single category.
type patternGroup struct {
	Category string
	Severity ThreatSeverity
	Patterns []*regexp.Regexp
}

var threatPatterns []patternGroup

func init() {
	threatPatterns = []patternGroup{
		// ── SQL Injection ──
		{
			Category: "SQL_INJECTION",
			Severity: SeverityCritical,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(\bUNION\s+(ALL\s+)?SELECT\b)`),
				regexp.MustCompile(`(?i)(\bSELECT\b.*\bFROM\b.*\bWHERE\b)`),
				regexp.MustCompile(`(?i)(\bINSERT\s+INTO\b.*\bVALUES\b)`),
				regexp.MustCompile(`(?i)(\bDROP\s+(TABLE|DATABASE|INDEX)\b)`),
				regexp.MustCompile(`(?i)(\bDELETE\s+FROM\b)`),
				regexp.MustCompile(`(?i)(\bUPDATE\b.*\bSET\b)`),
				regexp.MustCompile(`(?i)(\bEXEC(\s|%20|\+)*\()`),
				regexp.MustCompile(`(?i)(\bOR\s+('|")\d+('|")\s*=\s*('|")\d+('|"))`),
				regexp.MustCompile(`(?i)(\bAND\s+('|")\d+('|")\s*=\s*('|")\d+('|"))`),
				regexp.MustCompile(`(?i)(--[^\n]*$)`),
				regexp.MustCompile(`(?i)(/\*.*\*/)`),
				regexp.MustCompile(`(?i)(\bSLEEP\s*\(|WAITFOR\s+DELAY|pg_sleep\s*\()`),
				regexp.MustCompile(`(?i)(\bEXEC\s+sp_|\bxp_cmdshell\b)`),
			},
		},
		// ── XSS / HTML Injection ──
		{
			Category: "XSS",
			Severity: SeverityHigh,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(<script[^>]*>)`),
				regexp.MustCompile(`(?i)(javascript\s*:)`),
				regexp.MustCompile(`(?i)(on(load|click|error|mouse|key|focus|blur)\s*=)`),
				regexp.MustCompile(`(?i)(<img[^>]*onerror\s*=)`),
				regexp.MustCompile(`(?i)(<svg[^>]*onload\s*=)`),
				regexp.MustCompile(`(?i)(alert\s*\(|prompt\s*\(|confirm\s*\()`),
				regexp.MustCompile(`(?i)(document\.cookie)`),
				regexp.MustCompile(`(?i)(<iframe[^>]*>)`),
				regexp.MustCompile(`(?i)(eval\s*\(.*\))`),
				regexp.MustCompile(`(?i)(expression\s*\(|moz-binding)`),
			},
		},
		// ── Path Traversal ──
		{
			Category: "PATH_TRAVERSAL",
			Severity: SeverityHigh,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`\.\./\.\./`),
				regexp.MustCompile(`\.\.\\\.\.\\`),
				regexp.MustCompile(`(%2e%2e%2f|%2e%2e/)`),
				regexp.MustCompile(`(/etc/(passwd|shadow|hosts))`),
				regexp.MustCompile(`(C:\\Windows\\System32)`),
				regexp.MustCompile(`(/proc/self/(environ|cmdline|fd))`),
				regexp.MustCompile(`(file:///(etc|proc|sys|dev))`),
			},
		},
		// ── Command Injection ──
		{
			Category: "COMMAND_INJECTION",
			Severity: SeverityCritical,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(;\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl)\b)`),
				regexp.MustCompile(`(?i)(\|\s*(cat|ls|id|whoami|wget|curl|nc)\b)`),
				regexp.MustCompile(`(?i)(\$\{.*\})`),
				regexp.MustCompile(`(?i)(\b(cmd|command)\s*=\s*['"](/bin|/usr|C:\\))`),
				regexp.MustCompile("(?i)(`[^`]*`)"),
				regexp.MustCompile(`(?i)(\$\(.*\))`),
				regexp.MustCompile(`(?i)(&&\s*(wget|curl|nc|ncat|telnet|bash|sh)\b)`),
			},
		},
		// ── SSRF ──
		{
			Category: "SSRF",
			Severity: SeverityHigh,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(http://169\.254\.169\.254/)`),
				regexp.MustCompile(`(?i)(http://100\.\d+\.\d+\.\d+/)`),
				regexp.MustCompile(`(?i)(http://(localhost|127\.0\.0\.1|0\.0\.0\.0)[:/])`),
				regexp.MustCompile(`(?i)(http://\[::1\])`),
				regexp.MustCompile(`(?i)(metadata\.google\.internal)`),
				regexp.MustCompile(`(?i)(/latest/meta-data/)`),
			},
		},
		// ── LFI / RFI ──
		{
			Category: "FILE_INCLUSION",
			Severity: SeverityHigh,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)((php|http|https|ftp|data|expect|input)://)`),
				regexp.MustCompile(`(?i)(\.php\?.*=)`),
				regexp.MustCompile(`(?i)(/wp-(admin|content|includes)/)`),
				regexp.MustCompile(`(?i)(\.(ini|cfg|config|bak|old|swp|sql)(\?|%00|\x00|$))`),
			},
		},
		// ── NoSQL Injection ──
		{
			Category: "NOSQL_INJECTION",
			Severity: SeverityHigh,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(\$(ne|gt|gte|lt|lte|in|nin|regex|where|or|and|not|exists|type|mod|size|all|elemMatch|eq)\b)`),
				regexp.MustCompile(`(?i)(\{.*\$where.*\})`),
			},
		},
		// ── HTTP Header Injection ──
		{
			Category: "HEADER_INJECTION",
			Severity: SeverityMedium,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(Content-(Type|Length|Disposition)\s*:)`),
				regexp.MustCompile(`(?i)(\r\n.*(Location|Set-Cookie|X-Forwarded)\s*:)`),
			},
		},
	}
}

// ScanRequest inspects a request body, URL path, query string, and headers
// for known attack patterns. Returns all matches found, ordered by severity
// (critical first). An empty slice means the request is clean.
func ScanRequest(body, path, query string, headers map[string]string) []ThreatMatch {
	var matches []ThreatMatch

	check := func(source, location string) {
		if source == "" {
			return
		}
		for _, group := range threatPatterns {
			for _, pat := range group.Patterns {
				if loc := pat.FindStringIndex(source); loc != nil {
					sample := safeSample(source, loc[0], 80)
					matches = append(matches, ThreatMatch{
						Category: group.Category,
						Severity: group.Severity,
						Pattern:  pat.String(),
						Location: location,
						Sample:   sample,
					})
				}
			}
		}
	}

	check(body, "body")
	check(path, "path")
	check(query, "query")

	for k, v := range headers {
		check(v, "header:"+k)
	}

	return matches
}

// HighestSeverity returns the highest severity among the given matches.
// Returns SeverityLow if the slice is empty.
func HighestSeverity(matches []ThreatMatch) ThreatSeverity {
	max := SeverityLow
	for _, m := range matches {
		if m.Severity > max {
			max = m.Severity
		}
	}
	return max
}

// safeSample returns a redacted substring starting at index, capped at
// maxLen characters. Newlines and tabs are replaced with spaces.
func safeSample(s string, start, maxLen int) string {
	if start >= len(s) {
		return ""
	}
	end := start + maxLen
	if end > len(s) {
		end = len(s)
	}
	sample := s[start:end]
	sample = strings.ReplaceAll(sample, "\n", " ")
	sample = strings.ReplaceAll(sample, "\r", " ")
	sample = strings.ReplaceAll(sample, "\t", " ")
	return sample
}
