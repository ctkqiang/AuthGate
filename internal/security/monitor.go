package security

import (
	"regexp"
	"strings"
)

// ThreatSeverity classifies detected patterns by risk level.
type ThreatSeverity int

const (
	SeverityLow      ThreatSeverity = iota // informational
	SeverityMedium                         // suspicious
	SeverityHigh                           // likely attack
	SeverityCritical                       // confirmed exploit
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
	Category string // e.g. "SQL_INJECTION", "XSS"
	Severity ThreatSeverity
	Pattern  string // regex that matched
	Location string // "body", "path", "query", "header:..."
	Sample   string // redacted snippet (max 80 chars)
}

type patternGroup struct {
	Category string
	Severity ThreatSeverity
	Patterns []*regexp.Regexp
}

var threatPatterns []patternGroup

func init() {
	threatPatterns = []patternGroup{
		// ── SQL Injection — CRITICAL ──
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
		// ── XSS — HIGH ──
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
			},
		},
		// ── Path Traversal — HIGH ──
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
		// ── Command Injection — CRITICAL ──
		{
			Category: "COMMAND_INJECTION",
			Severity: SeverityCritical,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(;\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl)\b)`),
				regexp.MustCompile(`(?i)(\|\s*(cat|ls|id|whoami|wget|curl|nc)\b)`),
				regexp.MustCompile(`(?i)(\$\{.*\})`),
				regexp.MustCompile("(?i)(`[^`]*`)"),
				regexp.MustCompile(`(?i)(\$\(.*\))`),
				regexp.MustCompile(`(?i)(&&\s*(wget|curl|nc|ncat|telnet|bash|sh)\b)`),
			},
		},
		// ── SSRF — HIGH ──
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
		// ── LFI / RFI — HIGH ──
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
		// ── NoSQL Injection — HIGH ──
		{
			Category: "NOSQL_INJECTION",
			Severity: SeverityHigh,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(\$(ne|gt|gte|lt|lte|in|nin|regex|where|or|and|not|exists|type|mod|size|all|elemMatch|eq)\b)`),
				regexp.MustCompile(`(?i)(\{.*\$where.*\})`),
			},
		},
		// ── Sensitive File Probing — HIGH ──
		{
			Category: "SENSITIVE_FILE",
			Severity: SeverityHigh,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(/\.env\b)`),
				regexp.MustCompile(`(?i)(/\.git/)`),
				regexp.MustCompile(`(?i)(/\.svn/)`),
				regexp.MustCompile(`(?i)(/\.hg/)`),
				regexp.MustCompile(`(?i)(/\.docker/)`),
				regexp.MustCompile(`(?i)(/\.aws/)`),
				regexp.MustCompile(`(?i)(\.env\.(backup|bak|old|local|production|staging|dev))`),
				regexp.MustCompile(`(?i)(/(config|configuration)\.(json|yml|yaml|xml|ini|toml|php))`),
				regexp.MustCompile(`(?i)(/(settings|secrets|credentials)\.(json|yml|yaml|xml))`),
				regexp.MustCompile(`(?i)(/(docker-compose|Dockerfile|Makefile|Vagrantfile)\b)`),
				regexp.MustCompile(`(?i)(/(id_rsa|id_dsa|id_ecdsa|known_hosts))`),
				regexp.MustCompile(`(?i)(/\.kube/)`),
				regexp.MustCompile(`(?i)(/(web\.config|app\.config|package\.json|composer\.json))`),
				regexp.MustCompile(`(?i)(/\.bash_history|/\.zsh_history|/\.mysql_history)`),
				regexp.MustCompile(`(?i)(/phpinfo\.php|/info\.php|/test\.php)`),
				regexp.MustCompile(`(?i)(/(phpmyadmin|phpMyAdmin|pma|mysql|adminer)\b)`),
			},
		},
		// ── Directory Brute-force — MEDIUM ──
		{
			Category: "DIR_BRUTE_FORCE",
			Severity: SeverityMedium,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(/(admin|administrator|backend|cms|panel|manager|dashboard)\b)`),
				regexp.MustCompile(`(?i)(/(wp-login|wp-admin|xmlrpc)\.php)`),
				regexp.MustCompile(`(?i)(/(api|graphql|swagger|openapi|docs|rest)(/|$))`),
				regexp.MustCompile(`(?i)(/(\.well-known|actuator|health|info|metrics|trace|mappings|dump|heapdump|env|beans|loggers|logfile)(/|$))`),
				regexp.MustCompile(`(?i)(/(solr|jenkins|grafana|kibana|prometheus|consul|etcd|vault)(/|$))`),
				regexp.MustCompile(`(?i)(/(console|shell|cmd|exec|terminal|debug|trace)(/|$))`),
				regexp.MustCompile(`(?i)(/(api/v\d+/|api-docs|openapi\.json|swagger\.json))`),
				regexp.MustCompile(`(?i)(/(\.vscode|\.idea)/)`),
				regexp.MustCompile(`(?i)(/(backup|uploads?|tmp|temp|cache|log|logs)(/|$))`),
			},
		},
		// ── CSRF / Cross-Origin — MEDIUM ──
		{
			Category: "CROSS_ORIGIN",
			Severity: SeverityMedium,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(<form[^>]*action\s*=\s*['"]https?://)`),
				regexp.MustCompile(`(?i)(<input[^>]*name\s*=\s*['"]_?(csrftoken|csrfmiddlewaretoken|authenticity_token|nonce)`),
				regexp.MustCompile(`(?i)(\bcross-origin\b.*\b(blocked|denied|forbidden)\b)`),
			},
		},
		// ── Excessive Request Parameters — LOW ──
		{
			Category: "EXCESSIVE_PARAMS",
			Severity: SeverityLow,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`&[a-zA-Z0-9_]+=`),
			},
		},
		// ── XML Injection / XXE — HIGH ──
		{
			Category: "XML_ATTACK",
			Severity: SeverityHigh,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(<!ENTITY\s+\w+\s+SYSTEM)`),
				regexp.MustCompile(`(?i)(<!DOCTYPE[^>]*\[)`),
				regexp.MustCompile(`(?i)(<\?xml[^>]*encoding\s*=)`),
				regexp.MustCompile(`(?i)(<![CDATA\[)`),
			},
		},
		// ── HTTP Header Injection — MEDIUM ──
		{
			Category: "HEADER_INJECTION",
			Severity: SeverityMedium,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(Content-(Type|Length|Disposition)\s*:)`),
				regexp.MustCompile(`(?i)(\r\n.*(Location|Set-Cookie|X-Forwarded)\s*:)`),
			},
		},
		// ── Method Tampering — LOW ──
		{
			Category: "METHOD_TAMPERING",
			Severity: SeverityLow,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)(X-HTTP-Method-Override\s*:)`),
				regexp.MustCompile(`(?i)(_method\s*=\s*(PUT|DELETE|PATCH))`),
			},
		},
		// ── User-Agent Scanner — LOW ──
		{
			Category: "SCANNER_UA",
			Severity: SeverityLow,
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)((nikto|nessus|nmap|sqlmap|burp|zap|w3af|acunetix|openvas|gobuster|dirbuster|hydra|metasploit|masscan))`),
			},
		},
	}
}

// ScanRequest inspects a request body, URL path, query string, and
// headers for known attack patterns.
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
func HighestSeverity(matches []ThreatMatch) ThreatSeverity {
	max := SeverityLow
	for _, m := range matches {
		if m.Severity > max {
			max = m.Severity
		}
	}
	return max
}

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
