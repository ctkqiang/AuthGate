// Package aws (cloudwatch.go) provides security-aware CloudWatch logging
// with metric emission and alarm-ready structured events for Lambda mode.
//
// Security events are emitted as structured JSON to CloudWatch Logs.
// Metric filters in the CloudWatch console can trigger alarms based on
// the patterns documented below.
//
// CloudWatch Metric Filters (paste into Console → Log groups → Metric filters):
//
//	CRITICAL threat:
//	  { $.severity = "CRITICAL" }
//
//	HIGH severity threat:
//	  { $.severity = "HIGH" }
//
//	SQL Injection attempt:
//	  { $.category = "SQL_INJECTION" }
//
//	XSS attempt:
//	  { $.category = "XSS" }
//
//	Command Injection attempt:
//	  { $.category = "COMMAND_INJECTION" }
//
//	Any threat (count all):
//	  { $.event = "security.threat" }
//
// CloudWatch Alarm (via Console / CDK / Terraform):
//
//	Threshold:  MetricFilter count >= 1 within 1 minute
//	Action:     SNS → PagerDuty / Slack / Email
//	TreatMissingData: notBreaching
package aws

import (
	"authgate/internal/security"
	"authgate/internal/utilities"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// SecurityEvent is the structured payload emitted to CloudWatch Logs for
// every suspicious request. It is designed to be parsed by CloudWatch
// Metric Filters and Logs Insights.
type SecurityEvent struct {
	Timestamp     string                 `json:"timestamp"`
	Event         string                 `json:"event"`
	Severity      string                 `json:"severity"`
	Category      string                 `json:"category"`
	MatchCount    int                    `json:"match_count"`
	Path          string                 `json:"path"`
	Method        string                 `json:"method"`
	SourceIP      string                 `json:"source_ip"`
	UserAgent     string                 `json:"user_agent"`
	Matches       []security.ThreatMatch `json:"matches,omitempty"`
	LambdaRequest string                 `json:"lambda_request_id,omitempty"`
	FunctionName  string                 `json:"function_name,omitempty"`
}

// LogSecurityEvent writes a structured security event to stdout, which
// CloudWatch captures as a log entry. Only call this in Lambda mode.
func LogSecurityEvent(method, path, srcIP, ua string, matches []security.ThreatMatch) {
	if !isLambdaRuntime() {
		return
	}

	severity := security.HighestSeverity(matches)

	evt := SecurityEvent{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Event:         "security.threat",
		Severity:      severity.String(),
		Category:      dominantCategory(matches),
		MatchCount:    len(matches),
		Path:          path,
		Method:        method,
		SourceIP:      srcIP,
		UserAgent:     ua,
		Matches:       truncateMatches(matches, 5),
		LambdaRequest: os.Getenv("AWS_REQUEST_ID"),
		FunctionName:  os.Getenv("AWS_LAMBDA_FUNCTION_NAME"),
	}

	data, _ := json.Marshal(evt)
	fmt.Fprintln(os.Stdout, string(data))

	// Also emit via utilities so the structured block logger picks it up.
	utilities.Logf("Security", evt.Category, utilities.ERROR, "THREAT", 0,
		fmt.Sprintf("severity=%s", evt.Severity),
		fmt.Sprintf("path=%s", evt.Path),
		fmt.Sprintf("source=%s", evt.SourceIP),
		fmt.Sprintf("matches=%d", evt.MatchCount),
		fmt.Sprintf("method=%s", evt.Method),
	)
}

// EmitSecurityMetric emits a zero-dimensional CloudWatch metric for
// threat counting. This is a lightweight alternative to metric filters
// when the Lambda has cloudwatch:PutMetricData permission.
//
// Metric namespace: AuthGate/Security
// Metric name:     ThreatDetected
// Dimensions:      Category, Severity
func EmitSecurityMetric(matches []security.ThreatMatch) {
	if !isLambdaRuntime() {
		return
	}
	// CloudWatch Embedded Metric Format (EMF) — printed to stdout, the
	// CloudWatch agent or Lambda extension picks it up automatically.
	severity := security.HighestSeverity(matches)
	cat := dominantCategory(matches)

	emf := map[string]interface{}{
		"_aws": map[string]interface{}{
			"Timestamp": time.Now().UTC().UnixMilli(),
			"CloudWatchMetrics": []map[string]interface{}{
				{
					"Namespace":  "AuthGate/Security",
					"Dimensions": [][]string{{"Category", "Severity"}},
					"Metrics":    []map[string]string{{"Name": "ThreatDetected", "Unit": "Count"}},
				},
			},
		},
		"Category":       cat,
		"Severity":        severity.String(),
		"ThreatDetected":  1,
		"FunctionName":    os.Getenv("AWS_LAMBDA_FUNCTION_NAME"),
		"MatchCount":      len(matches),
	}
	data, _ := json.Marshal(emf)
	fmt.Fprintln(os.Stdout, string(data))
}

// ── helpers ──

func dominantCategory(matches []security.ThreatMatch) string {
	if len(matches) == 0 {
		return "NONE"
	}
	counts := map[string]int{}
	for _, m := range matches {
		counts[m.Category]++
	}
	best := ""
	bestN := 0
	for cat, n := range counts {
		if n > bestN {
			bestN = n
			best = cat
		}
	}
	return best
}

func truncateMatches(matches []security.ThreatMatch, max int) []security.ThreatMatch {
	if len(matches) <= max {
		return matches
	}
	return matches[:max]
}

// ── CloudWatch Logs Insights queries (copy-paste into console) ──
//
// Threat timeline (last 1h):
//
//	fields @timestamp, severity, category, path, source_ip
//	| filter event = "security.threat"
//	| sort @timestamp desc
//	| limit 100
//
// Threats by severity:
//
//	fields severity, count(*) as cnt
//	| filter event = "security.threat"
//	| stats count(*) by severity
//	| sort cnt desc
//
// Top attacking IPs:
//
//	fields source_ip, count(*) as cnt
//	| filter event = "security.threat"
//	| stats count(*) by source_ip
//	| sort cnt desc
//	| limit 20
//
// SQL injection timeline:
//
//	fields @timestamp, path, source_ip, match_count
//	| filter category = "SQL_INJECTION"
//	| sort @timestamp desc
//	| limit 50

// ── Recommended CloudWatch Alarms ──
//
// Via AWS Console → CloudWatch → Alarms → Create alarm:
//
// 1. Critical Threat Alarm (page on-call immediately):
//    Metric:   AuthGate/Security > ThreatDetected
//    Filter:   { $.severity = "CRITICAL" }
//    Stat:     Sum, Period: 1 minute
//    Threshold: >= 1
//    Action:   SNS → PagerDuty / OpsGenie
//
// 2. High Threat Alarm (Slack notification):
//    Metric:   AuthGate/Security > ThreatDetected
//    Filter:   { $.severity = "HIGH" }
//    Stat:     Sum, Period: 5 minutes
//    Threshold: >= 3
//    Action:   SNS → Slack / Teams webhook
//
// 3. SQL Injection Spike:
//    Metric:   AuthGate/Security > ThreatDetected
//    Filter:   { $.category = "SQL_INJECTION" }
//    Stat:     Sum, Period: 1 minute
//    Threshold: >= 1
//    Action:   SNS → Security team email
//
// 4. Threat Volume Anomaly (unusual spike):
//    Metric:   AuthGate/Security > ThreatDetected
//    Stat:     Sum, Period: 5 minutes
//    Anomaly Detection band: 3 standard deviations
//    Action:   SNS → Security on-call

// ── Lambda log group recommended retention & export ──
//
//	log_group: /aws/lambda/authgate
//	retention: 90 days
//	export:    S3 (infrequent access) after 7 days
//	data_protection_policy: mask PII fields (email, ip_address)

// EnsureLogGroup is a no-op in Lambda — the execution role automatically
// creates /aws/lambda/<function-name> on first invocation. Kept for
// documentation completeness.
func EnsureLogGroup() {}

// LogStartupInfo emits a one-time structured startup block containing
// function metadata — useful for correlating cold starts with threats.
func LogStartupInfo() {
	if !isLambdaRuntime() {
		return
	}

	fields := []string{
		fmt.Sprintf("function_name=%s", os.Getenv("AWS_LAMBDA_FUNCTION_NAME")),
		fmt.Sprintf("function_version=%s", os.Getenv("AWS_LAMBDA_FUNCTION_VERSION")),
		fmt.Sprintf("log_group=/aws/lambda/%s", os.Getenv("AWS_LAMBDA_FUNCTION_NAME")),
		fmt.Sprintf("region=%s", os.Getenv("AWS_REGION")),
		fmt.Sprintf("memory=%s", os.Getenv("AWS_LAMBDA_FUNCTION_MEMORY_SIZE")),
		fmt.Sprintf("runtime=%s", os.Getenv("AWS_EXECUTION_ENV")),
	}
	utilities.Logf("Lambda", "ColdStart", utilities.INFO, "STARTUP", 0, fields...)

	// Print a reminder about log configuration.
	fmt.Fprintf(os.Stdout,
		`{"event":"startup","message":"CloudWatch security logging active","function":"%s","version":"%s","severity_filter":"WARN+","retention_recommendation":"90d"}`+"\n",
		os.Getenv("AWS_LAMBDA_FUNCTION_NAME"),
		os.Getenv("AWS_LAMBDA_FUNCTION_VERSION"),
	)
}

// LogThreatSummary emits a periodic summary of threat counts. Lambda
// is stateless, so this runs per-invocation at the end of each request.
// For long-running functions, call this every N minutes via a goroutine.
func LogThreatSummary(path string, matchCount int, severity string) {
	if !isLambdaRuntime() {
		return
	}
	fmt.Fprintf(os.Stdout,
		`{"event":"security.summary","path":"%s","match_count":%d,"highest_severity":"%s","timestamp":"%s"}`+"\n",
		path, matchCount, severity, time.Now().UTC().Format(time.RFC3339),
	)
}

// ── Verbose request logging ──

// LogVerboseRequest emits a detailed request log entry for debugging
// and audit trails. Only call when LOG_LEVEL=DEBUG or VVERBOSE.
func LogVerboseRequest(method, path, srcIP, ua string, headers map[string]string, body string) {
	if !isLambdaRuntime() {
		return
	}

	redactedHeaders := make(map[string]string, len(headers))
	for k, v := range headers {
		if strings.EqualFold(k, "authorization") || strings.EqualFold(k, "x-api-key") {
			redactedHeaders[k] = maskValue(v)
		} else {
			redactedHeaders[k] = v
		}
	}

	entry := map[string]interface{}{
		"event":     "request.verbose",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"method":    method,
		"path":      path,
		"source_ip": srcIP,
		"user_agent": ua,
		"headers":   redactedHeaders,
		"body_len":  len(body),
	}

	data, _ := json.Marshal(entry)
	fmt.Fprintln(os.Stdout, string(data))
}

func maskValue(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:8] + "...[REDACTED]"
}
