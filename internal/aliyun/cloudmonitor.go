// Package aliyun (cloudmonitor.go) provides security-aware CloudMonitor
// logging with structured events and alarm-ready output for FC mode.
//
// CloudMonitor 日志服务 (SLS) 查询语法:
//
//	严重威胁:
//	  severity: CRITICAL
//
//	高危威胁:
//	  severity: HIGH
//
//	SQL 注入:
//	  category: SQL_INJECTION
//
//	威胁计数:
//	  event: security.threat | SELECT COUNT(*) AS total
//
// CloudMonitor 告警规则 (SLS 控制台 → 告警 → 创建):
//
//	阈值:  查询结果 >= 1 条/分钟
//	通知:  短信 / 邮件 / 钉钉 / 飞书 / Webhook
//	静默:  5 分钟
package aliyun

import (
	"authgate/internal/security"
	"authgate/internal/utilities"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// SecurityEvent is the structured payload emitted to SLS for every
// suspicious request detected in FC mode.
type SecurityEvent struct {
	Timestamp    string                 `json:"timestamp"`
	Event        string                 `json:"event"`
	Severity     string                 `json:"severity"`
	Category     string                 `json:"category"`
	MatchCount   int                    `json:"match_count"`
	Path         string                 `json:"path"`
	Method       string                 `json:"method"`
	SourceIP     string                 `json:"source_ip"`
	UserAgent    string                 `json:"user_agent"`
	Matches      []security.ThreatMatch `json:"matches,omitempty"`
	FCRequestID  string                 `json:"fc_request_id,omitempty"`
	FunctionName string                 `json:"function_name,omitempty"`
	ServiceName  string                 `json:"service_name,omitempty"`
}

// LogSecurityEvent writes a structured security event to stdout for
// SLS collection. Only call this in FC mode.
func LogSecurityEvent(method, path, srcIP, ua string, matches []security.ThreatMatch) {
	if !isFCRuntime() {
		return
	}

	severity := security.HighestSeverity(matches)
	cat := dominantCategory(matches)

	evt := SecurityEvent{
		Timestamp:    time.Now().Format(time.RFC3339),
		Event:        "security.threat",
		Severity:     severity.String(),
		Category:     cat,
		MatchCount:   len(matches),
		Path:         path,
		Method:       method,
		SourceIP:     srcIP,
		UserAgent:    ua,
		Matches:      truncateMatches(matches, 5),
		FCRequestID:  os.Getenv("FC_REQUEST_ID"),
		FunctionName: os.Getenv("FC_FUNCTION_NAME"),
		ServiceName:  os.Getenv("FC_SERVICE_NAME"),
	}

	data, _ := json.Marshal(evt)
	fmt.Fprintln(os.Stdout, string(data))

	utilities.Logf("Security", cat, utilities.ERROR, "THREAT", 0,
		fmt.Sprintf("severity=%s", evt.Severity),
		fmt.Sprintf("path=%s", evt.Path),
		fmt.Sprintf("source=%s", evt.SourceIP),
		fmt.Sprintf("matches=%d", evt.MatchCount),
		fmt.Sprintf("method=%s", evt.Method),
	)
}

// LogStartupInfo emits a one-time structured startup block for FC cold
// starts, including service metadata for log correlation.
func LogStartupInfo() {
	if !isFCRuntime() {
		return
	}

	fields := []string{
		fmt.Sprintf("service_name=%s", os.Getenv("FC_SERVICE_NAME")),
		fmt.Sprintf("function_name=%s", os.Getenv("FC_FUNCTION_NAME")),
		fmt.Sprintf("function_version=%s", os.Getenv("FC_FUNCTION_VERSION")),
		fmt.Sprintf("region=%s", os.Getenv("FC_REGION")),
		fmt.Sprintf("account_id=%s", os.Getenv("FC_ACCOUNT_ID")),
	}
	utilities.Logf("FC", "ColdStart", utilities.INFO, "STARTUP", 0, fields...)

	fmt.Fprintf(os.Stdout,
		`{"event":"startup","message":"CloudMonitor security logging active","service":"%s","function":"%s","region":"%s"}`+"\n",
		os.Getenv("FC_SERVICE_NAME"),
		os.Getenv("FC_FUNCTION_NAME"),
		os.Getenv("FC_REGION"),
	)
}

// LogThreatSummary emits a per-request threat summary.
func LogThreatSummary(path string, matchCount int, severity string) {
	if !isFCRuntime() {
		return
	}
	fmt.Fprintf(os.Stdout,
		`{"event":"security.summary","path":"%s","match_count":%d,"highest_severity":"%s","timestamp":"%s"}`+"\n",
		path, matchCount, severity, time.Now().Format(time.RFC3339),
	)
}

// LogVerboseRequest emits a detailed request audit log for debugging.
func LogVerboseRequest(method, path, srcIP, ua string, headers map[string]string, body string) {
	if !isFCRuntime() {
		return
	}

	redactedHeaders := make(map[string]string, len(headers))
	for k, v := range headers {
		if k == "authorization" || k == "x-api-key" || k == "x-fc-access-key-secret" {
			redactedHeaders[k] = maskValue(v)
		} else {
			redactedHeaders[k] = v
		}
	}

	entry := map[string]interface{}{
		"event":     "request.verbose",
		"timestamp": time.Now().Format(time.RFC3339),
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

func maskValue(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:8] + "...[REDACTED]"
}

// ── SLS 查询示例 (粘贴到阿里云日志服务控制台) ──
//
// 最近 1 小时威胁时间线:
//
//	event: security.threat
//	| SELECT timestamp, severity, category, path, source_ip
//	ORDER BY timestamp DESC
//	LIMIT 100
//
// 按严重程度统计:
//
//	event: security.threat
//	| SELECT severity, COUNT(*) AS cnt
//	GROUP BY severity
//	ORDER BY cnt DESC
//
// Top 攻击 IP:
//
//	event: security.threat
//	| SELECT source_ip, COUNT(*) AS cnt
//	GROUP BY source_ip
//	ORDER BY cnt DESC
//	LIMIT 20
//
// SQL 注入时间线:
//
//	category: SQL_INJECTION
//	| SELECT timestamp, path, source_ip, match_count
//	ORDER BY timestamp DESC
//	LIMIT 50

// ── CloudMonitor 推荐告警规则 ──
//
// 1. 严重威胁告警 (立即电话通知):
//    查询:    severity: CRITICAL | SELECT COUNT(*) AS cnt
//    触发:    cnt >= 1
//    周期:    1 分钟
//    通知:    电话 + 短信 + 飞书
//
// 2. 高危威胁告警 (飞书/钉钉通知):
//    查询:    severity: HIGH | SELECT COUNT(*) AS cnt
//    触发:    cnt >= 3
//    周期:    5 分钟
//    通知:    飞书群机器人 Webhook
//
// 3. SQL 注入告警:
//    查询:    category: SQL_INJECTION | SELECT COUNT(*) AS cnt
//    触发:    cnt >= 1
//    周期:    1 分钟
//    通知:    安全团队邮件
//
// 4. 威胁数量异常 (异常检测):
//    查询:    event: security.threat | SELECT COUNT(*) AS cnt
//    触发:    动态阈值 (3σ 偏离)
//    周期:    5 分钟
//    通知:    安全值班飞书群
