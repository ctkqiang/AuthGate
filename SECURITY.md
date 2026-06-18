# Security Policy

## Threat Model

AuthGate is an authentication gateway deployed at the edge (API Gateway / FC HTTP Trigger).
It handles user identity, credential storage, JWT issuance, and abuse detection.

### Assets Protected

| Asset | Storage | Encryption |
|---|---|---|
| User passwords | DynamoDB / TableStore | bcrypt (cost=12) |
| JWT signing keys | S3 / OSS (SSE) | RSA-2048, local mode in-memory only |
| Access tokens | Client-side | RS256 signed, 3600s TTL |
| Refresh tokens | Client-side | RS256 signed, 604800s TTL, revocable |

### Threat Detection (13 categories, ~90 regexes)

| Category | Severity | Detection |
|---|---|---|
| SQL Injection | CRITICAL | SQL keywords, tautologies, time-based, stored procedures |
| Command Injection | CRITICAL | Shell separators + system binaries, subshells |
| XSS | HIGH | Script tags, event handlers, javascript: URIs |
| Path Traversal | HIGH | Directory backtracking, system paths |
| SSRF | HIGH | Metadata endpoints, loopback addresses |
| Sensitive File Probing | HIGH | .env, .git/, SSH keys, config files |
| Directory Brute-force | MEDIUM | Admin panels, actuators, DevOps tools |
| NoSQL Injection | HIGH | MongoDB operators |
| XML/XXE Attack | HIGH | Entity declarations, CDATA |
| CSRF/Cross-Origin | MEDIUM | Form action patterns |
| Header Injection | MEDIUM | CRLF + response header patterns |
| Scanner User-Agent | LOW | sqlmap, nikto, burp, nmap, etc. |
| Rate Burst | HIGH/CRITICAL | Sliding window: 100/500/1000/5000 req/60s |

### Rate Limiting

| Threshold | Scope | Action |
|---|---|---|
| >= 100 req/60s | Same IP to same path | HTTP 429 (HIGH) |
| >= 500 req/60s | Same IP (all paths) | HTTP 429 (HIGH) |
| >= 1,000 req/60s | Same path (all IPs) | HTTP 429 (MEDIUM) |
| >= 5,000 req/60s | Global | HTTP 429 (CRITICAL alert) |

### Security Headers (every response)

```
Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options,
X-Frame-Options, Referrer-Policy, Permissions-Policy,
Cross-Origin-Resource-Policy, Cross-Origin-Embedder-Policy,
Cross-Origin-Opener-Policy, CORS headers
```

## Known Limitations

| Issue | Risk | Mitigation |
|---|---|---|
| Plaintext passwords (before bcrypt upgrade) | Credential leak | Upgraded to bcrypt cost=12 |
| Stateless JWT — logout does not invalidate tokens pre-blacklist | Token reuse | JTI blacklist implemented |
| Detection-only (threats not blocked) | Attack succeeds | WAF layer handles blocking |
| No MFA | Account takeover | Planned |

## Reporting

Report security issues to the project maintainer. Do NOT open a public issue.

## Dependency Versions

| Dependency | Version | CVE Status |
|---|---|---|
| golang-jwt/jwt | v5.3.1 | Clear |
| golang.org/x/crypto | v0.53.0 | Clear |
| aws-sdk-go-v2 | v1.42.0 | Clear |
| alibaba-cloud-sdk-go | v1.63.107 | Clear |

Last audited: 2026-06-18
