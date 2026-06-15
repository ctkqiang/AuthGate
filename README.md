# AuthGate

Multi-cloud unified authentication gateway. One Go codebase, three runtime environments — local development, AWS Lambda, Alibaba Cloud FC — sharing a single route table with zero-config switching.

Go 1.26 · RS256 JWT · DynamoDB / TableStore · S3 / OSS · API Gateway / FC HTTP Trigger

> [中文文档](README_CN.md)

## Architecture

**Ports & Adapters pattern**: `service.Routes` is the core port; `aws/` and `aliyun/` each implement adapters that convert cloud-platform event formats into standard `http.HandlerFunc`.

```
                        ┌──────────────────────────┐
                        │     service.Routes       │  ← Port (single source of truth)
                        │  7 routes, all envs      │
                        └─────┬──────────┬─────────┘
                              │          │
              ┌───────────────┘          └───────────────┐
              ▼                                          ▼
┌──────────────────────────┐           ┌──────────────────────────┐
│      aws/lambda.go        │           │    aliyun/functions.go   │  ← Adapters
│  API Gateway Proxy Event  │           │    FC HTTP Trigger       │
│  → http.Request           │           │  → http.ResponseWriter   │
└──────────────────────────┘           └──────────────────────────┘
              │                                          │
              └────────────────┬─────────────────────────┘
                               ▼
              ┌────────────────────────────────┐
              │  handler (business logic)       │
              │  register / login / refresh /   │
              │  logout / provider              │
              ├────────────────────────────────┤
              │  model (data structures)        │
              │  persistence (DynamoDB/TableStore)│
              └────────────────────────────────┘
```

![Architecture — Ports & Adapters](out/docs/architecture_EN/architecture.png)

### Startup Flow

```
main()
  ├─ config.LoadConfigurationFile()         reads config.toml
  ├─ Phase 1: aws.Initialize()             verifies IAM/STS, populates Account singleton
  │            aliyun.Initialize()          verifies RAM identity
  ├─ authentication.EnsureKeys()           tries S3/OSS download → not found → gen RSA-2048
  │     ├─ Cloud: upload to S3/OSS         available on next boot
  │     └─ Local: in-memory only           never touches cloud storage
  ├─ Phase 2: aws.InitializeLambdaService() Lambda mode → lambda.Start() blocks
  │            aliyun.InitializeFCService()  FC mode → fc.StartHttp() blocks
  ├─ handler.PersistUserFunc = ...         inject persistence callback
  ├─ handler.LookupUserFunc  = ...         inject lookup callback
  └─ service.StartLocalServer()            Local mode → net/http :8000
```

![Startup Sequence](out/docs/startup_EN/startup.png)

### Environment Detection

| Env Vars | Meaning | Behavior |
|---|---|---|
| `_LAMBDA_SERVER_PORT` + `AWS_LAMBDA_RUNTIME_API` | AWS Lambda runtime | `lambda.Start()` blocks, registers `HandleAPIGatewayEvent` |
| `FC_FUNCTION_NAME` | Alibaba Cloud FC runtime | `fc.StartHttp()` blocks, registers `fcHTTPHandler` |
| Neither | Local development | `net/http` listens on `0.0.0.0:8000` |

### Request Lifecycle (`POST /auth/register`)

```
Client → API Gateway → Lambda Invoke
                           │
  APIGatewayEvent {         ▼
    httpMethod: "POST"     HandleAPIGatewayEvent()
    path: "/auth/register"   ├─ event → http.Request (reconstruct)
    body: "{...}"            ├─ service.MatchRoute(path) → handler.AuthRegister
  }                          │    ├─ json.Decode(body) → model.User
                             │    ├─ Registration() → validate → JWT.Sign(RS256)
                             │    ├─ PersistUserFunc() → DynamoDB PutItem
                             │    └─ json.Encode(model.Response{...})
                             └─ apiGatewayResponse() → {statusCode, headers, body}
                                  │
Client ← HTTP 200 ← API Gateway  ◄
```

![Request Lifecycle](out/docs/request_lifecycle_EN/request_lifecycle.png)

## Project Structure

```
AuthGate/
├── main.go                       entry point, startup orchestration
├── config.toml / config.toml.example  runtime config
├── go.mod / go.sum               dependency management
├── postman_collection.json       Postman collection
│
└── internal/
    ├── model/                    domain models (pure data, zero deps)
    │   ├── user.go               User (GORM)
    │   ├── jwt.go                JWT claims, Sign(), Validate(), NewAccessToken()
    │   ├── response.go           Response, JwtResponse, Actor, security header constants
    │   ├── request.go            RequestHttpHeader, EmailPasswordAuthRequest
    │   ├── provider.go           CloudPlatform enum (10 cloud platforms)
    │   ├── auth_provider.go      AuthProvider enum (8 third-party logins)
    │   ├── credentials.go        AWSAuthorisationKeys, AliyunAuthorisationKeys
    │   ├── keys.go               PrivateKey / PublicKey global singletons
    │   └── handler.go            APIGatewayEvent
    │
    ├── config/                   configuration layer
    │   ├── get_configuration.go  TOML parsing (BurntSushi/toml)
    │   └── get_server.go         Addr, path constants (7 routes)
    │
    ├── handler/                  HTTP handlers + business logic
    │   ├── handler.go            Index, Health, AuthRegister, AuthLogin,
    │   │                         AuthLogout, AuthRefresh, AuthWithProvider
    │   ├── register.go           Registration() — validation + JWT issuance
    │   ├── login.go              Login() — DB lookup + password check + JWT
    │   ├── refresh.go            Refresh() + ValidateAccessToken()
    │   └── provider.go           AuthenticateWithProvider() — 8 providers
    │
    ├── service/                  service orchestration
    │   └── server.go             Routes (single route table), MatchRoute(),
    │                             IsLocalMode(), StartLocalServer()
    │
    ├── authentication/           key management
    │   └── get_keys.go           EnsureKeys() — download/generate/upload RSA keys
    │
    ├── security/                 security utilities
    │   ├── credential.go         AWSCredentials(), AliyunCredentials(), KeysConfig()
    │   ├── keygen.go             GenerateRSAKeyPair(), ParsePrivateKeyPEM()
    │   └── signature.go          PKCE: ComputeCodeChallenge(), ValidateCodeVerifier()
    │
    ├── persistence/              persistence bridge
    │   └── db.go                 LookupUser(), PersistUser() — auto-detect DynamoDB/TableStore
    │
    ├── aws/                      AWS adapters
    │   ├── authorisation.go      Account singleton, Initialize(), GetAccount(), Ready()
    │   ├── lambda.go             HandleAPIGatewayEvent(), apiGatewayResponse()
    │   ├── dynamodb.go           Insert, GetById, Update, DeleteById
    │   ├── s3.go                 GetObject, PutObject, ListObjects, PresignedURL
    │   └── cloudwatch.go         CloudWatch integration
    │
    ├── aliyun/                   Alibaba Cloud adapters
    │   ├── authorisation.go      Account singleton, Initialize(), GetAccount(), Ready()
    │   ├── functions.go          fcHTTPHandler(), InitializeFCService()
    │   ├── tablestore.go         Insert, GetById, Update, DeleteById
    │   ├── oss.go                GetObject, PutObject, ListObjects
    │   └── cloudmonitor.go       CloudMonitor integration
    │
    └── utilities/                utility
        └── logger.go             structured logging, CloudWatch-compatible, ANSI color
```

![Package Dependencies](out/docs/packages_EN/packages.png)

## Quick Start

### Prerequisites

- Go ≥ 1.26
- (Optional) AWS account + IAM keys — for DynamoDB / S3
- (Optional) Alibaba Cloud account + RAM keys — for TableStore / OSS

### Local Development (zero dependencies)

```bash
cp config.toml.example config.toml
go run main.go
```

Output:
```
[AuthGate@...]::INFO:: (Configuration loaded successfully:DecodeFile>>TASK-000::...)
[AuthGate@...]::INFO:: (auth:EnsureKeys>>...)  Progress=local mode — keys kept in memory only
[AuthGate@...]::INFO:: (HTTP:Starting local server>>...)  Progress=0.0.0.0:8000
```

RSA-2048 keys are generated in memory. All endpoints work with no cloud services.

### Connecting Cloud Services

Edit `config.toml` with real credentials:

```toml
[supported_providers]
aws = true

[aws]
region = "us-east-1"
access_key_id = "AKIA..."
access_key_secret = "..."
bucket = "authgate-keys"
dynamodb_table = "Users"
```

On restart the startup flow automatically:
1. Calls STS `GetCallerIdentity` to verify IAM
2. Downloads `private.pem` / `public.pem` from S3
3. If not found → generates RSA-2048 → uploads to S3
4. Reads/writes DynamoDB `Users` table for register/login

## API Reference

### Endpoints

| # | Method | Path | Auth | Body | → 200 | → 4xx |
|---|---|---|---|---|---|---|
| 1 | GET | `/` | — | — | `service, status` | — |
| 2 | GET | `/health` | — | — | `status: healthy` | — |
| 3 | POST | `/auth/register` | — | `User` JSON | JWT response | 400/500 |
| 4 | POST | `/auth/login` | — | `EmailPasswordAuthRequest` | JWT response | 401 |
| 5 | POST | `/auth/logout` | — | `access_token` | `logged out` | — |
| 6 | POST | `/auth/refresh` | — | `refresh_token` | new JWT pair | 401 |
| 7 | POST | `/auth/provider/{name}` | — | `subject, email` | JWT response | 401/400 |

### Register

```bash
curl -X POST http://0.0.0.0:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "Username": "alice",
    "Email": "alice@example.com",
    "Password": "secret123"
  }'
```

### Login

```bash
curl -X POST http://0.0.0.0:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"secret123"}'
```

### Refresh Token

```bash
curl -X POST http://0.0.0.0:8000/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"eyJ..."}'
```

### Third-Party Login

Supported providers:

| Name | Platform | Example Subject |
|---|---|---|
| `google` | Google OAuth | `google-oauth2\|123` |
| `github` | GitHub OAuth | `github\|987654` |
| `weixin` | WeChat | `wechat-openid\|oAb...` |
| `weibo` | Weibo | `weibo\|uid` |
| `douyin` | Douyin | `dy\|openid` |
| `tiktok` | TikTok | `tt\|openid` |
| `kuaishou` | Kuaishou | `ks\|openid` |
| `gitcode` | GitCode | `gitcode\|uid` |

```bash
curl -X POST http://0.0.0.0:8000/auth/provider/google \
  -H 'Content-Type: application/json' \
  -d '{"subject":"google-oauth2|123","email":"alice@gmail.com"}'
```

### Success Response

```json
{
  "status_code": 200,
  "signature": "",
  "event": null,
  "data": {
    "token": "eyJhbGciOiJSUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
    "expires_in": 3600,
    "event_type": "event.auth_register",
    "actor": {
      "idenitifier": "alice",
      "ip_address": "127.0.0.1:52079",
      "user_agent": "PostmanRuntime/7.53.0"
    }
  }
}
```

### Error Response

```json
{
  "status_code": 401,
  "signature": "",
  "event": null,
  "data": {
    "error": "invalid username or password"
  }
}
```

## Configuration

```toml
title = "AuthGate"

[server]
host = "0.0.0.0"
port = 8000

# Enabled cloud platforms (at least one must be true)
[supported_providers]
aws = true
aliyun = true
azure = false
gcp = false
tencent_cloud = false

# AWS credentials (IAM user needs S3 + DynamoDB + STS permissions)
[aws]
region = "us-east-1"
access_key_id = "AKIA..."
access_key_secret = "..."
bucket = "authgate-keys"          # stores private.pem / public.pem
dynamodb_table = "Users"          # Hash Key: username (String)

# Alibaba Cloud credentials (RAM user needs OSS + TableStore + RAM)
[aliyun]
region = "cn-hangzhou"
access_key_id = "LTAI..."
access_key_secret = "..."
bucket = "authgate-keys"
endpoint = "oss-cn-hangzhou.aliyuncs.com"
tablestore_instance = "authgate"
tablestore_table = "Users"        # Primary Key: username (String)

# JWT signing key paths in object storage
[keys]
private_key_path = "private.pem"
public_key_path = "public.pem"

# MySQL (reserved, not currently used)
[database]
host = "localhost"
port = 3306
user = "root"
password = "..."
dbname = "authgate"
max_connections = 50
max_idle_connections = 10
```

### Minimum IAM Policy (AWS)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "sts:GetCallerIdentity"
      ],
      "Resource": [
        "arn:aws:s3:::authgate-keys/*",
        "arn:aws:dynamodb:*:*:table/Users"
      ]
    }
  ]
}
```

## Deployment

### AWS Lambda + API Gateway

```bash
# Build
GOOS=linux GOARCH=arm64 go build -o bootstrap main.go
zip deployment.zip bootstrap

# Upload via console or CLI
aws lambda update-function-code \
  --function-name authgate \
  --zip-file fileb://deployment.zip

# API Gateway config:
#   - Type: REST API or HTTP API
#   - Integration: Lambda Proxy
#   - Route: /{proxy+} → authgate function
```

Lambda startup automatically:
- Obtains temporary credentials via IAM Role (no keys in config.toml needed)
- Downloads `.pem` keys from S3; auto-generates and uploads on first run
- Accepts API Gateway proxy events, dispatches via `service.Routes`

### Alibaba Cloud FC

```bash
GOOS=linux GOARCH=amd64 go build -o main main.go
zip function.zip main

# Upload via FC console
# Trigger: HTTP trigger, auth: anonymous
# Runtime: Custom Runtime (Go)
```

### Local Build

```bash
go build -o authgate main.go
./authgate
```

### Postman Collection

Import `postman_collection.json` — includes request templates and test scripts for all 7 endpoints.

![Deployment Topology](out/docs/deployment_EN/deployment.png)

## JWT Security

| Feature | Implementation |
|---|---|
| Signing Algorithm | RS256 (RSA 2048-bit) |
| Access Token TTL | 3600s (1 hour) |
| Refresh Token TTL | 604800s (7 days) |
| Token Binding | `ip_address` + `user_agent` in claims |
| Scope Isolation | access → `api:access`, refresh → `token:refresh` |
| Unique ID | `jti` — UUID per token, enables blacklisting |
| Key Storage | S3/OSS encrypted at rest; local mode in-memory only |

### Security Response Headers

Every response includes 15 security headers:

```
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; ...
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH
...
```

## Design Decisions

**Why not DDD?** — AuthGate is about authentication (a technical concern), not a complex business domain. The simplified Ports & Adapters approach is sufficient: `service.Routes` is the port, `aws/` / `aliyun/` are adapters, `model/` is the shared kernel.

**Callback injection over dependency inversion?** — `handler.PersistUserFunc` and `handler.LookupUserFunc` are function pointers rather than interfaces. This is lighter in Go and avoids import cycles between `handler`, `aws`/`aliyun`, and `persistence`.

**Why a single route table?** — Local dev, Lambda, and FC share `service.Routes`. Add an endpoint in one place, it works in all three environments.

**Plaintext passwords?** — The current version stores passwords as plaintext in DynamoDB/TableStore. Production should use bcrypt hashing. This is the next priority.

## Tech Stack

| Dependency | Purpose |
|---|---|
| `github.com/golang-jwt/jwt/v5` | JWT RS256 signing & verification |
| `github.com/google/uuid` | JTI generation |
| `github.com/BurntSushi/toml` | TOML config parsing |
| `github.com/aws/aws-sdk-go-v2` | AWS Lambda, DynamoDB, S3, STS |
| `github.com/aws/aws-lambda-go` | Lambda runtime |
| `github.com/aliyun/alibaba-cloud-sdk-go` | Alibaba Cloud STS |
| `github.com/aliyun/aliyun-oss-go-sdk` | Alibaba Cloud OSS |
| `github.com/aliyun/aliyun-tablestore-go-sdk` | Alibaba Cloud TableStore |
| `github.com/aliyun/fc-runtime-go-sdk` | Alibaba Cloud FC runtime |
| `gorm.io/gorm` | ORM (MySQL, reserved) |
