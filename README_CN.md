# AuthGate

多云统一认证网关。一套 Go 代码，本地开发、AWS Lambda、Alibaba Cloud FC 三种环境共用同一路由表，零配置切换。

Go 1.26 · RS256 JWT · DynamoDB / TableStore · S3 / OSS · API Gateway / FC HTTP Trigger

> [English Documentation](README.md)

## 架构

采用 **Ports & Adapters（六边形架构）** 模式：`service.Routes` 是核心端口，`aws/` 和 `aliyun/` 各自实现适配器，将云平台事件格式转成标准 `http.HandlerFunc`。

```
                        ┌──────────────────────────┐
                        │     service.Routes       │  ← 端口 (唯一真相源)
                        │  7 条路由，所有环境共用    │
                        └─────┬──────────┬─────────┘
                              │          │
              ┌───────────────┘          └───────────────┐
              ▼                                          ▼
┌──────────────────────────┐           ┌──────────────────────────┐
│      aws/lambda.go        │           │    aliyun/functions.go   │  ← 适配器
│  API Gateway Proxy Event  │           │    FC HTTP Trigger       │
│  → http.Request           │           │  → http.ResponseWriter   │
└──────────────────────────┘           └──────────────────────────┘
              │                                          │
              └────────────────┬─────────────────────────┘
                               ▼
              ┌────────────────────────────────┐
              │  handler (业务逻辑)              │
              │  register / login / refresh /   │
              │  logout / provider              │
              ├────────────────────────────────┤
              │  model (数据结构)               │
              │  persistence (DynamoDB/TableStore)│
              └────────────────────────────────┘
```

### 启动流程

```
main()
  ├─ config.LoadConfigurationFile()         读取 config.toml
  ├─ Phase 1: aws.Initialize()              验证 IAM/STS 身份，填充 Account 单例
  │            aliyun.Initialize()           验证 RAM 身份
  ├─ authentication.EnsureKeys()            尝试 S3/OSS 下载 → 未找到 → 生成 RSA-2048
  │     ├─ Cloud: 生成后上传到 S3/OSS        下次启动直接用
  │     └─ Local: 仅内存，不碰云存储
  ├─ Phase 2: aws.InitializeLambdaService()  Lambda 模式 → lambda.Start() 阻塞
  │            aliyun.InitializeFCService()   FC 模式 → fc.StartHttp() 阻塞
  ├─ handler.PersistUserFunc = ...          注入持久化回调
  ├─ handler.LookupUserFunc  = ...          注入查询回调
  └─ service.StartLocalServer()             Local 模式 → net/http :8000
```

### 环境检测

| 环境变量 | 含义 | 行为 |
|---|---|---|
| `_LAMBDA_SERVER_PORT` + `AWS_LAMBDA_RUNTIME_API` | AWS Lambda 运行时 | `lambda.Start()` 阻塞，注册 `HandleAPIGatewayEvent` |
| `FC_FUNCTION_NAME` | 阿里云 FC 运行时 | `fc.StartHttp()` 阻塞，注册 `fcHTTPHandler` |
| 以上皆无 | 本地开发 | `net/http` 监听 `0.0.0.0:8000` |

### 请求生命周期（以 `/auth/register` 为例）

```
Client → API Gateway → Lambda Invoke
                           │
  APIGatewayEvent {         ▼
    httpMethod: "POST"     HandleAPIGatewayEvent()
    path: "/auth/register"   ├─ event → http.Request (还原标准请求)
    body: "{...}"            ├─ service.MatchRoute(path) → handler.AuthRegister
  }                          │    ├─ json.Decode(body) → model.User
                             │    ├─ Registration() → 校验 → JWT.Sign(RS256)
                             │    ├─ PersistUserFunc() → DynamoDB PutItem
                             │    └─ json.Encode(model.Response{...})
                             └─ apiGatewayResponse() → {statusCode, headers, body}
                                  │
Client ← HTTP 200 ← API Gateway  ◄
```

## 项目结构

```
AuthGate/
├── main.go                        入口，启动编排
├── config.toml / config.toml.example  运行时配置
├── go.mod / go.sum                依赖管理
├── postman_collection.json        Postman 测试集合
│
└── internal/
    ├── model/                     领域模型（纯数据，零依赖）
    │   ├── user.go                User (GORM)
    │   ├── jwt.go                 JWT claims, Sign(), Validate(), NewAccessToken()
    │   ├── response.go            Response, JwtResponse, Actor, 安全头常量
    │   ├── request.go             RequestHttpHeader, EmailPasswordAuthRequest
    │   ├── provider.go            CloudPlatform 枚举 (10 种云平台)
    │   ├── auth_provider.go       AuthProvider 枚举 (8 种第三方登录)
    │   ├── credentials.go         AWSAuthorisationKeys, AliyunAuthorisationKeys
    │   ├── keys.go                PrivateKey / PublicKey 全局单例
    │   └── handler.go             APIGatewayEvent
    │
    ├── config/                    配置层
    │   ├── get_configuration.go   TOML 解析 (BurntSushi/toml)
    │   └── get_server.go          Addr, 路径常量 (7 条路由)
    │
    ├── handler/                   HTTP handlers + 业务逻辑
    │   ├── handler.go             Index, Health, AuthRegister, AuthLogin,
    │   │                          AuthLogout, AuthRefresh, AuthWithProvider
    │   ├── register.go            Registration() — 校验 + JWT 签发
    │   ├── login.go               Login() — 查库校验 + JWT 签发
    │   ├── refresh.go             Refresh() + ValidateAccessToken()
    │   └── provider.go            AuthenticateWithProvider() — 8 种第三方
    │
    ├── service/                   服务编排
    │   └── server.go              Routes (唯一路由表), MatchRoute(),
    │                              IsLocalMode(), StartLocalServer()
    │
    ├── authentication/            密钥管理
    │   └── get_keys.go            EnsureKeys() — 下载/生成/上传 RSA 密钥
    │
    ├── security/                  安全工具
    │   ├── credential.go          AWSCredentials(), AliyunCredentials(), KeysConfig()
    │   ├── keygen.go              GenerateRSAKeyPair(), ParsePrivateKeyPEM()
    │   └── signature.go           PKCE: ComputeCodeChallenge(), ValidateCodeVerifier()
    │
    ├── persistence/               持久化桥接层
    │   └── db.go                  LookupUser(), PersistUser() — 自动检测 DynamoDB/TableStore
    │
    ├── aws/                       AWS 适配器
    │   ├── authorisation.go       Account 单例, Initialize(), GetAccount(), Ready()
    │   ├── lambda.go              HandleAPIGatewayEvent(), apiGatewayResponse()
    │   ├── dynamodb.go            Insert, GetById, Update, DeleteById
    │   ├── s3.go                  GetObject, PutObject, ListObjects, PresignedURL
    │   └── cloudwatch.go          CloudWatch 集成
    │
    ├── aliyun/                    阿里云适配器
    │   ├── authorisation.go       Account 单例, Initialize(), GetAccount(), Ready()
    │   ├── functions.go           fcHTTPHandler(), InitializeFCService()
    │   ├── tablestore.go          Insert, GetById, Update, DeleteById
    │   ├── oss.go                 GetObject, PutObject, ListObjects
    │   └── cloudmonitor.go        云监控集成
    │
    └── utilities/                 工具
        └── logger.go              结构化日志, CloudWatch 兼容, ANSI 彩色输出
```

## 快速开始

### 前提

- Go ≥ 1.26
- （可选）AWS 账号 + IAM 密钥 — 用于 DynamoDB / S3
- （可选）阿里云账号 + RAM 密钥 — 用于 TableStore / OSS

### 本地开发（零依赖）

```bash
cp config.toml.example config.toml
go run main.go
```

输出：
```
[AuthGate@...]::INFO:: (Configuration loaded successfully:DecodeFile>>TASK-000::...)
[AuthGate@...]::INFO:: (auth:EnsureKeys>>...)  Progress=local mode — keys kept in memory only
[AuthGate@...]::INFO:: (HTTP:Starting local server>>...)  Progress=0.0.0.0:8000
```

此时 RSA-2048 密钥对已在内存中生成，所有端点可用，无需任何云服务。

### 连接云服务

编辑 `config.toml`，填入真实凭证：

```toml
[supported_providers]
aws = true

[aws]
region = "us-east-1"
access_key_id = "AKIA..."
access_key_secret = "..."
bucket = "authgate-keys"          # S3 bucket 存放 .pem
dynamodb_table = "Users"          # DynamoDB 表存放用户
```

重启后启动流程自动：
1. 调用 STS `GetCallerIdentity` 验证 IAM
2. 从 S3 下载 `private.pem` / `public.pem`
3. 如果 S3 中没有 → 生成 RSA-2048 → 上传到 S3
4. 注册/登录时读写 DynamoDB `Users` 表

## API 参考

### 端点

| # | Method | Path | Auth | Body | → 200 | → 4xx |
|---|---|---|---|---|---|---|
| 1 | GET | `/` | — | — | `service, status` | — |
| 2 | GET | `/health` | — | — | `status: healthy` | — |
| 3 | POST | `/auth/register` | — | `User` JSON | JWT 响应 | 400/500 |
| 4 | POST | `/auth/login` | — | `EmailPasswordAuthRequest` | JWT 响应 | 401 |
| 5 | POST | `/auth/logout` | — | `access_token` | `logged out` | — |
| 6 | POST | `/auth/refresh` | — | `refresh_token` | 新 JWT 对 | 401 |
| 7 | POST | `/auth/provider/{name}` | — | `subject, email` | JWT 响应 | 401/400 |

### 注册

```bash
curl -X POST http://0.0.0.0:8000/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "Username": "alice",
    "Email": "alice@example.com",
    "Password": "secret123"
  }'
```

### 登录

```bash
curl -X POST http://0.0.0.0:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"secret123"}'
```

### 刷新令牌

```bash
curl -X POST http://0.0.0.0:8000/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"eyJ..."}'
```

### 第三方登录

支持的 provider 名称：

| 名称 | 平台 | 示例 subject |
|---|---|---|
| `google` | Google OAuth | `google-oauth2\|123` |
| `github` | GitHub OAuth | `github\|987654` |
| `weixin` | 微信 | `wechat-openid\|oAb...` |
| `weibo` | 微博 | `weibo\|uid` |
| `douyin` | 抖音 | `dy\|openid` |
| `tiktok` | TikTok | `tt\|openid` |
| `kuaishou` | 快手 | `ks\|openid` |
| `gitcode` | GitCode | `gitcode\|uid` |

```bash
curl -X POST http://0.0.0.0:8000/auth/provider/google \
  -H 'Content-Type: application/json' \
  -d '{"subject":"google-oauth2|123","email":"alice@gmail.com"}'
```

### 成功响应

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

### 错误响应

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

## 配置参考

```toml
title = "AuthGate"

[server]
host = "0.0.0.0"
port = 8000

# 启用哪些云平台（至少一个为 true）
[supported_providers]
aws = true
aliyun = true
azure = false
gcp = false
tencent_cloud = false

# AWS 凭证（IAM 用户需有 S3 + DynamoDB + STS 权限）
[aws]
region = "us-east-1"
access_key_id = "AKIA..."
access_key_secret = "..."
bucket = "authgate-keys"          # 存放 private.pem / public.pem
dynamodb_table = "Users"          # Hash Key: username (String)

# 阿里云凭证（RAM 用户需有 OSS + TableStore + RAM 权限）
[aliyun]
region = "cn-hangzhou"
access_key_id = "LTAI..."
access_key_secret = "..."
bucket = "authgate-keys"
endpoint = "oss-cn-hangzhou.aliyuncs.com"
tablestore_instance = "authgate"
tablestore_table = "Users"        # Primary Key: username (String)

# JWT 签名密钥在对象存储中的路径
[keys]
private_key_path = "private.pem"
public_key_path = "public.pem"

# MySQL（预留，当前未使用）
[database]
host = "localhost"
port = 3306
user = "root"
password = "..."
dbname = "authgate"
max_connections = 50
max_idle_connections = 10
```

### 最小 IAM 权限（AWS）

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

## 部署

### AWS Lambda + API Gateway

```bash
# 构建
GOOS=linux GOARCH=arm64 go build -o bootstrap main.go
zip deployment.zip bootstrap

# 上传到 Lambda 控制台或通过 CLI
aws lambda update-function-code \
  --function-name authgate \
  --zip-file fileb://deployment.zip

# API Gateway 配置：
#   - 类型：REST API 或 HTTP API
#   - 集成：Lambda Proxy Integration
#   - 路由：/{proxy+} → authgate function
```

Lambda 启动时自动：
- 通过 IAM Role 获取临时凭证（无需在 config.toml 填密钥）
- 从 S3 下载 `.pem` 密钥，首次运行自动生成并上传
- 接受 API Gateway 代理事件，通过 `service.Routes` 分发

### Alibaba Cloud FC

```bash
GOOS=linux GOARCH=amd64 go build -o main main.go
zip function.zip main

# 上传到 FC 控制台
# 触发器：HTTP 触发器，认证方式：匿名
# 运行时：Custom Runtime (Go)
```

### 本地构建与测试

```bash
go build -o authgate main.go
./authgate
```

### Postman 测试集合

导入 `postman_collection.json`，包含所有 7 个端点的请求模板和测试脚本。

## JWT 安全设计

| 特性 | 实现 |
|---|---|
| 签名算法 | RS256（RSA 2048-bit） |
| Access Token 有效期 | 3600s（1 小时） |
| Refresh Token 有效期 | 604800s（7 天） |
| Token 绑定 | `ip_address` + `user_agent` 写入 claims |
| Scope 隔离 | access → `api:access`，refresh → `token:refresh` |
| 唯一标识 | `jti` — UUID，每条 token 唯一，支持黑名单 |
| 密钥存储 | S3/OSS 加密存储，本地模式仅内存 |

### 安全响应头

每个响应自动注入 15 个安全头：

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

## 设计决策

**为什么不是 DDD？** — AuthGate 的核心是认证（技术关注点），而非复杂业务领域。采用 Ports & Adapters 简化版：`service.Routes` 是端口，`aws/` / `aliyun/` 是适配器，`model/` 是共享内核。足够了。

**回调注入而非依赖反转？** — `handler.PersistUserFunc` 和 `handler.LookupUserFunc` 是函数指针而非接口。Go 中这种方式更轻量，避免 `handler` 包直接 import `aws`/`aliyun`/`persistence` 产生循环依赖。

**为什么是单一路由表？** — 本地开发、Lambda、FC 三种环境共用 `service.Routes`。加一个新端点只需在一处定义，三个环境自动生效。

**为什么密码明文存储？** — 当前版本明文写入 DynamoDB/TableStore。生产环境应改为 bcrypt 哈希。这是下一步要做的事。

## 技术栈

| 依赖 | 用途 |
|---|---|
| `github.com/golang-jwt/jwt/v5` | JWT RS256 签名与验证 |
| `github.com/google/uuid` | JTI 生成 |
| `github.com/BurntSushi/toml` | TOML 配置解析 |
| `github.com/aws/aws-sdk-go-v2` | AWS Lambda, DynamoDB, S3, STS |
| `github.com/aws/aws-lambda-go` | Lambda 运行时 |
| `github.com/aliyun/alibaba-cloud-sdk-go` | 阿里云 STS |
| `github.com/aliyun/aliyun-oss-go-sdk` | 阿里云 OSS |
| `github.com/aliyun/aliyun-tablestore-go-sdk` | 阿里云 TableStore |
| `github.com/aliyun/fc-runtime-go-sdk` | 阿里云 FC 运行时 |
| `gorm.io/gorm` | ORM（MySQL 预留） |
