# session-auth-core-go

本地会话认证与访问控制核心库：以**内存状态**与**本地生成的 HMAC 签名密钥**模拟真实登录链路，
让「令牌轮换、并发访问、会话失效、权限收回、频率限制」在各入口下得到**一致且可解释**的结论。

- 无外部依赖（不连数据库 / IdP / Redis），仅用 Go 标准库。
- 代码位于 `internal/auth`，可运行的串演入口在 `cmd/demo`。

---

## 1. 模型总览

### 1.1 用户与会话

| 对象 | 关键字段 | 说明 |
|---|---|---|
| `User` | `username, role, salt, passwordHash` | 口令以随机 salt + SHA-256 保存在内存，使用恒定时间比较 |
| `Session` | `id, username, role, scopes, refreshJTI, revoked, revokeReason` | 一条「会话链」的**实时状态**，所有判定最终回到这里 |

一次 `Login` 成功创建一条会话，并签发一对凭据：

- **访问凭据 access token（v2）**：默认 15 分钟有效，携带 `sub / sid / role / jti`；
- **刷新凭据 refresh token（v2）**：默认 24 小时有效，携带 `sid` 与唯一标识 `jti`。

凭据格式为三段式 `ver.<base64(payload)>.<HMAC-SHA256>`，签名密钥在进程内本地生成（可注入）。

### 1.2 角色与作用域（RBAC）

- `Policy` 维护静态的「角色 → 作用域集合」；登录时把角色的作用域**快照**到会话。
- **鉴权永远以会话上的实时作用域为准，而不是令牌内的快照**：
  因此 `RevokeScopes` 对既有会话**立即生效**，未过期的旧凭据也不会再获得已收回的能力。
- 未知角色、空作用域集合访问受保护资源时一律拒绝（**不默认放行**）。

内置作用域：`profile:read`、`profile:write`、`admin:read`、`admin:write`、`legacy:read`。

### 1.3 对外入口（`Service`）

| 方法 | 职责 |
|---|---|
| `Login(username, password, source)` | 校验账密，创建会话，签发凭据对 |
| `Refresh(refreshToken, source)` | 刷新凭据一次性轮换，重放即令会话链失效 |
| `Authorize(accessToken, requiredScope, source)` | 校验访问凭据并按实时作用域判定 |
| `RevokeSession(sessionID)` | 主动注销整条会话链 |
| `RevokeScopes(sessionID, scopes...)` | 实时收回作用域，对既有会话立即生效 |

---

## 2. 拒绝原因（归一化、可区分）

所有对外错误都是 `*AuthError`，错误码稳定可枚举，**不包含底层错误细节**：

| 错误码 | 触发情形 |
|---|---|
| `missing_credentials` | 入口未携带凭据 |
| `invalid_credentials` | 用户名/口令错误；凭据签名不符（被篡改）；格式无法解析；会话不存在 |
| `token_expired` | 凭据已过期（`now >= exp`） |
| `insufficient_scope` | 已认证但实时作用域不满足要求（含权限收回后再访问、v1 访问非兼容作用域） |
| `session_revoked` | 会话链已失效（管理员注销，或重放后用赢家凭据访问） |
| `refresh_token_reused` | 刷新凭据被重复 / 并发使用（jti 已轮换或 CAS 失败），会话链进入重放失效态 |
| `refresh_invalid` | 刷新入口收到非刷新类型凭据，或凭据不属于已知会话 |
| `rate_limited` | 同一账号或来源在窗口内尝试次数超过阈值，处于限制期 |
| `legacy_token_denied` | 旧格式(v1)凭据用在未开启兼容的访问入口，或用于刷新入口 |
| `internal_error` | 内部错误的统一归一化结果（底层 cause 只进服务端日志，不返回给调用方） |

---

## 3. 刷新轮换、并发与失效语义（核心）

刷新凭据**有且仅有一次有效**。会话保存「当前有效刷新凭据的 jti」，轮换通过
`MemoryStore.RotateRefresh` 的**原子 CAS**（`session.refreshJTI == oldJTI` 时才写入 newJTI）完成：

```
并发提交同一 refresh token（N 个请求）
        │
        ▼
   CAS(session.jti, oldJTI -> newJTI)   ← 互斥
   ├── 赢家 1 个：jti 轮换成功，签发新凭据对
   └── 输家 N-1 个：CAS 失败 / jti 不匹配
          └─ 返回 refresh_token_reused，并把会话链标记为 revoked(reason=reuse)
```

确定且可解释的结论（在 `-race` 下重复 20 次稳定）：

1. 同一刷新凭据无论并发还是串行重复提交，**恰好一个**请求成功；
2. 其余请求**全部**得到 `refresh_token_reused`，绝不出现两个赢家或静默成功；
3. 失效是**整条会话链**级别：发生重放后，即使是轮换赢家手上的新凭据，
   再访问得到 `session_revoked`、再刷新得到 `refresh_token_reused`，旧凭据也不会「复活」；
4. 管理员主动注销后，访问得到 `session_revoked`、刷新得到 `session_revoked`，
   与重放导致的失效（`refresh_token_reused`）原因**可区分**。

---

## 4. 频率限制

- 按「账号」与「来源」两个维度分别计数，固定窗口（默认窗口 1 分钟、阈值 5 次，可配置）。
- 语义确定：窗口内第 1..N 次尝试放行，**把计数推过阈值的第 N+1 次尝试本身即被拒绝**；
  处于限制期时返回 `rate_limited`，可通过 `RetryAfter` 得到剩余等待时间。
- 窗口自首次尝试起计时，经过窗口时长后下一次尝试自动开启新窗口（**限制解除后立即恢复正常**）。
- 登录成功会重置该账号/来源的计数；测试用可控时钟 `FakeClock` 推进时间验证恢复行为。

---

## 5. 旧格式(v1)兼容范围（默认不放行）

为兼容历史发行物，`TokenManager.IssueLegacy` 可签发 v1 凭据（无 `sid`、无 `jti`、无作用域列表）。
其兼容语义**固定且稳定**，不随角色扩大：

| 场景 | 结论 |
|---|---|
| `Authorize` 且 `AllowLegacyAccess=false`（默认） | `legacy_token_denied`（**默认拒绝**） |
| `Authorize` 且 `AllowLegacyAccess=true`，请求 `legacy:read` | 放行，Principal 标记 `Legacy=true` |
| 同上，但请求任何其他作用域（含 admin/profile） | `insufficient_scope`（v1 永远只有固定 `legacy:read`） |
| `Refresh` 使用 v1 凭据 | `legacy_token_denied`（v1 不可参与轮换） |
| v1 凭据过期 | `token_expired` |

---

## 6. 错误归一化与可观测性

- 签名失败、base64/JSON 解析失败等内部哨兵错误只在包内使用；
  `Service` 通过 `mapParseError` / `normalizeError` 映射为上表错误码，
  **底层错误文本（如 HMAC/base64 细节）不会返回给调用方**。
- 每次入口调用都会输出审计日志：输入摘要（用户名、来源、所需作用域、**凭据指纹**而非明文）
  与判定依据（`basis=cas_win / jti_mismatch / live_scopes / session_revoked ...`），
  失败时带归一化错误码。测试中日志同时写入 `os.Stdout`，`go test -v` 可直接看到输入与判定依据。

---

## 7. 本地验证方法

```bash
# 全量单元测试（日志中打印每次调用的输入与判定依据）
go test -v ./...

# 竞态检测 + 高重复，验证并发轮换结论稳定可复现
go test -race -count=20 -run TestConcurrentRefresh ./...

# 串演登录 / 越权 / 轮换 / 重放失效 / 权限收回
go run ./cmd/demo
```

测试覆盖场景（`internal/auth/*_test.go`）：

- 并发刷新（32 goroutine）恰好一个赢家、其余 `refresh_token_reused`、会话链确定失效；
- 串行重放（更换来源）结论稳定、会话不复活；
- 越权访问、权限收回立即生效、管理员注销；
- 缺少凭据、凭据过期、凭据被篡改（翻转签名段）；
- 登录限流、窗口到期后恢复；
- v1 默认拒绝 / 开启后固定 `legacy:read` / 不能刷新；
- 未知内部错误归一化为 `internal_error` 且不泄漏底层细节。

## 8. 包结构

```
internal/auth/
  errors.go       归一化错误码与 AuthError
  clock.go        时钟抽象（SystemClock / FakeClock）
  token.go        HMAC v2 / v1 凭据的签发与解析
  store.go        并发安全的用户/会话内存存储与原子 CAS 轮换
  rbac.go         角色-作用域策略与实时作用域判定
  ratelimit.go    按账号/来源的固定窗口限流
  service.go      对外门面：登录/刷新/鉴权/注销/收回作用域 + 审计日志
cmd/demo/         本地可运行的链路串演
```
