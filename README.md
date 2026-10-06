# session-auth-core-go

本地会话认证与访问控制核心：用内存状态与本地生成的 HMAC 签名密钥模拟真实登录链路，覆盖令牌轮换、并发访问与会话失效，所有入口给出一致且可解释的判定结论。

## 包结构

| 包 | 职责 |
|---|---|
| `auth` | 对外门面：登录、刷新、认证、鉴权、撤销、会话治理（上限淘汰/两层寿命/可见性/踢出）；统一归一化错误 |
| `autherr` | 归一化拒绝原因（见下表），底层错误不外泄 |
| `token` | 本地 HMAC 签名凭据（v2 信封）与旧格式 v1 的固定兼容语义 |
| `session` | 内存会话链存储；刷新凭据轮换为互斥锁下的 compare-and-swap；会话上限淘汰、空闲/绝对寿命、精确踢出 |
| `rbac` | 角色→作用域实时策略；收回立即生效 |
| `ratelimit` | 账号/来源两个维度的内存固定窗口限流 |

## 会话与权限模型

- **登录**：校验本地账号（加盐 SHA-256 口令摘要），按账号与来源两个维度各消耗一次限流配额，成功后创建会话链并签发访问/刷新凭据对。未知用户与错误口令返回相同的 `invalid_credential`，不泄露用户存在性。
- **凭据**：v2 信封 `b64(header).b64(payload).b64(HMAC-SHA256)`，由本地密钥签名。访问凭据携带 `sub/role/scp/sid/jti/iat/exp`；刷新凭据携带 `sub/role/sid/jti/iat/exp`。
- **会话链**：每次刷新轮换刷新凭据的 JTI，`Version` 单调递增。访问凭据绑定会话 ID，鉴权时会校验会话链状态（撤销/失效的会话即使凭据签名有效也会被拒绝）。
- **有效作用域** = 实时策略作用域 ∩ 凭据携带作用域。鉴权时按当前 `rbac.Policy` 求值，因此**权限收回后既有会话立即失去被收回的能力**；重新授予后无需重新登录即可恢复。

## 并发与失效语义

刷新凭据只能成功使用一次，轮换是会话存储内互斥锁保护的原子 compare-and-swap：

- 同一刷新凭据被并发或重复提交时，**恰好一个请求成功**；
- 其余提交了**已消费凭据**的请求统一得到 `refresh_replayed`，且整条会话链被置为 `invalid`（终态，粘性）；
- 此后用**轮换出的新凭据**访问已失效链得到 `session_invalid`——凭据本身未被消费，是链已死，两种原因可区分；
- 链失效后再次提交旧凭据仍是 `refresh_replayed`（凭据在已消费集合中），结论在竞态检测下稳定可复现；
- 显式撤销（按账号或按会话）置为 `revoked` 终态，同样不可再轮换、不可再鉴权。

## 会话治理（多设备/多来源并发登录）

治理规则由 `session.GovernanceConfig` 配置（`MaxActivePerSubject`、`IdleTTL`、`AbsoluteTTL`），经 `auth.Config` 的 `MaxActiveSessions/SessionIdleTTL/SessionAbsoluteTTL` 注入；不配置（或使用 `session.NewStore()`）时保持原有的无上限、无寿命语义，老调用方零改动。

- **每账号活跃上限与淘汰**：同一账号的活跃会话超过上限时，按 `LastActivityAt` 最久未活动者淘汰（平手再比建立时间、会话 ID，保证确定性）。被淘汰的会话进入终态 `evicted`，此后无论用它的访问凭据还是刷新凭据，统一得到 `session_evicted`——凭据签名仍然有效，是“被新会话挤出去”，不会被误判成凭据损坏（`invalid_credential`）、凭据过期（`credential_expired`）或权限不足（`permission_denied`）。淘汰是逐账号隔离的，A 账号永不挤占 B 账号。并发登录/续期/访问与淘汰都在存储内同一把锁的临界区完成，因此**最终活跃集合永不超过上限**，不会出现该留的被挤、该挤的还活着。
- **两层寿命**：
  - *空闲寿命*（`IdleTTL`）：自最近一次活动起算。鉴权（`Authenticate/Authorize`）与续期（`Refresh`）都算一次活动，会把空闲计时重置到当前时刻；超过空闲寿命无动静即失效，原因 `session_idle_expired`。到期时刻本身即视为到期。
  - *绝对寿命*（`AbsoluteTTL`）：自建立时刻 `CreatedAt` 起算的硬上限，反复续期、频繁活动都不能越过它；到点必须重新登录，原因 `session_absolute_expired`。两者同时到期时，绝对寿命优先。
  - 到期是惰性且原子的：在创建、`Touch`、轮换、列举时于锁内判定并一次性置终态，终态粘性、不可复活。
- **可见性**：`Service.ListSessions(subject)` 返回该账号当前活跃会话（`ID/Source/CreatedAt/LastActivityAt`），列举时一并结清已到期会话；只暴露治理视图，不泄露内部刷新 JTI。
- **精确踢出**：
  - `KickSession(sessionID)`：只终止指定的一条，终态 `kicked`，返回该 ID 是否存在；其它会话照旧可用。
  - `KeepOnlySession(subject, keepID)`：“只保留当前这条”，把同账号其它活跃会话一并踢掉，返回踢出条数；已处于终态的会话保留其原有、可区分的结论。
  - 被踢会话再次访问稳定得到 `session_kicked`。

四种会话级结局（`session_evicted` / `session_idle_expired` / `session_absolute_expired` / `session_kicked`）彼此可区分，也与 `credential_expired`（凭据自身到期，先于会话校验判定）以及 `refresh_replayed`（刷新凭据已消费）分开。原有按账号/按会话的 `Revoke` 仍映射到 `session_invalid`（`revoked`）。

## 拒绝原因一览（归一化，内部错误不外泄）

| Reason | 触发条件 |
|---|---|
| `missing_credential` | 未提供凭据 |
| `invalid_credential` | 格式错误、签名被篡改、类型不符、旧格式用于刷新、登录口令错误 |
| `credential_expired` | 凭据过期（到期时刻本身即视为过期） |
| `refresh_replayed` | 提交了已被消费的刷新凭据（并发失败者或重放）；会话已进入其它终态时该结论仍优先保留 |
| `session_invalid` | 会话链已失效/被撤销/不存在 |
| `session_evicted` | 账号活跃会话超上限，被更新的会话按最久未活动挤掉 |
| `session_idle_expired` | 超过空闲寿命且期间无鉴权/续期活动 |
| `session_absolute_expired` | 到达自建立起算的绝对寿命，续期也无法越过 |
| `session_kicked` | 被管理操作（精确踢出或“只保留当前”）主动踢掉 |
| `permission_denied` | 已认证但缺少所需作用域（含被收回、旧格式无作用域） |
| `rate_limited` | 账号或来源维度超出窗口配额 |
| `internal_error` | 其他内部失败；解析/签名校验的底层错误一律归一化为此类或上述业务原因，**原始错误文本不返回给调用方** |

## 兼容范围（旧格式 v1）

v1 线格式为 `b64(sub:role:expUnix).hex(HMAC)`，兼容语义固定且稳定：

- 有效 v1 凭据只认证身份（subject/role），**永不携带作用域**——任何作用域检查一律拒绝，不默认放行；
- 不绑定会话、**不能用于刷新**；
- 形状或签名不符一律 `invalid_credential`，不存在静默放行路径。

本次会话治理改动后，v1 的判定口径**保持不变**：因为不携带 `sid`、不绑定会话，它不受每账号活跃上限、空闲/绝对寿命、淘汰与踢出的任何影响，也永远不会产生 `session_evicted/session_idle_expired/session_absolute_expired/session_kicked`；其自身到期仍是 `credential_expired`。会话治理只作用于 v2 凭据绑定的会话链。

## 限流语义

固定窗口（默认 5 次/分钟，可配置），账号与来源两个维度独立计数：

- 窗口内前 N 次放行，之后拒绝并给出 `RetryAfter`；
- 窗口边界过后桶原子重置，行为与全新窗口完全一致（可预期恢复）；
- 登录的每次尝试（含口令错误）都消耗配额，防止暴力破解；刷新按来源+账号限流。

## 本地验证

```bash
# 构建与静态检查
go build ./... && go vet ./...

# 全部测试（含竞态检测；并发刷新、并发登录淘汰、越权、过期/篡改、限流恢复）
go test -race ./...

# 重复运行验证结论稳定
go test -race -count=5 ./...

# 查看单测日志中的输入与判定依据
go test -race ./auth/ -v
go test -race ./session/ -v
```

关键测试：

- `TestRefreshConcurrentExactlyOneWinner`：24 路并发刷新，恰好 1 胜 23 负（`refresh_replayed`），链终态 `invalid`；
- `TestRefreshRotationSingleUseSequential`：顺序重放与失效链后续访问的原因区分；
- `TestDistinguishableRejectionReasons`：缺失/篡改/垃圾/过期四种输入的可区分拒绝；
- `TestRevokedScopeDeniesExistingSession`：权限收回对既有会话立即生效，重新授予即恢复；
- `TestLegacyV1NoDefaultScopes`：旧格式只认证身份、无默认作用域、不可刷新；
- `TestRateLimitAndRecovery`：窗口内锁定、窗口后按预期恢复。

会话治理新增测试：

- `session.TestCapEvictsLeastRecentlyActive` / `TestCapEvictionIsPerSubject`：超上限按最久未活动淘汰、逐账号隔离；
- `session.TestTouchResetsIdleClock` / `TestIdleExpiryExactBoundary`：活动重置空闲计时与到期边界；
- `session.TestAbsoluteExpiryBeatsRenewal` / `TestAbsoluteBeforeIdleWhenBothElapsed`：绝对寿命不可续越、双到期时绝对优先；
- `session.TestKickOneAndKeepOnly` / `TestListActiveSettlesExpired`：精确踢出、只保留当前、活跃可见性；
- `session.TestConcurrentCreateNeverExceedsCap`：40 路并发建会话，活跃集合恒为上限且留下最新三条；
- `auth.TestCapEvictionStableConclusion`：被挤掉凭据的访问/续期都稳定给出 `session_evicted`；
- `auth.TestIdleAndAbsoluteLifetimeConclusions` / `TestCredentialExpiryStaysDistinctFromSessionExpiry`：两层寿命结论与凭据过期相互独立可分；
- `auth.TestListSessionsVisibility` / `TestPreciseKick`：活跃会话可见、只踢一条或只留当前；
- `auth.TestConcurrentLoginCapAndAccess` / `TestConcurrentRefreshKickNoStateCorruption`：并发登录淘汰与“刷新竞态 + 踢出”下集合不超限、终态不串味。
