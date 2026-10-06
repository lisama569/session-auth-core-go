# session-auth-core-go

本地会话认证与访问控制核心：用内存状态与本地生成的 HMAC 签名密钥模拟真实登录链路，覆盖令牌轮换、并发访问与会话失效，所有入口给出一致且可解释的判定结论。

## 包结构

| 包 | 职责 |
|---|---|
| `auth` | 对外门面：登录、刷新、认证、鉴权、撤销、会话可见性与踢出；统一归一化错误 |
| `autherr` | 归一化拒绝原因（见下表），底层错误不外泄 |
| `token` | 本地 HMAC 签名凭据（v2 信封）与旧格式 v1 的固定兼容语义 |
| `session` | 内存会话链存储；刷新凭据轮换为互斥锁下的 compare-and-swap；会话治理（上限淘汰、双层寿命、踢出） |
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

## 会话治理（上限、双层寿命、可见性与踢出）

会话治理由 `session.NewStoreWithConfig(session.Config{...})` 开启，三个参数零值均表示"不限制"（`NewStore()` 等价于全零配置，行为与治理引入前完全一致）。所有治理判定都在会话存储的同一把互斥锁下完成，因此并发新建、续期、访问与淘汰不会越限或错杀：

- **活跃上限与淘汰（`MaxActivePerSubject`）**：同一账号的活跃会话数超限后，按**最近活动时间**把最久没动的会话挤掉（`evicted` 终态，粘性）。刚建立的会话活动时间最新，永远不会挤掉自己。被挤掉的会话之后无论拿访问凭据还是刷新凭据来，都稳定得到 `session_evicted`——不是 `invalid_credential`（凭据没坏），也不是 `permission_denied`（不是权限问题），也不是 `refresh_replayed`（凭据未被消费）。
- **双层寿命**：
  - **空闲寿命（`IdleTTL`）**：一段时间没有任何活动即作废（`idle_expired`）。**鉴权（Authenticate/Authorize）和续期（Refresh）都算一次活动**，会重置空闲计时。
  - **绝对寿命（`AbsoluteTTL`）**：从会话建立那一刻算起，到达上限必须重新登录；反复续期只重置空闲计时，**绝不延长绝对寿命**（`absolute_expired`）。
  - 两者都在访问/续期/列举时惰性求值并落为终态，各入口结论一致。
- **可见性**：`Service.ListSessions(subject)` 返回该账号当前活跃会话（会话 ID、来源、建立时间、最近活动时间、链版本），按最近活动倒序；列举前先做惰性过期求值，看到的即是"活着的"。
- **精确踢人**：`Service.KickSession(sessionID)` 只踢指定的一条；`Service.KickOtherSessions(subject, keepID)` 只保留当前这条、其余一起踢掉。被踢会话再访问或续期都稳定得到 `session_kicked`，未被点名的会话（包括其他账号的）完全不受影响。
- **并发保证**：上限检查与淘汰在创建会话的同一把锁内完成，并发登录下最终活跃集合恒等于上限；淘汰按活动时间确定性选受害者（时间相同按建立时间、再按 ID 破平），不存在"该留的被挤掉"。

### 治理相关拒绝原因（新增，均可互相区分、并与凭据过期区分）

| Reason | 触发条件 |
|---|---|
| `session_evicted` | 会话被更新的登录按 LRU 挤出（每账号活跃上限） |
| `session_idle_expired` | 空闲寿命内无任何鉴权/续期活动 |
| `session_absolute_expired` | 达到自建立起的绝对寿命，必须重新登录 |
| `session_kicked` | 被账号所有者精确踢出（单条或"保留当前"） |

旧的 `session_invalid` 仍只表示刷新重放导致的链失效与显式撤销；`credential_expired` 仍只表示凭据自身过期，与会话层面的失效完全分开。

## 拒绝原因一览（归一化，内部错误不外泄）

| Reason | 触发条件 |
|---|---|
| `missing_credential` | 未提供凭据 |
| `invalid_credential` | 格式错误、签名被篡改、类型不符、旧格式用于刷新、登录口令错误 |
| `credential_expired` | 凭据过期（到期时刻本身即视为过期） |
| `refresh_replayed` | 提交了已被消费的刷新凭据（并发失败者或重放） |
| `session_invalid` | 会话链已失效（刷新重放）/被撤销/不存在 |
| `session_evicted` | 会话被更新的登录按 LRU 挤出（活跃上限） |
| `session_idle_expired` | 会话空闲超期（无鉴权/续期活动） |
| `session_absolute_expired` | 会话达到绝对寿命，须重新登录 |
| `session_kicked` | 会话被所有者精确踢出 |
| `permission_denied` | 已认证但缺少所需作用域（含被收回、旧格式无作用域） |
| `rate_limited` | 账号或来源维度超出窗口配额 |
| `internal_error` | 其他内部失败；解析/签名校验的底层错误一律归一化为此类或上述业务原因，**原始错误文本不返回给调用方** |

## 兼容范围（旧格式 v1）

v1 线格式为 `b64(sub:role:expUnix).hex(HMAC)`，兼容语义固定且稳定：

- 有效 v1 凭据只认证身份（subject/role），**永不携带作用域**——任何作用域检查一律拒绝，不默认放行；
- 不绑定会话、**不能用于刷新**；
- 形状或签名不符一律 `invalid_credential`，不存在静默放行路径。

**会话治理改动后 v1 的判定口径不变**：v1 凭据不绑定会话，因此不参与活跃上限/淘汰、不受空闲与绝对寿命约束、不可被列出或踢出；其判定仍只看凭据自身（形状、签名、是否过期），结论依旧是 `invalid_credential` / `credential_expired` / `permission_denied` 三选一，不会出现任何 `session_*` 原因。

## 限流语义

固定窗口（默认 5 次/分钟，可配置），账号与来源两个维度独立计数：

- 窗口内前 N 次放行，之后拒绝并给出 `RetryAfter`；
- 窗口边界过后桶原子重置，行为与全新窗口完全一致（可预期恢复）；
- 登录的每次尝试（含口令错误）都消耗配额，防止暴力破解；刷新按来源+账号限流。

## 本地验证

```bash
# 构建与静态检查
go build ./... && go vet ./...

# 全部测试（含竞态检测；并发刷新、越权、过期/篡改、限流恢复、会话治理）
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

- `TestCapEvictsLeastRecentlyActive` / `TestEvictedSessionReportsDistinctReason`：超限按最近活动时间挤掉最久未动的会话，被挤会话访问/续期稳定得到 `session_evicted`，幸存会话不受影响；
- `TestConcurrentCreateNeverExceedsCap` / `TestConcurrentLoginsRespectCap` / `TestConcurrentCreateRotateTouchStaysConsistent`：并发新建+续期+访问下活跃集合恒不超上限，幸存者恰为最近活跃的 N 条；
- `TestIdleExpiryAndActivityReset` / `TestIdleVsAbsoluteExpiryReasons`：鉴权与续期都重置空闲计时；空闲到期与绝对到期分别给出 `session_idle_expired` / `session_absolute_expired`，续期不能越过绝对寿命；
- `TestListActiveAndKick` / `TestListAndKickSessions`：活跃会话可见（来源/建立/最近活动时间），单踢与"保留当前"精确生效，被踢者稳定得到 `session_kicked`；
- `TestConcurrentRefreshUnchangedUnderGovernance`：治理开启后并发续期"恰好一个成功、失败者 `refresh_replayed`"的结论不变（竞态检测下稳定复现）。
