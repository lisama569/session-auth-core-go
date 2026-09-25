package auth

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

type testEnv struct {
	svc   *Service
	clock *FakeClock
	logs  *bytes.Buffer
}

func newTestEnv(t *testing.T, allowLegacy bool) *testEnv {
	t.Helper()
	start := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	clock := NewFakeClock(start)
	svc, err := NewService(Config{
		AccessTTL:         time.Minute,
		RefreshTTL:        time.Hour,
		LoginMaxAttempts:  3,
		RateWindow:        time.Minute,
		AllowLegacyAccess: allowLegacy,
		Clock:             clock,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	svc.GrantRole("admin", ScopeProfileRead, ScopeProfileWrite, ScopeAdminRead, ScopeAdminWrite)
	svc.GrantRole("user", ScopeProfileRead, ScopeProfileWrite)
	svc.GrantRole("viewer", ScopeProfileRead)
	if err := svc.AddUser("alice", "pw-alice", "admin"); err != nil {
		t.Fatalf("AddUser alice: %v", err)
	}
	if err := svc.AddUser("bob", "pw-bob", "viewer"); err != nil {
		t.Fatalf("AddUser bob: %v", err)
	}
	var buf bytes.Buffer
	svc.SetLogOutput(io.MultiWriter(&buf, os.Stdout))
	return &testEnv{svc: svc, clock: clock, logs: &buf}
}

func (e *testEnv) dumpLogs(t *testing.T, header string) {
	t.Helper()
	t.Logf("---- 判定日志 %s ----\n%s", header, strings.TrimSpace(e.logs.String()))
	e.logs.Reset()
}

func wantCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("期望错误 %s，但请求成功", want)
	}
	ae, ok := AsAuthError(err)
	if !ok {
		t.Fatalf("期望 *AuthError，实际 %T: %v", err, err)
	}
	if ae.Code != want {
		t.Fatalf("期望错误码 %s，实际 %s（%s）", want, ae.Code, ae.Message)
	}
}

// 1. 登录成功，访问凭据可通过角色对应作用域的判定。
func TestLoginAndAccess_Success(t *testing.T) {
	env := newTestEnv(t, false)
	pair, err := env.svc.Login("alice", "pw-alice", "10.0.0.1")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	t.Logf("输入: Login(alice)；输出 sid=%s access_fp=%s refresh_fp=%s",
		pair.SessionID, fingerprint(pair.AccessToken), fingerprint(pair.RefreshToken))

	p, err := env.svc.Authorize(pair.AccessToken, ScopeAdminWrite, "10.0.0.1")
	if err != nil {
		t.Fatalf("Authorize admin:write: %v", err)
	}
	t.Logf("输入: Authorize(need=%s)；判定依据: 角色=%s 实时作用域=%v",
		ScopeAdminWrite, p.Role, p.Scopes)
	if p.Username != "alice" {
		t.Fatalf("principal user = %s", p.Username)
	}
	env.dumpLogs(t, "登录+访问成功")
}

// 2. 错误口令 -> invalid_credentials，且连续失败达到阈值后限流。
func TestLogin_WrongPassword_ThenRateLimit(t *testing.T) {
	env := newTestEnv(t, false)
	for i := 1; i <= 3; i++ {
		_, err := env.svc.Login("alice", "bad", "10.0.0.2")
		wantCode(t, err, CodeInvalidCredentials)
		t.Logf("输入: 第%d次错误口令；判定依据: 口令校验失败 -> %s", i, CodeInvalidCredentials)
	}
	// 第 4 次：即便口令正确也处于限制期。
	_, err := env.svc.Login("alice", "pw-alice", "10.0.0.2")
	wantCode(t, err, CodeRateLimited)
	t.Logf("输入: 阈值后正确口令；判定依据: 固定窗口内尝试超阈值 -> %s", CodeRateLimited)
	env.dumpLogs(t, "登录失败与限流")
}

// 3. 缺少凭据。
func TestAccess_MissingToken(t *testing.T) {
	env := newTestEnv(t, false)
	_, err := env.svc.Authorize("", ScopeProfileRead, "10.0.0.3")
	wantCode(t, err, CodeMissingCredentials)
	t.Logf("输入: 空凭据；判定依据: 入口前置检查 -> %s", CodeMissingCredentials)
	env.dumpLogs(t, "缺少凭据")
}

// 4. 访问凭据过期。
func TestAccess_TokenExpired(t *testing.T) {
	env := newTestEnv(t, false)
	pair, _ := env.svc.Login("alice", "pw-alice", "10.0.0.1")
	env.clock.Advance(61 * time.Second) // AccessTTL=1m
	_, err := env.svc.Authorize(pair.AccessToken, ScopeProfileRead, "10.0.0.1")
	wantCode(t, err, CodeTokenExpired)
	t.Logf("输入: 推进时钟61s后访问；判定依据: now>=exp -> %s", CodeTokenExpired)
	env.dumpLogs(t, "凭据过期")
}

// 5. 凭据被篡改（翻转末字符）-> invalid_credentials（签名无效）。
func TestAccess_TamperedToken(t *testing.T) {
	env := newTestEnv(t, false)
	pair, _ := env.svc.Login("alice", "pw-alice", "10.0.0.1")
	tampered := pair.AccessToken[:len(pair.AccessToken)-1]
	if strings.HasSuffix(pair.AccessToken, "A") {
		tampered += "B"
	} else {
		tampered += "A"
	}
	_, err := env.svc.Authorize(tampered, ScopeProfileRead, "10.0.0.1")
	wantCode(t, err, CodeInvalidCredentials)
	t.Logf("输入: 篡改签名段 access_fp=%s；判定依据: HMAC不一致 -> %s（不透出底层错误）",
		fingerprint(tampered), CodeInvalidCredentials)
	env.dumpLogs(t, "凭据篡改")
}

// 6. 越权访问：viewer 访问 admin 作用域 -> insufficient_scope。
func TestAccess_InsufficientScope(t *testing.T) {
	env := newTestEnv(t, false)
	pair, _ := env.svc.Login("bob", "pw-bob", "10.0.0.4")
	_, err := env.svc.Authorize(pair.AccessToken, ScopeAdminWrite, "10.0.0.4")
	wantCode(t, err, CodeInsufficientScope)
	t.Logf("输入: bob(viewer) 请求 %s；判定依据: 实时作用域仅含 profile:read -> %s",
		ScopeAdminWrite, CodeInsufficientScope)
	env.dumpLogs(t, "越权访问")
}

// 7. 刷新轮换成功，旧刷新凭据不得再用；新凭据可用。
func TestRefresh_RotationAndReplay(t *testing.T) {
	env := newTestEnv(t, false)
	pair, _ := env.svc.Login("alice", "pw-alice", "10.0.0.1")

	next, err := env.svc.Refresh(pair.RefreshToken, "10.0.0.1")
	if err != nil {
		t.Fatalf("首次刷新: %v", err)
	}
	t.Logf("输入: 刷新 fp=%s；输出新 refresh fp=%s",
		fingerprint(pair.RefreshToken), fingerprint(next.RefreshToken))

	// 重放旧刷新凭据：拒绝原因为 refresh_token_reused，会话链进入失效态。
	_, err = env.svc.Refresh(pair.RefreshToken, "10.0.0.1")
	wantCode(t, err, CodeRefreshReused)
	t.Logf("输入: 重放旧刷新 fp=%s；判定依据: jti 不匹配 -> %s",
		fingerprint(pair.RefreshToken), CodeRefreshReused)

	// 新刷新凭据同样不可用：会话链已失效。
	_, err = env.svc.Refresh(next.RefreshToken, "10.0.0.1")
	wantCode(t, err, CodeRefreshReused)
	// 既有访问凭据随即以 session_revoked 拒绝。
	_, err = env.svc.Authorize(next.AccessToken, ScopeProfileRead, "10.0.0.1")
	wantCode(t, err, CodeSessionRevoked)
	t.Logf("输入: 轮换赢家的新凭据；判定依据: 会话链已被重放标记失效 -> session_revoked")
	env.dumpLogs(t, "刷新轮换与重放失效")
}

// 8. 用访问凭据调用刷新入口 -> refresh_invalid。
func TestRefresh_WrongKind(t *testing.T) {
	env := newTestEnv(t, false)
	pair, _ := env.svc.Login("alice", "pw-alice", "10.0.0.1")
	_, err := env.svc.Refresh(pair.AccessToken, "10.0.0.1")
	wantCode(t, err, CodeRefreshInvalid)
	t.Logf("输入: 以访问凭据刷新；判定依据: kind!=refresh -> %s", CodeRefreshInvalid)
	env.dumpLogs(t, "刷新类型错误")
}

// 9. 权限收回立即生效：即便访问凭据尚未过期，也不能再获得被收回的能力。
func TestScopeRevocation_ImmediateEffect(t *testing.T) {
	env := newTestEnv(t, false)
	pair, _ := env.svc.Login("alice", "pw-alice", "10.0.0.1")
	if _, err := env.svc.Authorize(pair.AccessToken, ScopeAdminWrite, "10.0.0.1"); err != nil {
		t.Fatalf("收回前应可访问: %v", err)
	}
	if !env.svc.RevokeScopes(pair.SessionID, ScopeAdminWrite) {
		t.Fatal("RevokeScopes 应返回 true")
	}
	_, err := env.svc.Authorize(pair.AccessToken, ScopeAdminWrite, "10.0.0.1")
	wantCode(t, err, CodeInsufficientScope)
	// 未被收回的作用域仍可用。
	if _, err := env.svc.Authorize(pair.AccessToken, ScopeProfileRead, "10.0.0.1"); err != nil {
		t.Fatalf("未收回作用域应仍可用: %v", err)
	}
	t.Logf("输入: 收回 admin:write；判定依据: 会话实时作用域已不含该能力")
	env.dumpLogs(t, "权限收回立即生效")
}

// 10. 管理员注销会话：访问与刷新均以 session_revoked 拒绝。
func TestAdminSessionRevocation(t *testing.T) {
	env := newTestEnv(t, false)
	pair, _ := env.svc.Login("alice", "pw-alice", "10.0.0.1")
	if !env.svc.RevokeSession(pair.SessionID) {
		t.Fatal("RevokeSession 应返回 true")
	}
	_, err := env.svc.Authorize(pair.AccessToken, ScopeProfileRead, "10.0.0.1")
	wantCode(t, err, CodeSessionRevoked)
	_, err = env.svc.Refresh(pair.RefreshToken, "10.0.0.1")
	wantCode(t, err, CodeSessionRevoked) // 主动注销的会话刷新按 session_revoked 拒绝
	t.Logf("输入: 注销后访问+刷新；判定依据: session.Revoked=true -> session_revoked")
	env.dumpLogs(t, "管理员注销")
}

// 11. 限流窗口到期后自动解除：行为可预期。
func TestRateLimit_RecoveryAfterWindow(t *testing.T) {
	env := newTestEnv(t, false)
	// 先制造一次成功登录以重置其他测试痕迹无关；这里全程使用独立来源 src-rl-only
	for i := 0; i < 3; i++ {
		_, _ = env.svc.Login("alice", "bad", "src-rl-only")
	}
	_, err := env.svc.Login("alice", "pw-alice", "src-rl-only")
	wantCode(t, err, CodeRateLimited)
	t.Logf("输入: 窗口内第4次尝试；判定依据: count>max -> %s, RetryAfter=%s",
		CodeRateLimited, env.svc.limiter.RetryAfter("login:src:src-rl-only"))

	env.clock.Advance(61 * time.Second) // RateWindow=1m
	pair, err := env.svc.Login("alice", "pw-alice", "src-rl-only")
	if err != nil {
		t.Fatalf("窗口解除后应放行: %v", err)
	}
	t.Logf("输入: 推进61s后登录；判定依据: 新窗口 count=1；sid=%s", pair.SessionID)
	env.dumpLogs(t, "限流恢复")
}

// 12. 旧格式(v1)：默认拒绝；显式开启后只有固定 legacy:read。
func TestLegacyToken_Compatibility(t *testing.T) {
	// 默认不接受 v1
	env := newTestEnv(t, false)
	tm := env.svc.tokens
	legacy, err := tm.IssueLegacy("alice", "admin", env.clock.Now(), time.Hour)
	if err != nil {
		t.Fatalf("IssueLegacy: %v", err)
	}
	_, err = env.svc.Authorize(legacy, ScopeLegacyRead, "10.0.0.9")
	wantCode(t, err, CodeLegacyDenied)
	t.Logf("输入: v1凭据 need=%s；判定依据: AllowLegacyAccess=false -> %s（不放行）",
		ScopeLegacyRead, CodeLegacyDenied)

	// 开启兼容入口：legacy:read 放行，其他作用域一律 insufficient_scope
	env2 := newTestEnv(t, true)
	legacy2, _ := env2.svc.tokens.IssueLegacy("alice", "admin", env2.clock.Now(), time.Hour)
	p, err := env2.svc.Authorize(legacy2, ScopeLegacyRead, "10.0.0.9")
	if err != nil {
		t.Fatalf("v1 legacy:read 应放行: %v", err)
	}
	if !p.Legacy || len(p.Scopes) != 1 || p.Scopes[0] != ScopeLegacyRead {
		t.Fatalf("v1 固定作用域不符合预期: %+v", p)
	}
	_, err = env2.svc.Authorize(legacy2, ScopeAdminWrite, "10.0.0.9")
	wantCode(t, err, CodeInsufficientScope)
	// v1 不能用于刷新
	_, err = env2.svc.Refresh(legacy2, "10.0.0.9")
	wantCode(t, err, CodeLegacyDenied)
	t.Logf("输入: v1凭据 need=admin:write/刷新；判定依据: 固定作用域=legacy:read，刷新入口拒绝")
	env.dumpLogs(t, "v1默认拒绝")
	env2.dumpLogs(t, "v1固定兼容")
}

// 13. 底层/未知错误必须归一化为 internal_error，不外泄细节。
func TestNormalizeError_Internal(t *testing.T) {
	raw := errors.New("hmac: illegal base64 data at input byte 42 (内部细节示例)")
	ae := normalizeError(raw)
	if ae.Code != CodeInternal {
		t.Fatalf("期望 %s，实际 %s", CodeInternal, ae.Code)
	}
	if strings.Contains(ae.Message, "base64") || strings.Contains(ae.Error(), "byte 42") {
		t.Fatalf("底层错误细节被外泄: %s", ae.Error())
	}
	t.Logf("输入: 未知底层错误；判定依据: 非AuthError -> 统一 %s，对外文案=%q", CodeInternal, ae.Message)
}
