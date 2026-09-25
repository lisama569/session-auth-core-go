package auth

import (
	"bytes"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

// 并发刷新轮换：同一刷新凭据被 N 个请求同时提交。
// 稳定结论（竞态检测下也必须成立）：
//   - 恰好 1 个成功（refresh_token_reused 之外的赢家）；
//   - 其余 N-1 个全部以 refresh_token_reused 失败；
//   - 会话链进入明确失效状态：赢家手上的新凭据随后也不能再访问/刷新。
func TestConcurrentRefresh_ExactlyOneWinner(t *testing.T) {
	start := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	clock := NewFakeClock(start)
	svc, err := NewService(Config{
		AccessTTL: time.Minute, RefreshTTL: time.Hour,
		LoginMaxAttempts: 1000, RateWindow: time.Hour, // 本测试不触发来源限流
		Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	svc.SetLogOutput(io.MultiWriter(&buf, os.Stdout))
	svc.GrantRole("admin", ScopeProfileRead, ScopeProfileWrite)
	if err := svc.AddUser("alice", "pw", "admin"); err != nil {
		t.Fatal(err)
	}
	pair, err := svc.Login("alice", "pw", "src-conc")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("输入: 同一刷新凭据 fp=%s 被 %d 个 goroutine 并发提交", fingerprint(pair.RefreshToken), 32)

	const n = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	winners, reused, others := 0, 0, 0
	var winnerPair *TokenPair
	startGate := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startGate // 尽量同时进入 Refresh
			p, rerr := svc.Refresh(pair.RefreshToken, "src-conc")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case rerr == nil:
				winners++
				winnerPair = p
			case func() bool { ae, ok := AsAuthError(rerr); return ok && ae.Code == CodeRefreshReused }():
				reused++
			default:
				others++
				t.Errorf("出现不可预期的拒绝原因: %v", rerr)
			}
		}()
	}
	close(startGate)
	wg.Wait()

	t.Logf("判定依据: CAS(session.jti==oldJTI)；结果 成功=%d 重放拒绝=%d 其他=%d",
		winners, reused, others)
	if winners != 1 || reused != n-1 || others != 0 {
		t.Fatalf("并发结论不稳定: winners=%d reused=%d others=%d（期望 1/%d/0）",
			winners, reused, others, n-1)
	}

	// 会话链失效是“全有”语义：即便赢家也不再保有有效会话。
	sess := svc.store.GetSession(pair.SessionID)
	if sess == nil || !sess.Revoked || sess.RevokeReason != revokeReasonReuse {
		t.Fatalf("会话链未进入重放失效态: %+v", sess)
	}
	if _, err := svc.Authorize(winnerPair.AccessToken, ScopeProfileRead, "src-conc"); err == nil {
		t.Fatal("重放发生后赢家的访问凭据必须随会话链一起失效")
	} else {
		ae, _ := AsAuthError(err)
		if ae.Code != CodeSessionRevoked {
			t.Fatalf("期望 session_revoked，实际 %s", ae.Code)
		}
	}
	if _, err := svc.Refresh(winnerPair.RefreshToken, "src-conc"); err == nil {
		t.Fatal("赢家的新刷新凭据同样不得再用")
	} else {
		ae, _ := AsAuthError(err)
		if ae.Code != CodeRefreshReused {
			t.Fatalf("期望 refresh_token_reused，实际 %s", ae.Code)
		}
	}
	t.Log("判定依据: 重放后 session.Revoked=true(reason=reuse)；赢家访问->session_revoked，再刷新->reused")
	t.Logf("---- 并发判定日志（节选）----\n%s", tailLog(buf.String(), 6))
}

// 串行重放与并发结论一致：旧刷新凭据第二次使用必失败且失效会话。
func TestSequentialReplay_SameConclusion(t *testing.T) {
	env := newTestEnv(t, false)
	pair, _ := env.svc.Login("alice", "pw-alice", "src-0")
	if _, err := env.svc.Refresh(pair.RefreshToken, "src-0"); err != nil {
		t.Fatal(err)
	}
	// 即使每次都换来源（绕开同一来源的频率计数），重放检测仍按会话 jti 生效，
	// 结论保持稳定、可区分，会话不会“复活”。
	for i := 1; i <= 6; i++ {
		_, err := env.svc.Refresh(pair.RefreshToken, "src-replay-"+itoa(i))
		wantCode(t, err, CodeRefreshReused)
	}
	t.Log("输入: 旧刷新凭据从不同来源连续重放6次；判定依据: jti 不匹配+会话保持 reuse 失效态")
	env.dumpLogs(t, "串行重放稳定性")
}

func tailLog(s string, n int) string {
	lines := splitLines(s)
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
