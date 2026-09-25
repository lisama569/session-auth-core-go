package auth

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lisama569/session-auth-core-go/autherr"
	"github.com/lisama569/session-auth-core-go/ratelimit"
	"github.com/lisama569/session-auth-core-go/rbac"
	"github.com/lisama569/session-auth-core-go/session"
	"github.com/lisama569/session-auth-core-go/token"
)

type fixture struct {
	svc    *Service
	policy rbac.Policy
	store  session.Store
	signer token.Signer
	clock  *fakeClock
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newFixture(t *testing.T) *fixture {
	return newFixtureLimit(t, 5)
}

func newFixtureLimit(t *testing.T, maxAttempts int) *fixture {
	t.Helper()
	policy := rbac.NewPolicy(map[string][]string{
		"admin":  {"read:doc", "write:doc", "admin:users"},
		"reader": {"read:doc"},
		"guest":  {},
	})
	store := session.NewStore()
	signer := token.NewLocalSigner([]byte("integration-secret"))
	clk := &fakeClock{t: time.Date(2026, 9, 25, 9, 0, 0, 0, time.UTC)}
	svc := NewService(Config{
		Signer:     signer,
		Store:      store,
		Policy:     policy,
		Limiter:    ratelimit.New(maxAttempts, time.Minute),
		AccessTTL:  10 * time.Minute,
		RefreshTTL: time.Hour,
		Clock:      clk.now,
	})
	if err := svc.AddUser("u-admin", "Admin", "admin", "pw-admin"); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddUser("u-reader", "Reader", "reader", "pw-reader"); err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, policy: policy, store: store, signer: signer, clock: clk}
}

func (f *fixture) login(t *testing.T, subject, pw, source string) *CredentialBundle {
	t.Helper()
	b, err := f.svc.Login(context.Background(), subject, pw, source)
	if err != nil {
		t.Fatalf("login(%s): %v", subject, err)
	}
	t.Logf("LOGIN input subject=%s source=%s -> session=%s", subject, source, b.SessionID)
	return b
}

func TestLoginAndAuthorize(t *testing.T) {
	f := newFixture(t)
	b := f.login(t, "u-reader", "pw-reader", "10.0.0.10")

	p, d, err := f.svc.Authorize(context.Background(), b.Access, "read:doc")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	t.Logf("AUTHORIZE input scope=read:doc subject=%s -> allowed=%v basis=%q", p.Subject, d.Allowed, d.Basis)
	if !d.Allowed || !p.Scopes["read:doc"] {
		t.Fatal("reader must access read:doc")
	}

	_, d, err = f.svc.Authorize(context.Background(), b.Access, "write:doc")
	if err == nil || autherr.ReasonOf(err) != autherr.ReasonPermissionDenied {
		t.Fatalf("reader must be denied write:doc, got %v", err)
	}
	t.Logf("AUTHORIZE input scope=write:doc -> allowed=%v reason=%s basis=%q", d.Allowed, autherr.ReasonOf(err), d.Basis)
}

func TestDistinguishableRejectionReasons(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := f.login(t, "u-reader", "pw-reader", "10.0.0.11")

	// Missing
	if _, _, err := f.svc.Authorize(ctx, "", "read:doc"); autherr.ReasonOf(err) != autherr.ReasonMissingCredential {
		t.Fatalf("want missing, got %v", err)
	} else {
		t.Logf("input=<empty> -> reason=%s", autherr.ReasonOf(err))
	}

	// Tampered: flip a byte in the signature segment.
	tampered := b.Access[:len(b.Access)-1]
	if strings.HasSuffix(tampered, "A") {
		tampered += "B"
	} else {
		tampered += "A"
	}
	if _, _, err := f.svc.Authorize(ctx, tampered, "read:doc"); autherr.ReasonOf(err) != autherr.ReasonInvalidCredential {
		t.Fatalf("want invalid, got %v", err)
	} else {
		t.Logf("input=<flipped signature> -> reason=%s", autherr.ReasonOf(err))
	}

	// Garbage
	if _, _, err := f.svc.Authorize(ctx, "garbage!!", "read:doc"); autherr.ReasonOf(err) != autherr.ReasonInvalidCredential {
		t.Fatalf("want invalid for garbage, got %v", err)
	} else {
		t.Logf("input=garbage -> reason=%s", autherr.ReasonOf(err))
	}

	// Expired
	f.clock.advance(11 * time.Minute)
	if _, _, err := f.svc.Authorize(ctx, b.Access, "read:doc"); autherr.ReasonOf(err) != autherr.ReasonExpiredCredential {
		t.Fatalf("want expired, got %v", err)
	} else {
		t.Logf("input=<access ttl 10m, now +11m> -> reason=%s", autherr.ReasonOf(err))
	}
}

func TestLoginFailureIsInvalid(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, in := range [][2]string{
		{"u-reader", "wrong-pw"},
		{"u-ghost", "pw-reader"},
	} {
		if _, err := f.svc.Login(ctx, in[0], in[1], "10.0.0.12"); autherr.ReasonOf(err) != autherr.ReasonInvalidCredential {
			t.Fatalf("input subject=%s badpw -> want invalid_credential, got %v", in[0], err)
		} else {
			t.Logf("LOGIN input subject=%s -> reason=%s (normalized, no user-existence hint)", in[0], autherr.ReasonOf(err))
		}
	}
}

func TestRefreshRotationSingleUseSequential(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := f.login(t, "u-reader", "pw-reader", "10.0.0.20")

	first := b.Refresh
	b2, err := f.svc.Refresh(ctx, first, "10.0.0.20")
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	t.Logf("REFRESH #1 input=%q -> new session bundle", first)

	// The same refresh credential must not work twice.
	_, err = f.svc.Refresh(ctx, first, "10.0.0.20")
	if autherr.ReasonOf(err) != autherr.ReasonReusedRefresh {
		t.Fatalf("replay must report refresh_replayed, got %v", err)
	}
	t.Logf("REFRESH replay input=%q -> reason=%s, chain invalidated", first, autherr.ReasonOf(err))

	// Chain is terminally invalid: even the freshly minted refresh fails now.
	_, err = f.svc.Refresh(ctx, b2.Refresh, "10.0.0.20")
	if autherr.ReasonOf(err) != autherr.ReasonSessionInvalid {
		t.Fatalf("post-replay chain use must report session_invalid, got %v", err)
	}
	t.Logf("REFRESH new credential on invalid chain -> reason=%s", autherr.ReasonOf(err))

	s, _ := f.store.Get(ctx, b.SessionID)
	if s.State != session.StateInvalid {
		t.Fatalf("session state=%s, want invalid", s.State)
	}
	t.Logf("session=%s final state=%s why=%q", s.ID, s.State, s.InvalidationWhy)
}

func TestRefreshConcurrentExactlyOneWinner(t *testing.T) {
	f := newFixtureLimit(t, 10000)
	ctx := context.Background()
	b := f.login(t, "u-reader", "pw-reader", "10.0.0.21")

	const n = 24
	var wg sync.WaitGroup
	type outcome struct {
		ok     bool
		reason autherr.Reason
		bundle *CredentialBundle
	}
	outcomes := make(chan outcome, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			nb, err := f.svc.Refresh(ctx, b.Refresh, "10.0.0.21")
			if err == nil {
				outcomes <- outcome{ok: true, bundle: nb}
				return
			}
			outcomes <- outcome{ok: false, reason: autherr.ReasonOf(err)}
		}()
	}
	close(start)
	wg.Wait()
	close(outcomes)

	wins, replays, others := 0, 0, 0
	var winnerBundle *CredentialBundle
	for o := range outcomes {
		switch {
		case o.ok:
			wins++
			winnerBundle = o.bundle
		case o.reason == autherr.ReasonReusedRefresh:
			replays++
		default:
			others++
			t.Errorf("unexpected loser reason: %s", o.reason)
		}
	}
	t.Logf("concurrent REFRESH n=%d winners=%d replay_rejections=%d other=%d", n, wins, replays, others)
	if wins != 1 || replays != n-1 || others != 0 {
		t.Fatalf("exactly one refresh must win, all others must report refresh_replayed")
	}

	// Follow-up: replaying the consumed credential is still a replay.
	if _, err := f.svc.Refresh(ctx, b.Refresh, "10.0.0.21"); autherr.ReasonOf(err) != autherr.ReasonReusedRefresh {
		t.Fatalf("reused credential must remain a replay, got %v", err)
	}
	t.Logf("post-race replay of consumed credential -> reason=%s", autherr.ReasonReusedRefresh)

	// The winner's NEW refresh credential lives on a now-dead chain: the
	// credential itself was never consumed, so the reason is session_invalid.
	if winnerBundle == nil {
		t.Fatal("expected one winning bundle")
	}
	if _, err := f.svc.Refresh(ctx, winnerBundle.Refresh, "10.0.0.21"); autherr.ReasonOf(err) != autherr.ReasonSessionInvalid {
		t.Fatalf("new credential on dead chain must report session_invalid, got %v", err)
	}
	t.Logf("winner's fresh credential on invalid chain -> reason=%s (stable terminal state)", autherr.ReasonSessionInvalid)

	s, _ := f.store.Get(ctx, b.SessionID)
	if s.State != session.StateInvalid || s.Version != 1 {
		t.Fatalf("state=%s version=%d, want invalid/v1", s.State, s.Version)
	}
}

func TestRevokedScopeDeniesExistingSession(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := f.login(t, "u-reader", "pw-reader", "10.0.0.30")

	if _, _, err := f.svc.Authorize(ctx, b.Access, "read:doc"); err != nil {
		t.Fatalf("pre-revoke access: %v", err)
	}
	t.Logf("pre-revoke: read:doc allowed")

	// Revoke at the policy level; existing credential must be denied at once.
	f.policy.Revoke(ctx, "reader", "read:doc")
	t.Logf("policy: reader/read:doc revoked")

	p, d, err := f.svc.Authorize(ctx, b.Access, "read:doc")
	if autherr.ReasonOf(err) != autherr.ReasonPermissionDenied {
		t.Fatalf("post-revoke must deny, got %v", err)
	}
	if len(p.Scopes) != 0 {
		t.Fatalf("effective scopes must shrink to live policy, got %v", p.Scopes)
	}
	t.Logf("post-revoke AUTHORIZE -> allowed=%v effectiveScopes=%v basis=%q", d.Allowed, d.EffectiveScope, d.Basis)

	// Restoring the scope re-enables access without a new login.
	f.policy.Grant(ctx, "reader", "read:doc")
	if _, _, err := f.svc.Authorize(ctx, b.Access, "read:doc"); err != nil {
		t.Fatalf("re-grant must re-enable existing session, got %v", err)
	}
	t.Logf("re-grant: existing credential allowed again")
}

func TestRevokedSessionDenied(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := f.login(t, "u-reader", "pw-reader", "10.0.0.31")
	f.svc.Revoke(ctx, "u-reader", "")
	_, _, err := f.svc.Authorize(ctx, b.Access, "read:doc")
	if autherr.ReasonOf(err) != autherr.ReasonSessionInvalid {
		t.Fatalf("revoked session must be denied with session_invalid, got %v", err)
	}
	t.Logf("revoked subject access -> reason=%s", autherr.ReasonOf(err))
}

func TestLegacyV1NoDefaultScopes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// A reader would have read:doc under current policy, but a v1 credential
	// carries no scopes, so scope checks must deny. Identity still authenticates.
	legacy, err := f.signer.SignLegacy(ctx, "u-reader", "reader", f.clock.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("legacy credential input=%q", legacy)

	p, err := f.svc.Authenticate(ctx, legacy)
	if err != nil {
		t.Fatalf("legacy must authenticate identity: %v", err)
	}
	if len(p.Scopes) != 0 {
		t.Fatalf("legacy effective scopes must be empty, got %v", p.Scopes)
	}
	t.Logf("legacy AUTHENTICATE subject=%s effectiveScopes=%v", p.Subject, p.Scopes)

	_, d, err := f.svc.Authorize(ctx, legacy, "read:doc")
	if autherr.ReasonOf(err) != autherr.ReasonPermissionDenied {
		t.Fatalf("legacy must never pass scope checks, got %v", err)
	}
	t.Logf("legacy AUTHORIZE scope=read:doc -> allowed=%v basis=%q", d.Allowed, d.Basis)

	// Legacy credentials cannot be used as refresh credentials.
	if _, err := f.svc.Refresh(ctx, legacy, "10.0.0.40"); autherr.ReasonOf(err) != autherr.ReasonInvalidCredential {
		t.Fatalf("legacy refresh must be invalid_credential, got %v", err)
	}
	t.Logf("legacy REFRESH -> reason=%s", autherr.ReasonInvalidCredential)
}

func TestRateLimitAndRecovery(t *testing.T) {
	f := newFixture(t) // limiter: 5/min
	ctx := context.Background()

	// 5 good logins allowed.
	for i := 0; i < 5; i++ {
		if _, err := f.svc.Login(ctx, "u-reader", "pw-reader", "10.0.0.50"); err != nil {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	t.Logf("5 login attempts allowed")

	// 6th is rate limited even with correct credentials.
	_, err := f.svc.Login(ctx, "u-reader", "pw-reader", "10.0.0.50")
	if autherr.ReasonOf(err) != autherr.ReasonRateLimited {
		t.Fatalf("6th attempt must be rate limited, got %v", err)
	}
	t.Logf("6th attempt (correct password) -> reason=%s (lockout within window)", autherr.ReasonOf(err))

	// Still blocked mid-window.
	f.clock.advance(30 * time.Second)
	if _, err := f.svc.Login(ctx, "u-reader", "pw-reader", "10.0.0.50"); autherr.ReasonOf(err) != autherr.ReasonRateLimited {
		t.Fatalf("mid-window attempt must stay blocked, got %v", err)
	}
	t.Logf("attempt at +30s -> still rate_limited")

	// Window boundary restores predictable behavior.
	f.clock.advance(31 * time.Second)
	if _, err := f.svc.Login(ctx, "u-reader", "pw-reader", "10.0.0.50"); err != nil {
		t.Fatalf("post-window attempt must recover, got %v", err)
	}
	t.Logf("attempt at +61s -> recovered, login succeeds")
}

func TestRefreshExpiredCredential(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	b := f.login(t, "u-admin", "pw-admin", "10.0.0.60")
	f.clock.advance(2 * time.Hour) // refreshTTL = 1h
	_, err := f.svc.Refresh(ctx, b.Refresh, "10.0.0.60")
	if autherr.ReasonOf(err) != autherr.ReasonExpiredCredential {
		t.Fatalf("expired refresh must report credential_expired, got %v", err)
	}
	t.Logf("expired refresh (now +2h, ttl 1h) -> reason=%s", autherr.ReasonOf(err))
}
