package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/lisama569/session-auth-core-go/autherr"
	"github.com/lisama569/session-auth-core-go/ratelimit"
	"github.com/lisama569/session-auth-core-go/rbac"
	"github.com/lisama569/session-auth-core-go/session"
	"github.com/lisama569/session-auth-core-go/token"
)

// newGovFixture builds a service backed by a governance-enabled session store.
func newGovFixture(t *testing.T, cfg session.Config) *fixture {
	t.Helper()
	policy := rbac.NewPolicy(map[string][]string{
		"reader": {"read:doc"},
	})
	store := session.NewStoreWithConfig(cfg)
	signer := token.NewLocalSigner([]byte("governance-secret"))
	clk := &fakeClock{t: time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)}
	svc := NewService(Config{
		Signer:     signer,
		Store:      store,
		Policy:     policy,
		Limiter:    ratelimit.New(10000, time.Minute),
		AccessTTL:  45 * time.Minute, // long enough that session governance, not credential expiry, decides
		RefreshTTL: 24 * time.Hour,
		Clock:      clk.now,
	})
	if err := svc.AddUser("u-reader", "Reader", "reader", "pw-reader"); err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, policy: policy, store: store, signer: signer, clock: clk}
}

func TestEvictedSessionReportsDistinctReason(t *testing.T) {
	f := newGovFixture(t, session.Config{MaxActivePerSubject: 2})
	ctx := context.Background()

	b1 := f.login(t, "u-reader", "pw-reader", "device-A")
	f.clock.advance(time.Minute)
	b2 := f.login(t, "u-reader", "pw-reader", "device-B")
	f.clock.advance(time.Minute)
	b3 := f.login(t, "u-reader", "pw-reader", "device-C")
	t.Logf("cap=2; logins on device-A, device-B, device-C -> oldest (device-A) must be evicted")

	// The evicted session's access credential is well-formed and unexpired,
	// yet access fails with the dedicated evicted reason.
	_, _, err := f.svc.Authorize(ctx, b1.Access, "read:doc")
	if autherr.ReasonOf(err) != autherr.ReasonSessionEvicted {
		t.Fatalf("evicted session access -> reason=%s, want session_evicted", autherr.ReasonOf(err))
	}
	t.Logf("device-A access (valid signature, not expired) -> reason=%s", autherr.ReasonOf(err))

	// Refresh on the evicted session reports the same conclusion.
	if _, err := f.svc.Refresh(ctx, b1.Refresh, "device-A"); autherr.ReasonOf(err) != autherr.ReasonSessionEvicted {
		t.Fatalf("evicted session refresh -> reason=%s, want session_evicted", autherr.ReasonOf(err))
	}
	t.Logf("device-A refresh -> reason=%s (not refresh_replayed, not invalid_credential)", autherr.ReasonSessionEvicted)

	// Survivors are fully usable.
	for i, b := range []*CredentialBundle{b2, b3} {
		if _, _, err := f.svc.Authorize(ctx, b.Access, "read:doc"); err != nil {
			t.Fatalf("survivor %d must be usable: %v", i, err)
		}
	}
	t.Logf("device-B and device-C still authorized; active set = 2 within cap")

	// The evicted conclusion is stable: repeat access gives the same reason.
	if _, _, err := f.svc.Authorize(ctx, b1.Access, "read:doc"); autherr.ReasonOf(err) != autherr.ReasonSessionEvicted {
		t.Fatalf("evicted reason must be stable, got %v", err)
	}
	t.Logf("repeat device-A access -> reason=%s (stable terminal conclusion)", autherr.ReasonSessionEvicted)
}

func TestIdleVsAbsoluteExpiryReasons(t *testing.T) {
	f := newGovFixture(t, session.Config{
		IdleTTL:     30 * time.Minute,
		AbsoluteTTL: 2 * time.Hour,
	})
	ctx := context.Background()
	b := f.login(t, "u-reader", "pw-reader", "device-I")

	// Access counts as activity and resets the idle clock.
	f.clock.advance(20 * time.Minute)
	if _, err := f.svc.Authenticate(ctx, b.Access); err != nil {
		t.Fatalf("access at +20m must succeed: %v", err)
	}
	t.Logf("idleTTL=30m; authenticate at +20m -> ok (activity, idle clock reset)")

	// Refresh also counts as activity.
	f.clock.advance(20 * time.Minute) // +40m, 20m after last activity
	b2, err := f.svc.Refresh(ctx, b.Refresh, "device-I")
	if err != nil {
		t.Fatalf("refresh at +40m (20m idle) must succeed: %v", err)
	}
	t.Logf("refresh at +40m (20m since activity) -> ok (idle clock reset again)")

	// Now stay quiet past the idle TTL: idle expiry, distinct from absolute.
	f.clock.advance(31 * time.Minute) // +71m, 31m idle
	_, err = f.svc.Authenticate(ctx, b2.Access)
	if autherr.ReasonOf(err) != autherr.ReasonSessionIdleExp {
		t.Fatalf("31m idle -> reason=%s, want session_idle_expired", autherr.ReasonOf(err))
	}
	t.Logf("authenticate after 31m idle -> reason=%s", autherr.ReasonOf(err))
	if _, err := f.svc.Refresh(ctx, b2.Refresh, "device-I"); autherr.ReasonOf(err) != autherr.ReasonSessionIdleExp {
		t.Fatalf("refresh after idle expiry -> reason=%s, want session_idle_expired", autherr.ReasonOf(err))
	}
	t.Logf("refresh after idle expiry -> reason=%s (same conclusion on both entry points)", autherr.ReasonSessionIdleExp)

	// A fresh session kept alive by refresh still dies at the absolute limit.
	b = f.login(t, "u-reader", "pw-reader", "device-J")
	cur := b
	for i := 0; i < 5; i++ {
		f.clock.advance(20 * time.Minute) // +100m total, always < 30m idle
		nb, err := f.svc.Refresh(ctx, cur.Refresh, "device-J")
		if err != nil {
			t.Fatalf("refresh %d at +%dm must succeed: %v", i+1, (i+1)*20, err)
		}
		cur = nb
	}
	t.Logf("absoluteTTL=2h; refreshed every 20m up to +100m -> all ok (idle never trips)")

	f.clock.advance(20 * time.Minute) // +120m = absolute limit
	_, err = f.svc.Refresh(ctx, cur.Refresh, "device-J")
	if autherr.ReasonOf(err) != autherr.ReasonSessionAbsExp {
		t.Fatalf("refresh at absolute limit -> reason=%s, want session_absolute_expired", autherr.ReasonOf(err))
	}
	t.Logf("refresh at +120m (absolute limit, last activity +100m) -> reason=%s: re-login required", autherr.ReasonOf(err))
}

func TestListAndKickSessions(t *testing.T) {
	f := newGovFixture(t, session.Config{MaxActivePerSubject: 10})
	ctx := context.Background()

	b1 := f.login(t, "u-reader", "pw-reader", "web")
	f.clock.advance(time.Minute)
	b2 := f.login(t, "u-reader", "pw-reader", "ios")
	f.clock.advance(time.Minute)
	b3 := f.login(t, "u-reader", "pw-reader", "android")

	infos := f.svc.ListSessions(ctx, "u-reader")
	if len(infos) != 3 {
		t.Fatalf("list sessions -> %d, want 3", len(infos))
	}
	for _, in := range infos {
		t.Logf("LIST session=%s source=%s created=%s lastActive=%s version=%d",
			in.SessionID, in.Source, in.CreatedAt.Format(time.RFC3339), in.LastActiveAt.Format(time.RFC3339), in.Version)
	}
	if infos[0].SessionID != b3.SessionID {
		t.Fatalf("most recently active session must sort first, got %s", infos[0].SessionID)
	}

	// Kick exactly one session: only it fails, with the kicked reason.
	f.svc.KickSession(ctx, b2.SessionID)
	t.Logf("KICK session=%s (ios)", b2.SessionID)
	if _, err := f.svc.Authenticate(ctx, b2.Access); autherr.ReasonOf(err) != autherr.ReasonSessionKicked {
		t.Fatalf("kicked session access -> reason=%s, want session_kicked", autherr.ReasonOf(err))
	}
	if _, err := f.svc.Refresh(ctx, b2.Refresh, "ios"); autherr.ReasonOf(err) != autherr.ReasonSessionKicked {
		t.Fatalf("kicked session refresh -> reason=%s, want session_kicked", autherr.ReasonOf(err))
	}
	t.Logf("kicked session access+refresh -> reason=%s", autherr.ReasonSessionKicked)
	for _, b := range []*CredentialBundle{b1, b3} {
		if _, err := f.svc.Authenticate(ctx, b.Access); err != nil {
			t.Fatalf("un-kicked session must be unaffected: %v", err)
		}
	}
	t.Logf("web and android sessions unaffected by kicking ios")

	// Keep only the current session, kick the rest.
	f.svc.KickOtherSessions(ctx, "u-reader", b3.SessionID)
	t.Logf("KICK-OTHERS keep=%s (android)", b3.SessionID)
	if _, err := f.svc.Authenticate(ctx, b1.Access); autherr.ReasonOf(err) != autherr.ReasonSessionKicked {
		t.Fatalf("kick-others victim -> reason=%s, want session_kicked", autherr.ReasonOf(err))
	}
	if _, err := f.svc.Authenticate(ctx, b3.Access); err != nil {
		t.Fatalf("kept session must survive: %v", err)
	}
	infos = f.svc.ListSessions(ctx, "u-reader")
	if len(infos) != 1 || infos[0].SessionID != b3.SessionID {
		t.Fatalf("after kick-others -> %d active, want only android", len(infos))
	}
	t.Logf("after kick-others: active=%v (only the kept session)", infos[0].SessionID)
}

func TestConcurrentRefreshUnchangedUnderGovernance(t *testing.T) {
	f := newGovFixture(t, session.Config{
		MaxActivePerSubject: 5,
		IdleTTL:             time.Hour,
		AbsoluteTTL:         24 * time.Hour,
	})
	ctx := context.Background()
	b := f.login(t, "u-reader", "pw-reader", "device-R")

	const n = 24
	var wg sync.WaitGroup
	type outcome struct {
		ok     bool
		reason autherr.Reason
	}
	outcomes := make(chan outcome, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := f.svc.Refresh(ctx, b.Refresh, "device-R"); err == nil {
				outcomes <- outcome{ok: true}
			} else {
				outcomes <- outcome{reason: autherr.ReasonOf(err)}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(outcomes)

	wins, replays := 0, 0
	for o := range outcomes {
		if o.ok {
			wins++
		} else if o.reason == autherr.ReasonReusedRefresh {
			replays++
		} else {
			t.Errorf("unexpected loser reason under governance: %s", o.reason)
		}
	}
	t.Logf("governance store, concurrent refresh n=%d -> winners=%d replayed=%d", n, wins, replays)
	if wins != 1 || replays != n-1 {
		t.Fatalf("exactly-one-winner semantics must not change: wins=%d replays=%d", wins, replays)
	}
}

func TestConcurrentLoginsRespectCap(t *testing.T) {
	const cap = 3
	f := newGovFixture(t, session.Config{MaxActivePerSubject: cap})
	ctx := context.Background()

	const n = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := f.svc.Login(ctx, "u-reader", "pw-reader", "device-x"); err != nil {
				t.Errorf("login: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	infos := f.svc.ListSessions(ctx, "u-reader")
	t.Logf("concurrent logins n=%d cap=%d -> active sessions=%d", n, cap, len(infos))
	if len(infos) != cap {
		t.Fatalf("active sessions must equal cap=%d, got %d", cap, len(infos))
	}
}
