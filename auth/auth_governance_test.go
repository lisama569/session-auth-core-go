package auth

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lisama569/session-auth-core-go/autherr"
	"github.com/lisama569/session-auth-core-go/session"
)

// Login on the governed fixture, logging the decision inputs.
func govLogin(t *testing.T, f *fixture, source string) *CredentialBundle {
	t.Helper()
	b, err := f.svc.Login(context.Background(), "u-reader", "pw-reader", source)
	if err != nil {
		t.Fatalf("login source=%s: %v", source, err)
	}
	t.Logf("LOGIN source=%s -> session=%s", source, b.SessionID)
	return b
}

func TestCapEvictionStableConclusion(t *testing.T) {
	f := newGovFixture(t, 2, 0, 0)
	ctx := context.Background()

	b1 := govLogin(t, f, "dev-a")
	f.clock.advance(time.Minute)
	b2 := govLogin(t, f, "dev-b")
	f.clock.advance(time.Minute)
	b3 := govLogin(t, f, "dev-c") // cap 2 -> b1 (oldest activity) evicted

	// Access with the evicted session's still-cryptographically-valid credential
	// must be a distinct "evicted" conclusion, never invalid/permission/expired.
	if _, _, err := f.svc.Authorize(ctx, b1.Access, "read:doc"); autherr.ReasonOf(err) != autherr.ReasonSessionEvicted {
		t.Fatalf("evicted access -> %v, want session_evicted", err)
	} else {
		t.Logf("AUTHORIZE evicted session credential -> reason=%s (distinct from credential/permission errors)", autherr.ReasonOf(err))
	}
	// Refresh on the evicted session gives the same stable conclusion.
	if _, err := f.svc.Refresh(ctx, b1.Refresh, "dev-a"); autherr.ReasonOf(err) != autherr.ReasonSessionEvicted {
		t.Fatalf("evicted refresh -> %v, want session_evicted", err)
	}
	t.Logf("REFRESH evicted session -> reason=%s (stable across credential types)", autherr.ReasonSessionEvicted)

	// The surviving sessions continue to work.
	if _, _, err := f.svc.Authorize(ctx, b2.Access, "read:doc"); err != nil {
		t.Fatalf("b2 must survive: %v", err)
	}
	if _, _, err := f.svc.Authorize(ctx, b3.Access, "read:doc"); err != nil {
		t.Fatalf("b3 must survive: %v", err)
	}
	t.Logf("surviving sessions b2,b3 authorize normally")
}

func TestIdleAndAbsoluteLifetimeConclusions(t *testing.T) {
	// Long credential TTLs (1h/24h) so the SESSION idle/absolute conclusions
	// are exercised independently of credential expiry.
	f := newGovFixtureTTL(t, 0, 5*time.Minute, 30*time.Minute, time.Hour, 24*time.Hour)
	ctx := context.Background()
	b := govLogin(t, f, "phone-1")

	// Access at +4m counts as activity and resets the idle clock.
	f.clock.advance(4 * time.Minute)
	if _, _, err := f.svc.Authorize(ctx, b.Access, "read:doc"); err != nil {
		t.Fatalf("activity at +4m: %v", err)
	}
	t.Logf("authorize at +4m -> ok (idle reset, access credential still valid)")

	// Another access at +8m (4m later) is still within the 5m idle lifetime.
	f.clock.advance(4 * time.Minute)
	if _, _, err := f.svc.Authorize(ctx, b.Access, "read:doc"); err != nil {
		t.Fatalf("activity at +8m: %v", err)
	}
	t.Logf("authorize at +8m -> ok (4m idle, within 5m)")

	// No activity until +13m: 5m since the last activity -> idle expiry. The
	// long-lived access credential itself is NOT expired, so the session wins.
	f.clock.advance(5 * time.Minute)
	if _, _, err := f.svc.Authorize(ctx, b.Access, "read:doc"); autherr.ReasonOf(err) != autherr.ReasonSessionIdle {
		t.Fatalf("idle access -> %v, want session_idle_expired", err)
	}
	t.Logf("authorize at +13m (5m idle, credential still valid) -> reason=%s", autherr.ReasonSessionIdle)
	if _, err := f.svc.Refresh(ctx, b.Refresh, "phone-1"); autherr.ReasonOf(err) != autherr.ReasonSessionIdle {
		t.Fatalf("idle refresh -> %v, want session_idle_expired", err)
	}
	t.Logf("refresh at +13m -> reason=%s (same idle conclusion)", autherr.ReasonSessionIdle)

	// Absolute expiry is a separate concern: fresh session, keep active until
	// the hard limit, then it must be forced to re-login despite recent use.
	b2 := govLogin(t, f, "phone-2")
	for step := 1; step <= 5; step++ {
		f.clock.advance(4 * time.Minute) // active at +4,+8,+12,+16,+20m (idle-safe)
		if _, _, err := f.svc.Authorize(ctx, b2.Access, "read:doc"); err != nil {
			t.Fatalf("active session at +%dm: %v", step*4, err)
		}
	}
	t.Logf("session phone-2 kept active through +20m (absolute deadline +30m)")
	f.clock.advance(10 * time.Minute)
	if _, _, err := f.svc.Authorize(ctx, b2.Access, "read:doc"); autherr.ReasonOf(err) != autherr.ReasonSessionAbsolute {
		t.Fatalf("absolute access -> %v, want session_absolute_expired", err)
	}
	t.Logf("authorize at +30m despite activity at +20m -> reason=%s", autherr.ReasonSessionAbsolute)
	if _, err := f.svc.Refresh(ctx, b2.Refresh, "phone-2"); autherr.ReasonOf(err) != autherr.ReasonSessionAbsolute {
		t.Fatalf("absolute refresh -> %v, want session_absolute_expired", err)
	}
	t.Logf("refresh at +30m -> reason=%s (renewal cannot cross hard limit)", autherr.ReasonSessionAbsolute)
}

func TestCredentialExpiryStaysDistinctFromSessionExpiry(t *testing.T) {
	// AccessTTL is 10m; session lifetimes are long here, so the CREDENTIAL
	// expiring must remain credential_expired rather than a session reason.
	f := newGovFixture(t, 0, time.Hour, 24*time.Hour)
	ctx := context.Background()
	b := govLogin(t, f, "watch-1")
	f.clock.advance(11 * time.Minute) // access credential (10m) expired, session alive
	if _, _, err := f.svc.Authorize(ctx, b.Access, "read:doc"); autherr.ReasonOf(err) != autherr.ReasonExpiredCredential {
		t.Fatalf("expired credential -> %v, want credential_expired", err)
	}
	t.Logf("access at +11m -> reason=%s (credential expiry separated from session lifetime)", autherr.ReasonExpiredCredential)
}

func TestListSessionsVisibility(t *testing.T) {
	f := newGovFixture(t, 0, 0, 0)
	ctx := context.Background()
	b1 := govLogin(t, f, "laptop")
	b2 := govLogin(t, f, "phone")

	list := f.svc.ListSessions(ctx, "u-reader")
	if len(list) != 2 {
		t.Fatalf("want 2 active sessions visible, got %d", len(list))
	}
	src := map[string]SessionInfo{}
	for _, info := range list {
		src[info.Source] = info
		t.Logf("visible session id=%s source=%s created=%v lastActivity=%v",
			info.ID, info.Source, info.CreatedAt.UTC().Format(time.RFC3339), info.LastActivityAt.UTC().Format(time.RFC3339))
	}
	for _, want := range []string{"laptop", "phone"} {
		if _, ok := src[want]; !ok {
			t.Fatalf("source %s missing from active listing", want)
		}
	}
	// Activity updates LastActivityAt for that session only.
	f.clock.advance(2 * time.Minute)
	if _, _, err := f.svc.Authorize(ctx, b1.Access, "read:doc"); err != nil {
		t.Fatal(err)
	}
	list = f.svc.ListSessions(ctx, "u-reader")
	for _, info := range list {
		if info.ID == b1.SessionID && !info.LastActivityAt.Equal(f.clock.now()) {
			t.Fatalf("b1 lastActivity=%v, want %v", info.LastActivityAt, f.clock.now())
		}
		if info.ID == b2.SessionID && !info.LastActivityAt.Before(f.clock.now()) {
			t.Fatalf("b2 lastActivity must stay older")
		}
	}
	t.Logf("after using b1, only its lastActivity advanced to %v", f.clock.now())
}

func TestPreciseKick(t *testing.T) {
	f := newGovFixture(t, 0, 0, 0)
	ctx := context.Background()
	b1 := govLogin(t, f, "laptop")
	b2 := govLogin(t, f, "phone")
	b3 := govLogin(t, f, "tablet")

	if !f.svc.KickSession(ctx, b2.SessionID) {
		t.Fatal("kick must report true for existing session")
	}
	if f.svc.KickSession(ctx, "nope") {
		t.Fatal("kick must report false for unknown session")
	}
	if _, _, err := f.svc.Authorize(ctx, b2.Access, "read:doc"); autherr.ReasonOf(err) != autherr.ReasonSessionKicked {
		t.Fatalf("kicked access -> %v, want session_kicked", err)
	}
	t.Logf("kicked phone -> reason=%s; other devices untouched", autherr.ReasonSessionKicked)
	for _, b := range []*CredentialBundle{b1, b3} {
		if _, _, err := f.svc.Authorize(ctx, b.Access, "read:doc"); err != nil {
			t.Fatalf("unnamed session must keep working: %v", err)
		}
	}
	t.Logf("laptop and tablet still authorize after kicking phone")

	// KeepOnly laptop: tablet (the other survivor) is kicked; laptop remains.
	n := f.svc.KeepOnlySession(ctx, "u-reader", b1.SessionID)
	if n != 1 {
		t.Fatalf("KeepOnly must kick 1 sibling, got %d", n)
	}
	if _, _, err := f.svc.Authorize(ctx, b3.Access, "read:doc"); autherr.ReasonOf(err) != autherr.ReasonSessionKicked {
		t.Fatalf("tablet -> %v, want session_kicked", err)
	}
	if _, _, err := f.svc.Authorize(ctx, b1.Access, "read:doc"); err != nil {
		t.Fatalf("kept laptop must remain active: %v", err)
	}
	t.Logf("KeepOnly(laptop): kicked=%d, tablet=%s, laptop active", n, autherr.ReasonSessionKicked)
}

func TestConcurrentLoginCapAndAccess(t *testing.T) {
	const capN = 3
	f := newGovFixture(t, capN, 0, 0)
	ctx := context.Background()

	const n = 30
	type res struct {
		b   *CredentialBundle
		err error
	}
	resCh := make(chan res, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			b, err := f.svc.Login(ctx, "u-reader", "pw-reader", fmt.Sprintf("dev-%02d", i))
			resCh <- res{b, err}
		}(i)
	}
	close(start)
	wg.Wait()
	close(resCh)

	active := f.svc.ListSessions(ctx, "u-reader")
	if len(activityIDs(active)) > capN {
		t.Fatalf("active sessions=%d exceed cap %d after concurrent logins", len(active), capN)
	}
	// Evicted bundles must fail with the stable eviction conclusion; the store
	// settles final state, so classify each created session directly.
	evicted := 0
	for r := range resCh {
		if r.err != nil {
			t.Fatalf("login should succeed (cap evicts, never rejects login): %v", r.err)
		}
		s, _ := f.store.Get(ctx, r.b.SessionID)
		if s.State == session.StateEvicted {
			evicted++
			if _, _, err := f.svc.Authorize(ctx, r.b.Access, "read:doc"); autherr.ReasonOf(err) != autherr.ReasonSessionEvicted {
				t.Fatalf("evicted credential access -> %v, want session_evicted", err)
			}
		} else if s.State == session.StateActive {
			if _, _, err := f.svc.Authorize(ctx, r.b.Access, "read:doc"); err != nil {
				t.Fatalf("active credential must authorize: %v", err)
			}
		} else {
			t.Fatalf("unexpected post-login state %s", s.State)
		}
	}
	t.Logf("concurrent logins n=%d cap=%d -> active=%d evicted=%d; every evicted credential reports %s",
		n, capN, len(active), evicted, autherr.ReasonSessionEvicted)
	if len(active) != capN {
		t.Fatalf("want exactly %d active, got %d", capN, len(active))
	}
	if evicted != n-capN {
		t.Fatalf("want %d evicted, got %d", n-capN, evicted)
	}
}

func TestConcurrentRefreshKickNoStateCorruption(t *testing.T) {
	f := newGovFixture(t, 0, 0, 0)
	ctx := context.Background()
	b := govLogin(t, f, "race-device")

	// Concurrent refreshes of the same credential keep the single-use rule,
	// while a concurrent kick races against them; outcomes must remain in the
	// stable set {winner, refresh_replayed, session_kicked} and never corrupt
	// the chain.
	const n = 24
	type outcome struct {
		reason autherr.Reason
		ok     bool
	}
	out := make(chan outcome, n+1)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := f.svc.Refresh(ctx, b.Refresh, "race-device")
			if err == nil {
				out <- outcome{ok: true}
				return
			}
			out <- outcome{reason: autherr.ReasonOf(err)}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if f.svc.KickSession(ctx, b.SessionID) {
			out <- outcome{reason: autherr.ReasonSessionKicked}
		}
	}()
	close(start)
	wg.Wait()
	close(out)

	wins, replays, kicks, others := 0, 0, 0, 0
	for o := range out {
		switch {
		case o.ok:
			wins++
		case o.reason == autherr.ReasonReusedRefresh:
			replays++
		case o.reason == autherr.ReasonSessionKicked:
			kicks++
		default:
			others++
			t.Errorf("unexpected race outcome: %s", o.reason)
		}
	}
	t.Logf("race refresh n=%d + kick: winners=%d replays=%s_count=%d kicks=%d other=%d",
		n, wins, autherr.ReasonReusedRefresh, replays, kicks, others)
	if others != 0 {
		t.Fatalf("unexpected outcomes: %d", others)
	}
	// Either the single winner or the kick may land first; in BOTH orderings
	// the replay rule and the kick rule stay distinguishable. If a winner
	// existed before the kick, its rotated chain is still kicked afterwards.
	s, _ := f.store.Get(ctx, b.SessionID)
	if s.State != session.StateInvalid && s.State != session.StateKicked {
		t.Fatalf("final state=%s, want invalid (replay) or kicked", s.State)
	}
	t.Logf("final chain state=%s (one of replay-invalid/kicked, no corruption)", s.State)
	// Once kicked/killed, any later access gives a stable terminal conclusion.
	if _, _, err := f.svc.Authorize(ctx, b.Access, "read:doc"); autherr.ReasonOf(err) != autherr.ReasonSessionInvalid &&
		autherr.ReasonOf(err) != autherr.ReasonSessionKicked {
		t.Fatalf("post-race access -> %v, want session_invalid or session_kicked", err)
	}
}

func activityIDs(list []SessionInfo) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = s.ID
	}
	return out
}
