package session

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func newActive(t *testing.T, st Store, id, jti string) *Session {
	t.Helper()
	s, err := st.Create(context.Background(), &Session{
		ID: id, Subject: "u-1", Role: "reader", Source: "127.0.0.1",
		State: StateActive, CreatedAt: time.Now(), RefreshJTI: jti,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return s
}

func TestRotateSingleWinner(t *testing.T) {
	st := NewStore()
	newActive(t, st, "sess_1", "rt_1")

	res := st.Rotate(context.Background(), "sess_1", "rt_1", "rt_2", time.Now())
	if !res.OK || res.Session.RefreshJTI != "rt_2" || res.Session.Version != 1 {
		t.Fatalf("first rotation must win: %+v", res)
	}
	t.Logf("rotation 1: want=rt_1 next=rt_2 -> ok, version=%d", res.Session.Version)

	// Reusing the consumed JTI loses and invalidates the chain.
	res = st.Rotate(context.Background(), "sess_1", "rt_1", "rt_3", time.Now())
	if res.OK || res.Reason != StateInvalid {
		t.Fatalf("replay must lose and invalidate: %+v", res)
	}
	t.Logf("replay with stale rt_1 -> reason=%s, chain state=%s", res.Reason, res.Session.State)

	// The chain is terminally invalid: even the newest JTI cannot rotate.
	res = st.Rotate(context.Background(), "sess_1", "rt_2", "rt_4", time.Now())
	if res.OK || res.Reason != StateInvalid {
		t.Fatalf("invalid chain must stay invalid: %+v", res)
	}
	t.Logf("rotate on invalidated chain -> reason=%s (sticky)", res.Reason)
}

func TestRotateConcurrentExactlyOneWinner(t *testing.T) {
	st := NewStore()
	newActive(t, st, "sess_c", "rt_0")

	const n = 32
	var wg sync.WaitGroup
	results := make(chan RotateResult, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results <- st.Rotate(context.Background(), "sess_c", "rt_0", fmt.Sprintf("rt_next_%d", i), time.Now())
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	winners, losers := 0, 0
	for r := range results {
		if r.OK {
			winners++
		} else {
			losers++
			if r.Reason != StateInvalid {
				t.Fatalf("loser must observe StateInvalid, got %s", r.Reason)
			}
		}
	}
	t.Logf("concurrent rotation: n=%d winners=%d losers=%d", n, winners, losers)
	if winners != 1 || losers != n-1 {
		t.Fatalf("exactly one winner required, got winners=%d losers=%d", winners, losers)
	}

	s, err := st.Get(context.Background(), "sess_c")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if s.State != StateInvalid {
		t.Fatalf("chain must be invalid after concurrent reuse, got %s", s.State)
	}
	t.Logf("final chain state=%s version=%d why=%q", s.State, s.Version, s.InvalidationWhy)
}

func TestRevokeIsSticky(t *testing.T) {
	st := NewStore()
	newActive(t, st, "sess_r", "rt_1")
	st.Revoke(context.Background(), "", "sess_r")

	res := st.Rotate(context.Background(), "sess_r", "rt_1", "rt_2", time.Now())
	if res.OK || res.Reason != StateRevoked {
		t.Fatalf("revoked session must not rotate: %+v", res)
	}
	t.Logf("rotate on revoked session -> reason=%s", res.Reason)

	s, _ := st.Get(context.Background(), "sess_r")
	if s.State != StateRevoked {
		t.Fatalf("state=%s, want revoked", s.State)
	}
}

func TestUnknownSessionRotate(t *testing.T) {
	st := NewStore()
	res := st.Rotate(context.Background(), "nope", "x", "y", time.Now())
	if res.OK || res.Reason != StateInvalid {
		t.Fatalf("unknown session must report invalid: %+v", res)
	}
	t.Logf("rotate unknown session -> reason=%s", res.Reason)
}

// --- session governance tests ---

type fixedClock struct{ t time.Time }

func (c *fixedClock) get() time.Time { return c.t }

func newGov(t *testing.T, maxActive int, idle, absolute time.Duration) (Store, *fixedClock) {
	t.Helper()
	clk := &fixedClock{t: time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)}
	st := NewGovernedStore(GovernanceConfig{
		MaxActivePerSubject: maxActive,
		IdleTTL:             idle,
		AbsoluteTTL:         absolute,
		Clock:               clk.get,
	})
	return st, clk
}

func govSession(id, subject string, created, lastActivity time.Time) *Session {
	return &Session{
		ID: id, Subject: subject, Role: "reader", Source: "src-" + id,
		State: StateActive, CreatedAt: created, LastActivityAt: lastActivity,
		RefreshJTI: "jti-" + id,
	}
}

func TestCapEvictsLeastRecentlyActive(t *testing.T) {
	ctx := context.Background()
	st, clk := newGov(t, 2, 0, 0)
	base := clk.t

	a, err := st.Create(ctx, govSession("sA", "u1", base, base))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := st.Create(ctx, govSession("sB", "u1", base.Add(time.Minute), base.Add(time.Minute)))
	// c arrives; active set {A,B,c} exceeds cap 2 -> A (oldest activity) evicted.
	c, _ := st.Create(ctx, govSession("sC", "u1", base.Add(2*time.Minute), base.Add(2*time.Minute)))
	t.Logf("created A@0 B@1m C@2m with cap=2 -> expect sA evicted (oldest lastActivity)")

	if got, _ := st.Get(ctx, "sA"); got.State != StateEvicted {
		t.Fatalf("sA state=%s, want evicted", got.State)
	}
	if got, _ := st.Get(ctx, "sB"); got.State != StateActive {
		t.Fatalf("sB state=%s, want active", got.State)
	}
	if got, _ := st.Get(ctx, "sC"); got.State != StateActive {
		t.Fatalf("sC state=%s, want active", got.State)
	}
	t.Logf("states after overflow: sA=%s(%q) sB=%s sC=%s",
		a.State, mustGet(t, st, "sA").InvalidationWhy, b.State, c.State)

	// An evicted session fails on every credential with a stable conclusion.
	if r := st.Touch(ctx, "sA", clk.t); r.OK || r.Reason != StateEvicted {
		t.Fatalf("touch evicted -> %+v, want evicted", r)
	}
	if r := st.Rotate(ctx, "sA", "jti-sA", "next", clk.t); r.OK || r.Reason != StateEvicted || r.Replayed {
		t.Fatalf("rotate evicted -> %+v, want evicted/not-replayed", r)
	}
	t.Logf("evicted session: touch=%s rotate=%s (stable, never invalid_credential)",
		StateEvicted, StateEvicted)
}

func mustGet(t *testing.T, st Store, id string) *Session {
	t.Helper()
	s, err := st.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get %s: %v", id, err)
	}
	return s
}

func TestCapEvictionIsPerSubject(t *testing.T) {
	ctx := context.Background()
	st, clk := newGov(t, 1, 0, 0)
	base := clk.t
	if _, err := st.Create(ctx, govSession("a1", "uA", base, base)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(ctx, govSession("b1", "uB", base, base)); err != nil {
		t.Fatal(err)
	}
	// Different subjects do not evict one another.
	if got := mustGet(t, st, "a1"); got.State != StateActive {
		t.Fatalf("a1=%s, other subject must not evict", got.State)
	}
	if got := mustGet(t, st, "b1"); got.State != StateActive {
		t.Fatalf("b1=%s", got.State)
	}
	// Same subject's second login evicts its first.
	if _, err := st.Create(ctx, govSession("a2", "uA", base.Add(time.Minute), base.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	if got := mustGet(t, st, "a1"); got.State != StateEvicted {
		t.Fatalf("a1=%s, want evicted by a2", got.State)
	}
	t.Logf("cap is per-subject: uA {a1 evicted, a2 active}, uB {b1 active}")
}

func TestTouchResetsIdleClock(t *testing.T) {
	ctx := context.Background()
	st, clk := newGov(t, 0, 5*time.Minute, 0)
	s0, _ := st.Create(ctx, govSession("sI", "u1", clk.t, clk.t))

	clk.t = clk.t.Add(4 * time.Minute)
	if r := st.Touch(ctx, "sI", clk.t); !r.OK {
		t.Fatalf("activity at +4m must keep session alive: %+v", r)
	}
	t.Logf("touch at +4m -> ok, idle clock reset to %v", clk.t)

	// Without the touch, +5m would have expired; now +4m more is still alive.
	clk.t = clk.t.Add(4 * time.Minute)
	if r := st.Touch(ctx, "sI", clk.t); !r.OK {
		t.Fatalf("activity at +8m (4m after reset) must stay alive: %+v", r)
	}
	t.Logf("touch at +8m (4m since last activity) -> ok")

	// Go idle for longer than the TTL with no activity.
	clk.t = clk.t.Add(6 * time.Minute)
	if r := st.Touch(ctx, "sI", clk.t); r.OK || r.Reason != StateIdleExpired {
		t.Fatalf("touch at +14m -> %+v, want idle_expired", r)
	}
	t.Logf("touch at +14m (6m idle) -> reason=%s sticky=%v",
		StateIdleExpired, mustGet(t, st, "sI").State)
	_ = s0
}

func TestIdleExpiryExactBoundary(t *testing.T) {
	ctx := context.Background()
	st, clk := newGov(t, 0, time.Minute, 0)
	_, _ = st.Create(ctx, govSession("sB", "u1", clk.t, clk.t))
	// At exactly idle deadline (now == lastActivity + idleTTL): expired.
	if r := st.Touch(ctx, "sB", clk.t.Add(time.Minute)); r.OK || r.Reason != StateIdleExpired {
		t.Fatalf("boundary touch -> %+v, want idle_expired", r)
	}
}

func TestAbsoluteExpiryBeatsRenewal(t *testing.T) {
	ctx := context.Background()
	st, clk := newGov(t, 0, 0, 10*time.Minute)
	_, _ = st.Create(ctx, govSession("sH", "u1", clk.t, clk.t))

	// Plenty of activity renews the idle clock but can never move the deadline.
	for i := 0; i < 3; i++ {
		clk.t = clk.t.Add(3 * time.Minute)
		if r := st.Touch(ctx, "sH", clk.t); !r.OK {
			t.Fatalf("touch #%d at +%dm must stay alive: %+v", i+1, 3*(i+1), r)
		}
	}
	t.Logf("repeated activity until +9m (idle clock fresh); absolute deadline=+10m")
	// At +12m the session is past its absolute lifetime despite recent activity.
	clk.t = clk.t.Add(3 * time.Minute)
	if r := st.Touch(ctx, "sH", clk.t); r.OK || r.Reason != StateAbsoluteExpired {
		t.Fatalf("touch past absolute deadline -> %+v, want absolute_expired", r)
	}
	t.Logf("touch at +12m -> reason=%s (recent activity cannot extend hard limit)", StateAbsoluteExpired)

	// Rotation is refused on the same basis.
	if r := st.Rotate(ctx, "sH", "jti-sH", "next", clk.t); r.OK || r.Reason != StateAbsoluteExpired {
		t.Fatalf("rotate past absolute deadline -> %+v, want absolute_expired", r)
	}
}

func TestAbsoluteBeforeIdleWhenBothElapsed(t *testing.T) {
	ctx := context.Background()
	st, clk := newGov(t, 0, 2*time.Minute, 5*time.Minute)
	_, _ = st.Create(ctx, govSession("sX", "u1", clk.t, clk.t))
	clk.t = clk.t.Add(10 * time.Minute) // both elapsed
	if r := st.Touch(ctx, "sX", clk.t); r.OK || r.Reason != StateAbsoluteExpired {
		t.Fatalf("both elapsed -> %+v, want absolute_expired precedence", r)
	}
	t.Logf("both idle and absolute elapsed -> reason=%s (absolute takes precedence)", StateAbsoluteExpired)
}

func TestKickOneAndKeepOnly(t *testing.T) {
	ctx := context.Background()
	st, _ := newGov(t, 0, 0, 0)
	for _, id := range []string{"k1", "k2", "k3"} {
		if _, err := st.Create(ctx, govSession(id, "u1", time.Now(), time.Now())); err != nil {
			t.Fatal(err)
		}
	}

	if !st.Kick(ctx, "k2", time.Now()) {
		t.Fatal("kick existing session must report true")
	}
	if st.Kick(ctx, "missing", time.Now()) {
		t.Fatal("kick unknown session must report false")
	}
	if r := st.Touch(ctx, "k2", time.Now()); r.OK || r.Reason != StateKicked {
		t.Fatalf("kicked touch -> %+v, want kicked", r)
	}
	if r := st.Rotate(ctx, "k2", "jti-k2", "n", time.Now()); r.OK || r.Reason != StateKicked {
		t.Fatalf("kicked rotate -> %+v, want kicked", r)
	}
	// The named session and unrelated sessions keep working.
	if r := st.Touch(ctx, "k1", time.Now()); !r.OK {
		t.Fatalf("k1 must survive k2 kick: %+v", r)
	}
	if r := st.Touch(ctx, "k3", time.Now()); !r.OK {
		t.Fatalf("k3 must survive k2 kick: %+v", r)
	}
	t.Logf("kick k2 -> k2=%s, k1/k3 active", StateKicked)

	n := st.KeepOnly(ctx, "u1", "k1", time.Now())
	if n != 1 {
		t.Fatalf("KeepOnly k1 must kick 1 remaining sibling, got %d", n)
	}
	if r := st.Touch(ctx, "k3", time.Now()); r.OK || r.Reason != StateKicked {
		t.Fatalf("k3 -> %+v, want kicked", r)
	}
	if r := st.Touch(ctx, "k1", time.Now()); !r.OK {
		t.Fatalf("kept session k1 must stay active: %+v", r)
	}
	t.Logf("KeepOnly(k1): kicked=%d, k3=%s, k1 active", n, StateKicked)
}

func TestListActiveSettlesExpired(t *testing.T) {
	ctx := context.Background()
	st, clk := newGov(t, 0, time.Minute, 0)
	_, _ = st.Create(ctx, govSession("l1", "u1", clk.t, clk.t))
	_, _ = st.Create(ctx, govSession("l2", "u1", clk.t, clk.t))
	clk.t = clk.t.Add(90 * time.Second)
	active := st.ListActive(ctx, "u1")
	if len(active) != 0 {
		t.Fatalf("idle sessions must not be listed active, got %d", len(active))
	}
	for _, id := range []string{"l1", "l2"} {
		if got := mustGet(t, st, id); got.State != StateIdleExpired {
			t.Fatalf("%s state=%s, want idle_expired", id, got.State)
		}
	}
	t.Logf("ListActive at +90s lazily settled both sessions to %s", StateIdleExpired)
}

func TestConcurrentCreateNeverExceedsCap(t *testing.T) {
	ctx := context.Background()
	const capN = 3
	st, clk := newGov(t, capN, 0, 0)
	base := clk.t

	const n = 40
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// Distinct activity instants make the eviction order observable.
			at := base.Add(time.Duration(i) * time.Second)
			id := fmt.Sprintf("p%02d", i)
			_, _ = st.Create(ctx, govSession(id, "u1", at, at))
		}(i)
	}
	close(start)
	wg.Wait()

	active := st.ListActive(ctx, "u1")
	if len(active) != capN {
		t.Fatalf("after %d concurrent creates, active=%d, want exactly %d", n, len(active), capN)
	}
	// The survivors must be exactly the newest three by activity.
	for _, id := range []string{"p39", "p38", "p37"} {
		if got := mustGet(t, st, id); got.State != StateActive {
			t.Fatalf("%s=%s, want active (newest must survive)", id, got.State)
		}
	}
	if got := mustGet(t, st, "p36"); got.State != StateEvicted {
		t.Fatalf("p36=%s, want evicted", got.State)
	}
	t.Logf("concurrent creates n=%d cap=%d -> active set=%v, older evicted=%s",
		n, capN, ids(active), StateEvicted)
}

func ids(ss []*Session) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.ID
	}
	return out
}
