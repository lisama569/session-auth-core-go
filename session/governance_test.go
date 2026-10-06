package session

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

var govBase = time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)

func createAt(t *testing.T, st Store, id, subject string, created, active time.Time) *Session {
	t.Helper()
	s, err := st.Create(context.Background(), &Session{
		ID: id, Subject: subject, Role: "reader", Source: "src-" + id,
		State: StateActive, CreatedAt: created, LastActiveAt: active,
		RefreshJTI: "rt-" + id,
	})
	if err != nil {
		t.Fatalf("create %s: %v", id, err)
	}
	return s
}

func TestCapEvictsLeastRecentlyActive(t *testing.T) {
	st := NewStoreWithConfig(Config{MaxActivePerSubject: 2})
	t0 := govBase

	// s1 idle since t0, s2 active at t0+10m: s1 is the LRU victim.
	createAt(t, st, "s1", "u", t0, t0)
	createAt(t, st, "s2", "u", t0, t0.Add(10*time.Minute))
	createAt(t, st, "s3", "u", t0, t0.Add(20*time.Minute))

	s1, _ := st.Get(context.Background(), "s1")
	if s1.State != StateEvicted {
		t.Fatalf("input=3rd login with s1 idle longest -> s1 state=%s, want evicted", s1.State)
	}
	t.Logf("cap=2, activity s1<t0> s2<t0+10m> s3<t0+20m>: s1 -> state=%s why=%q", s1.State, s1.InvalidationWhy)

	// Eviction is sticky: even the currently valid refresh JTI is rejected
	// with the evicted reason, not a replay and not a generic invalid.
	res := st.Rotate(context.Background(), "s1", "rt-s1", "rt-x", t0.Add(21*time.Minute))
	if res.OK || res.Reason != StateEvicted || res.Replayed {
		t.Fatalf("evicted session rotate -> %+v, want reason=evicted replayed=false", res)
	}
	t.Logf("rotate on evicted s1 -> ok=%v reason=%s replayed=%v (distinguishable from replay/invalid)", res.OK, res.Reason, res.Replayed)

	// The survivors stay active and usable.
	for _, id := range []string{"s2", "s3"} {
		res := st.Rotate(context.Background(), id, "rt-"+id, "rt2-"+id, t0.Add(22*time.Minute))
		if !res.OK {
			t.Fatalf("survivor %s must still rotate, got %+v", id, res)
		}
	}
	t.Logf("survivors s2,s3 rotate fine; active set = {s2,s3}, size within cap=2")
}

func TestConcurrentCreateNeverExceedsCap(t *testing.T) {
	const cap = 3
	st := NewStoreWithConfig(Config{MaxActivePerSubject: cap})
	t0 := govBase

	const n = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// Stagger activity timestamps so LRU order is well defined.
			at := t0.Add(time.Duration(i) * time.Second)
			_, err := st.Create(context.Background(), &Session{
				ID: fmt.Sprintf("cs-%02d", i), Subject: "u", Role: "reader",
				State: StateActive, CreatedAt: at, LastActiveAt: at,
				RefreshJTI: fmt.Sprintf("rt-%02d", i),
			})
			if err != nil {
				t.Errorf("create: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	active := st.ListActive(context.Background(), "u", t0.Add(time.Hour))
	t.Logf("concurrent create n=%d cap=%d -> active=%d", n, cap, len(active))
	if len(active) != cap {
		t.Fatalf("active set must equal cap=%d, got %d", cap, len(active))
	}
	// The survivors must be exactly the three most recently active sessions.
	want := map[string]bool{"cs-29": true, "cs-30": true, "cs-31": true}
	for _, s := range active {
		if !want[s.ID] {
			t.Fatalf("session %s survived but is not among the 3 most recently active", s.ID)
		}
		delete(want, s.ID)
	}
	if len(want) != 0 {
		t.Fatalf("expected survivors missing: %v", want)
	}
	t.Logf("survivors are exactly the 3 most recently active sessions; everyone else evicted")
}

func TestConcurrentCreateRotateTouchStaysConsistent(t *testing.T) {
	const cap = 4
	st := NewStoreWithConfig(Config{MaxActivePerSubject: cap, IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour})
	t0 := govBase

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			at := t0.Add(time.Duration(i%8) * time.Minute)
			id := fmt.Sprintf("mx-%02d", i)
			_, _ = st.Create(context.Background(), &Session{
				ID: id, Subject: "u", Role: "reader",
				State: StateActive, CreatedAt: at, LastActiveAt: at,
				RefreshJTI: "rt-" + id,
			})
			// Mix in activity and rotations racing the evictions.
			_, _, _ = st.Touch(context.Background(), id, at.Add(time.Second))
			st.Rotate(context.Background(), id, "rt-"+id, "rt2-"+id, at.Add(2*time.Second))
		}(i)
	}
	close(start)
	wg.Wait()

	active := st.ListActive(context.Background(), "u", t0.Add(30*time.Minute))
	t.Logf("64 goroutines create+touch+rotate, cap=%d -> final active=%d", cap, len(active))
	if len(active) > cap {
		t.Fatalf("active set %d exceeds cap %d", len(active), cap)
	}
}

func TestIdleExpiryAndActivityReset(t *testing.T) {
	st := NewStoreWithConfig(Config{IdleTTL: 30 * time.Minute})
	t0 := govBase
	createAt(t, st, "idle-1", "u", t0, t0)

	// Activity at +20m resets the idle clock.
	_, state, err := st.Touch(context.Background(), "idle-1", t0.Add(20*time.Minute))
	if err != nil || state != StateActive {
		t.Fatalf("touch at +20m -> state=%s err=%v, want active", state, err)
	}
	t.Logf("idleTTL=30m; touch at +20m -> state=%s (idle clock reset)", state)

	// +45m is only 25m after the last activity: still active.
	_, state, _ = st.Touch(context.Background(), "idle-1", t0.Add(45*time.Minute))
	if state != StateActive {
		t.Fatalf("touch at +45m (25m after activity) -> state=%s, want active", state)
	}
	t.Logf("touch at +45m (25m since last activity) -> state=%s", state)

	// +80m is 35m after the last activity at +45m: idle-expired.
	_, state, _ = st.Touch(context.Background(), "idle-1", t0.Add(80*time.Minute))
	if state != StateIdleExpired {
		t.Fatalf("touch at +80m (35m idle) -> state=%s, want idle_expired", state)
	}
	t.Logf("touch at +80m (35m since last activity) -> state=%s (sticky)", state)

	// Sticky: refresh with the valid JTI now reports idle expiry, not replay.
	res := st.Rotate(context.Background(), "idle-1", "rt-idle-1", "rt-x", t0.Add(81*time.Minute))
	if res.OK || res.Reason != StateIdleExpired || res.Replayed {
		t.Fatalf("rotate on idle-expired -> %+v, want reason=idle_expired", res)
	}
	t.Logf("rotate on idle-expired session -> reason=%s replayed=%v", res.Reason, res.Replayed)
}

func TestAbsoluteExpiryCannotBeExtendedByRotation(t *testing.T) {
	st := NewStoreWithConfig(Config{IdleTTL: time.Hour, AbsoluteTTL: 2 * time.Hour})
	t0 := govBase
	createAt(t, st, "abs-1", "u", t0, t0)

	// Rotate every 30 minutes: idle clock keeps resetting, chain advances.
	jti := "rt-abs-1"
	for i := 1; i <= 3; i++ {
		at := t0.Add(time.Duration(i) * 30 * time.Minute)
		res := st.Rotate(context.Background(), "abs-1", jti, fmt.Sprintf("rt-abs-1-v%d", i), at)
		if !res.OK {
			t.Fatalf("rotation %d at +%dm must succeed (idle reset each time): %+v", i, i*30, res)
		}
		jti = fmt.Sprintf("rt-abs-1-v%d", i)
		t.Logf("rotation %d at +%dm -> ok, version=%d (idle clock reset, absolute clock untouched)", i, i*30, res.Session.Version)
	}

	// At +2h the absolute lifetime is reached even though the session was
	// active 30 minutes ago and holds the currently valid refresh JTI.
	res := st.Rotate(context.Background(), "abs-1", jti, "rt-final", t0.Add(2*time.Hour))
	if res.OK || res.Reason != StateAbsExpired {
		t.Fatalf("rotate at absolute limit -> %+v, want reason=absolute_expired", res)
	}
	t.Logf("rotate at +2h (absoluteTTL=2h, last activity +90m) -> reason=%s: refresh cannot extend absolute lifetime", res.Reason)

	// Touch (authentication) observes the same terminal state.
	_, state, _ := st.Touch(context.Background(), "abs-1", t0.Add(2*time.Hour))
	if state != StateAbsExpired {
		t.Fatalf("touch after absolute expiry -> state=%s", state)
	}
	t.Logf("touch after absolute expiry -> state=%s (consistent across entry points)", state)
}

func TestListActiveAndKick(t *testing.T) {
	st := NewStoreWithConfig(Config{MaxActivePerSubject: 10})
	t0 := govBase
	createAt(t, st, "k1", "u", t0, t0)
	createAt(t, st, "k2", "u", t0, t0.Add(5*time.Minute))
	createAt(t, st, "k3", "u", t0, t0.Add(9*time.Minute))
	createAt(t, st, "other", "v", t0, t0)

	active := st.ListActive(context.Background(), "u", t0.Add(10*time.Minute))
	if len(active) != 3 || active[0].ID != "k3" {
		t.Fatalf("list active -> %v, want 3 sessions most-recent-first", ids(active))
	}
	t.Logf("list active for u -> %v (most recently active first)", ids(active))

	// Kick exactly one: the others keep working.
	st.Kick(context.Background(), "k2", t0.Add(10*time.Minute))
	res := st.Rotate(context.Background(), "k2", "rt-k2", "rt-x", t0.Add(11*time.Minute))
	if res.OK || res.Reason != StateKicked {
		t.Fatalf("rotate kicked k2 -> %+v, want reason=kicked", res)
	}
	t.Logf("kick k2; rotate k2 -> reason=%s", res.Reason)
	for _, id := range []string{"k1", "k3"} {
		res := st.Rotate(context.Background(), id, "rt-"+id, "rt2-"+id, t0.Add(11*time.Minute))
		if !res.OK {
			t.Fatalf("un-kicked %s must be unaffected: %+v", id, res)
		}
	}
	t.Logf("k1,k3 unaffected by kicking k2")

	// Kick everyone except the current session.
	st.KickOthers(context.Background(), "u", "k3", t0.Add(12*time.Minute))
	active = st.ListActive(context.Background(), "u", t0.Add(12*time.Minute))
	if len(active) != 1 || active[0].ID != "k3" {
		t.Fatalf("after KickOthers keep=k3 -> active=%v, want [k3]", ids(active))
	}
	t.Logf("KickOthers keep=k3 -> active=%v; k1 also kicked, k3 kept", ids(active))

	// Another subject's session is untouched.
	if _, state, _ := st.Touch(context.Background(), "other", t0.Add(12*time.Minute)); state != StateActive {
		t.Fatalf("other subject session must be unaffected, state=%s", state)
	}
	t.Logf("subject v's session unaffected by u's kicks")
}

func ids(ss []*Session) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.ID)
	}
	return out
}
