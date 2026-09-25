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
