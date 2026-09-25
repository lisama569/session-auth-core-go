package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestWindowBlocksThenRecovers(t *testing.T) {
	const maxAttempts = 3
	const window = time.Minute
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	l := New(maxAttempts, window)
	ctx := context.Background()
	key := Key{Type: KeyAccount, ID: "u-1"}

	for i := 1; i <= maxAttempts; i++ {
		d := l.Allow(ctx, key, now)
		if !d.Allowed {
			t.Fatalf("attempt %d should be allowed: %+v", i, d)
		}
		t.Logf("attempt %d -> allowed remaining=%d", i, d.Remaining)
	}

	// Attempts 4 and 5 are blocked for the remainder of the window.
	for _, at := range []time.Time{now.Add(10 * time.Second), now.Add(30 * time.Second)} {
		d := l.Allow(ctx, key, at)
		if d.Allowed || d.RetryAfter <= 0 {
			t.Fatalf("within-window attempt must be blocked: %+v", d)
		}
		t.Logf("attempt at +%v -> blocked retryAfter=%v", at.Sub(now), d.RetryAfter)
	}

	// After the fixed-window boundary, behavior is exactly as a fresh window.
	recovered := now.Add(window)
	for i := 1; i <= maxAttempts; i++ {
		d := l.Allow(ctx, key, recovered.Add(time.Duration(i-1)*time.Second))
		if !d.Allowed {
			t.Fatalf("post-recovery attempt %d must be allowed: %+v", i, d)
		}
		t.Logf("recovery attempt %d -> allowed remaining=%d", i, d.Remaining)
	}
	d := l.Allow(ctx, key, recovered.Add(3*time.Second))
	if d.Allowed {
		t.Fatalf("attempt %d in new window must be blocked again", maxAttempts+1)
	}
	t.Logf("new-window attempt %d -> blocked as expected", maxAttempts+1)
}

func TestKeysAreIndependent(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	l := New(1, time.Minute)
	ctx := context.Background()
	a := Key{Type: KeyAccount, ID: "a"}
	b := Key{Type: KeySource, ID: "10.0.0.1"}

	if !l.Allow(ctx, a, now).Allowed || !l.Allow(ctx, b, now).Allowed {
		t.Fatal("first attempts on distinct keys must be allowed")
	}
	if l.Allow(ctx, a, now).Allowed {
		t.Fatal("second attempt on account must block")
	}
	if l.Allow(ctx, b, now).Allowed {
		t.Fatal("second attempt on source must block")
	}
	t.Logf("account and source buckets block independently")
}

func TestReset(t *testing.T) {
	now := time.Now()
	l := New(1, time.Minute)
	ctx := context.Background()
	k := Key{Type: KeyAccount, ID: "u-9"}
	l.Allow(ctx, k, now)
	if l.Allow(ctx, k, now).Allowed {
		t.Fatal("expected block")
	}
	l.Reset(ctx, k)
	if !l.Allow(ctx, k, now).Allowed {
		t.Fatal("expected recovery after reset")
	}
	t.Logf("reset restores availability immediately")
}
