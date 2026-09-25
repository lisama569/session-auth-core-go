// Package ratelimit provides an in-memory fixed-window limiter keyed by an
// opaque identity (account id or source address). Behavior is deterministic:
// within a window the first maxAttempts calls are allowed, further calls are
// rejected with a positive RetryAfter; once the window boundary passes the
// bucket resets atomically and calls are allowed again.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Key types identify the dimension being limited.
type KeyType string

const (
	KeyAccount KeyType = "account"
	KeySource  KeyType = "source"
)

// Key is a limiter bucket key.
type Key struct {
	Type KeyType
	ID   string
}

func (k Key) String() string { return string(k.Type) + ":" + k.ID }

// Decision is the result of an Allow check.
type Decision struct {
	Allowed    bool
	Remaining  int
	RetryAfter time.Duration
}

// Limiter is a fixed-window, in-memory rate limiter.
type Limiter interface {
	Allow(ctx context.Context, key Key, now time.Time) Decision
	Reset(ctx context.Context, key Key)
}

type bucket struct {
	windowStart time.Time
	count       int
}

type fixedWindow struct {
	mu          sync.Mutex
	maxAttempts int
	window      time.Duration
	buckets     map[Key]bucket
}

// New returns a limiter allowing maxAttempts attempts per window.
func New(maxAttempts int, window time.Duration) Limiter {
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	if window <= 0 {
		window = time.Minute
	}
	return &fixedWindow{
		maxAttempts: maxAttempts,
		window:      window,
		buckets:     make(map[Key]bucket),
	}
}

func (l *fixedWindow) Allow(_ context.Context, key Key, now time.Time) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.buckets[key]
	start := now.Truncate(l.window)
	// Atomically roll over to a new fixed window.
	if !b.windowStart.Equal(start) {
		b = bucket{windowStart: start}
	}
	b.count++
	l.buckets[key] = b

	windowEnd := start.Add(l.window)
	if b.count <= l.maxAttempts {
		return Decision{
			Allowed:   true,
			Remaining: l.maxAttempts - b.count,
		}
	}
	return Decision{
		Allowed:    false,
		Remaining:  0,
		RetryAfter: windowEnd.Sub(now),
	}
}

func (l *fixedWindow) Reset(_ context.Context, key Key) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}
