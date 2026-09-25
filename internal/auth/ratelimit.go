package auth

import (
	"sync"
	"time"
)

type bucket struct {
	count       int
	windowStart time.Time
}

// RateLimiter 按 key（账号或来源）做固定窗口尝试计数。
// 行为约定：
//   - 同一窗口内第 1..maxAttempts 次尝试放行，第 maxAttempts+1 次起拒绝；
//   - 窗口自首次尝试起计时，经过 window 后下一次尝试自动开启新窗口（解除限制）；
//   - 被限流时不增加额外计数，RetryAfter 给出可预期的剩余等待时间。
type RateLimiter struct {
	mu          sync.Mutex
	clock       Clock
	maxAttempts int
	window      time.Duration
	buckets     map[string]*bucket
}

// NewRateLimiter 构造限流器。
func NewRateLimiter(clock Clock, maxAttempts int, window time.Duration) *RateLimiter {
	if clock == nil {
		clock = SystemClock{}
	}
	return &RateLimiter{
		clock:       clock,
		maxAttempts: maxAttempts,
		window:      window,
		buckets:     map[string]*bucket{},
	}
}

// allow 同时返回该 key 当前窗口内已发生的尝试次数（用于日志）。
func (l *RateLimiter) allow(key string) (bool, int, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	b, ok := l.buckets[key]
	if !ok || now.Sub(b.windowStart) >= l.window {
		// 窗口不存在或已结束：开启新窗口（限制解除后的行为确定）。
		b = &bucket{count: 0, windowStart: now}
		l.buckets[key] = b
	}
	b.count++
	return b.count <= l.maxAttempts, b.count, b.windowStart
}

// Allow 记录一次尝试并报告是否放行。
func (l *RateLimiter) Allow(key string) bool {
	ok, _, _ := l.allow(key)
	return ok
}

// State 返回（当前窗口尝试次数，窗口起点，是否仍在窗口内），供日志使用。
func (l *RateLimiter) State(key string) (int, time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	b, ok := l.buckets[key]
	if !ok {
		return 0, now, false
	}
	active := now.Sub(b.windowStart) < l.window
	if !active {
		return 0, b.windowStart, false
	}
	return b.count, b.windowStart, true
}

// RetryAfter 报告该 key 还需等待多久解除限制；未被限流返回 0。
func (l *RateLimiter) RetryAfter(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	b, ok := l.buckets[key]
	if !ok || now.Sub(b.windowStart) >= l.window {
		return 0
	}
	if b.count <= l.maxAttempts {
		return 0
	}
	elapsed := now.Sub(b.windowStart)
	left := l.window - elapsed
	if left < 0 {
		return 0
	}
	return left
}

// Reset 清除指定 key 的计数。
func (l *RateLimiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}
