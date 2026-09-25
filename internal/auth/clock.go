package auth

import "time"

// Clock 抽象时间来源，便于测试过期与限流窗口。
type Clock interface {
	Now() time.Time
}

// SystemClock 使用墙钟时间。
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

// FakeClock 供测试使用的可控时钟。
type FakeClock struct {
	t time.Time
}

// NewFakeClock 从给定时刻构造可控时钟。
func NewFakeClock(start time.Time) *FakeClock { return &FakeClock{t: start} }

func (c *FakeClock) Now() time.Time { return c.t }

// Advance 将时钟向前推进 d。
func (c *FakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }
