// Package session holds in-memory session-chain state. The critical operation
// is refresh-credential rotation, implemented as a compare-and-swap under a
// single mutex:
//
//   - exactly one submission carrying the currently expected refresh JTI wins;
//   - any concurrent or later submission with a stale JTI loses and marks the
//     whole chain StateInvalid exactly once;
//   - losers and subsequent uses all observe the same terminal invalid state,
//     so the conclusion is identical under the race detector.
//
// Session governance (all enforced under the same mutex, so concurrent
// create/rotate/touch cannot exceed limits or evict the wrong session):
//
//   - MaxActivePerSubject caps the live sessions per account; creating beyond
//     the cap evicts the least-recently-active session (StateEvicted, sticky);
//   - IdleTTL expires a session with no activity (StateIdleExpired);
//   - AbsoluteTTL expires a session measured from creation (StateAbsExpired)
//     and cannot be extended by rotation;
//   - authentication (Touch) and rotation both count as activity and reset
//     the idle clock;
//   - Kick/KickOthers mark sessions StateKicked (sticky, distinguishable).
package session

import (
	"context"
	"errors"
	"sync"
	"time"
)

// State is the lifecycle state of a session chain.
type State string

const (
	StateActive  State = "active"
	StateRevoked State = "revoked"
	StateInvalid State = "invalid" // replay/concurrent reuse or explicit invalidation
	StateExpired State = "expired"

	// Governance terminal states (all sticky, all distinguishable).
	StateEvicted     State = "evicted"          // pushed out by a newer session under the per-account cap
	StateIdleExpired State = "idle_expired"     // no activity within the idle lifetime
	StateAbsExpired  State = "absolute_expired" // absolute lifetime from creation reached
	StateKicked      State = "kicked"           // explicitly kicked by the account owner
)

// ErrNotFound is returned when no session exists for an id.
var ErrNotFound = errors.New("session: not found")

// Session is one authenticated session chain. The struct must never be
// mutated outside the store's lock; accessors return copies.
type Session struct {
	ID              string
	Subject         string
	Role            string
	Source          string
	State           State
	CreatedAt       time.Time
	LastActiveAt    time.Time // last authenticate/refresh; drives idle expiry and LRU eviction
	LastRotateAt    time.Time
	RefreshJTI      string // JTI of the currently valid refresh credential
	Version         int    // monotonically increases on every rotation
	InvalidatedAt   time.Time
	InvalidationWhy string
	consumed        map[string]bool // refresh JTIs already consumed (replay memory)
}

// RotateResult reports the outcome of a compare-and-swap rotation.
type RotateResult struct {
	OK       bool
	Reason   State // StateInvalid on replay; StateRevoked/StateExpired/governance states as applicable
	Replayed bool  // presented refresh credential was already consumed
	Session  *Session
}

// Config tunes session governance. Zero values mean "no limit".
type Config struct {
	// MaxActivePerSubject caps simultaneously active sessions per account.
	// Beyond the cap the least-recently-active session is evicted.
	MaxActivePerSubject int
	// IdleTTL expires a session after this much inactivity. Authentication
	// and refresh both reset the idle clock.
	IdleTTL time.Duration
	// AbsoluteTTL expires a session this long after creation, no matter how
	// often it is refreshed.
	AbsoluteTTL time.Duration
}

// Store is the concurrency-safe in-memory session store.
type Store interface {
	Create(ctx context.Context, s *Session) (*Session, error)
	Get(ctx context.Context, id string) (*Session, error)
	List(ctx context.Context, subject string) []*Session

	// ListActive returns the subject's sessions that are still active at now
	// (lazy expiry is applied first), ordered by most recent activity.
	ListActive(ctx context.Context, subject string, now time.Time) []*Session

	// Rotate performs CAS: succeed only when the session is active and its
	// current RefreshJTI equals wantJTI. On mismatch the chain is marked
	// StateInvalid exactly once; concurrent losers observe the invalid state.
	// A successful rotation counts as activity (resets the idle clock) but
	// never extends the absolute lifetime.
	Rotate(ctx context.Context, id string, wantJTI, nextJTI string, now time.Time) RotateResult

	// Touch records an authentication as activity on an active session and
	// applies lazy expiry. It returns the session copy and its state at now;
	// a non-active state means the caller must reject with that reason.
	Touch(ctx context.Context, id string, now time.Time) (*Session, State, error)

	// Revoke marks sessions of a subject, or one session when sessionID set.
	Revoke(ctx context.Context, subject, sessionID string)

	// Kick marks exactly one session StateKicked (no-op if unknown).
	Kick(ctx context.Context, sessionID string, now time.Time)

	// KickOthers marks every session of a subject except keepID StateKicked.
	KickOthers(ctx context.Context, subject, keepID string, now time.Time)
}

type memStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	cfg      Config
}

// NewStore builds an in-memory store with no governance limits.
func NewStore() Store {
	return NewStoreWithConfig(Config{})
}

// NewStoreWithConfig builds an in-memory store with governance limits.
func NewStoreWithConfig(cfg Config) Store {
	return &memStore{sessions: make(map[string]*Session), cfg: cfg}
}

func clone(s *Session) *Session {
	if s == nil {
		return nil
	}
	cp := *s
	if s.consumed != nil {
		cp.consumed = make(map[string]bool, len(s.consumed))
		for k := range s.consumed {
			cp.consumed[k] = true
		}
	}
	return &cp
}

// terminateLocked moves a session to a terminal state once, recording why.
func terminateLocked(s *Session, state State, why string, now time.Time) {
	if s.State != StateActive {
		return
	}
	s.State = state
	s.InvalidatedAt = now
	s.InvalidationWhy = why
}

// evalLocked applies lazy expiry to an active session: absolute lifetime
// first (it can never be extended), then idle lifetime. Returns the state
// after evaluation.
func (m *memStore) evalLocked(s *Session, now time.Time) State {
	if s.State != StateActive {
		return s.State
	}
	if m.cfg.AbsoluteTTL > 0 && !now.Before(s.CreatedAt.Add(m.cfg.AbsoluteTTL)) {
		terminateLocked(s, StateAbsExpired, "absolute lifetime reached", now)
		return s.State
	}
	lastActive := s.LastActiveAt
	if lastActive.IsZero() {
		lastActive = s.CreatedAt
	}
	if m.cfg.IdleTTL > 0 && !now.Before(lastActive.Add(m.cfg.IdleTTL)) {
		terminateLocked(s, StateIdleExpired, "idle lifetime reached without activity", now)
		return s.State
	}
	return s.State
}

// enforceCapLocked evicts least-recently-active sessions of the subject until
// the active count is within the cap. The just-created session has the
// freshest activity timestamp, so it is never the eviction victim.
func (m *memStore) enforceCapLocked(subject string, now time.Time) {
	if m.cfg.MaxActivePerSubject <= 0 {
		return
	}
	for {
		count := 0
		var victim *Session
		for _, s := range m.sessions {
			if s.Subject != subject || s.State != StateActive {
				continue
			}
			count++
			if victim == nil || activeLess(s, victim) {
				victim = s
			}
		}
		if count <= m.cfg.MaxActivePerSubject {
			return
		}
		terminateLocked(victim, StateEvicted, "evicted by a newer session (per-account cap)", now)
	}
}

// activeLess orders sessions for LRU eviction: least recent activity first,
// ties broken by creation time then id for a deterministic victim.
func activeLess(a, b *Session) bool {
	la, lb := a.LastActiveAt, b.LastActiveAt
	if la.IsZero() {
		la = a.CreatedAt
	}
	if lb.IsZero() {
		lb = b.CreatedAt
	}
	if !la.Equal(lb) {
		return la.Before(lb)
	}
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	return a.ID < b.ID
}

func (m *memStore) Create(_ context.Context, s *Session) (*Session, error) {
	if s == nil || s.ID == "" {
		return nil, errors.New("session: invalid session")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.sessions[s.ID]; exists {
		return nil, errors.New("session: duplicate id")
	}
	if s.State == "" {
		s.State = StateActive
	}
	if s.LastActiveAt.IsZero() {
		s.LastActiveAt = s.CreatedAt
	}
	stored := clone(s)
	m.sessions[s.ID] = stored
	// The cap is enforced while still holding the lock, so concurrent
	// creations can never leave the active set above the limit.
	m.enforceCapLocked(stored.Subject, stored.LastActiveAt)
	return clone(stored), nil
}

func (m *memStore) Get(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return clone(s), nil
}

func (m *memStore) List(_ context.Context, subject string) []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Session, 0)
	for _, s := range m.sessions {
		if subject == "" || s.Subject == subject {
			out = append(out, clone(s))
		}
	}
	return out
}

func (m *memStore) ListActive(_ context.Context, subject string, now time.Time) []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Session, 0)
	for _, s := range m.sessions {
		if subject != "" && s.Subject != subject {
			continue
		}
		if m.evalLocked(s, now) != StateActive {
			continue
		}
		out = append(out, clone(s))
	}
	// Most recently active first, deterministic for equal timestamps.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && activeLess(out[j-1], out[j]); j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func (m *memStore) Rotate(_ context.Context, id, wantJTI, nextJTI string, now time.Time) RotateResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		// Unknown session: same external conclusion as an invalid chain.
		return RotateResult{OK: false, Reason: StateInvalid}
	}

	// Lazy expiry applies before any rotation decision: an expired session
	// cannot be refreshed even with the currently valid credential.
	m.evalLocked(s, now)

	// Terminal states are sticky and observable identically by every caller.
	switch s.State {
	case StateInvalid:
		// A credential that was already consumed is a replay even when it
		// arrives after another loser invalidated the chain; any other JTI is
		// simply an attempt on a dead chain.
		if s.consumed[wantJTI] {
			return RotateResult{OK: false, Reason: StateInvalid, Replayed: true, Session: clone(s)}
		}
		return RotateResult{OK: false, Reason: StateInvalid, Session: clone(s)}
	case StateActive:
		// continue below
	default:
		return RotateResult{OK: false, Reason: s.State, Session: clone(s)}
	}

	if s.RefreshJTI != wantJTI {
		// Stale/duplicate refresh credential: invalidate the chain once and
		// remember the presented JTI as consumed.
		if s.consumed == nil {
			s.consumed = make(map[string]bool)
		}
		s.consumed[wantJTI] = true
		s.State = StateInvalid
		s.InvalidatedAt = now
		s.InvalidationWhy = "refresh credential replay or concurrent reuse"
		s.RefreshJTI = ""
		return RotateResult{OK: false, Reason: StateInvalid, Replayed: true, Session: clone(s)}
	}

	// The single winning submission advances the chain atomically and the old
	// JTI joins the consumed set. Rotation counts as activity (idle clock
	// resets) but CreatedAt never moves, so the absolute lifetime stands.
	if s.consumed == nil {
		s.consumed = make(map[string]bool)
	}
	s.consumed[wantJTI] = true
	s.RefreshJTI = nextJTI
	s.Version++
	s.LastRotateAt = now
	s.LastActiveAt = now
	return RotateResult{OK: true, Reason: StateActive, Session: clone(s)}
}

func (m *memStore) Touch(_ context.Context, id string, now time.Time) (*Session, State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, StateInvalid, ErrNotFound
	}
	state := m.evalLocked(s, now)
	if state != StateActive {
		return clone(s), state, nil
	}
	s.LastActiveAt = now
	return clone(s), StateActive, nil
}

func (m *memStore) Revoke(_ context.Context, subject, sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, s := range m.sessions {
		if sessionID != "" {
			if s.ID == sessionID {
				terminateLocked(s, StateRevoked, "revoked", now)
			}
			continue
		}
		if subject != "" && s.Subject == subject {
			terminateLocked(s, StateRevoked, "revoked", now)
		}
	}
}

func (m *memStore) Kick(_ context.Context, sessionID string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		terminateLocked(s, StateKicked, "kicked by account owner", now)
	}
}

func (m *memStore) KickOthers(_ context.Context, subject, keepID string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		if s.Subject == subject && s.ID != keepID {
			terminateLocked(s, StateKicked, "kicked by account owner (keep current session)", now)
		}
	}
}
