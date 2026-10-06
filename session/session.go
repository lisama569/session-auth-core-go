// Package session holds in-memory session-chain state. The critical operation
// is refresh-credential rotation, implemented as a compare-and-swap under a
// single mutex:
//
//   - exactly one submission carrying the currently expected refresh JTI wins;
//   - any concurrent or later submission with a stale JTI loses and marks the
//     whole chain StateInvalid exactly once;
//   - losers and subsequent uses all observe the same terminal invalid state,
//     so the conclusion is identical under the race detector.
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
	StateActive          State = "active"
	StateRevoked         State = "revoked"
	StateInvalid         State = "invalid" // replay/concurrent reuse or explicit invalidation
	StateExpired         State = "expired"
	StateEvicted         State = "evicted"          // pushed out by a newer session (per-account cap)
	StateIdleExpired     State = "idle_expired"     // no activity within the idle lifetime
	StateAbsoluteExpired State = "absolute_expired" // hard lifetime since creation reached
	StateKicked          State = "kicked"           // explicitly removed by a management action
)

// ErrNotFound is returned when no session exists for an id.
var ErrNotFound = errors.New("session: not found")

// Session is one authenticated session chain. The struct must never be
// mutated outside the store's lock; accessors return copies.
type Session struct {
	ID               string
	Subject          string
	Role             string
	Source           string
	State            State
	CreatedAt        time.Time
	LastRotateAt     time.Time
	LastActivityAt   time.Time     // every authenticate/refresh counts as activity
	AbsoluteDeadline time.Time     // hard ceiling since creation; zero => no absolute bound
	IdleTTL          time.Duration // idle lifetime; zero => no idle bound
	RefreshJTI       string        // JTI of the currently valid refresh credential
	Version          int           // monotonically increases on every rotation
	InvalidatedAt    time.Time
	InvalidationWhy  string
	consumed         map[string]bool // refresh JTIs already consumed (replay memory)
}

// RotateResult reports the outcome of a compare-and-swap rotation.
type RotateResult struct {
	OK       bool
	Reason   State // terminal State on failure: StateInvalid/StateRevoked/StateEvicted/...
	Replayed bool  // presented refresh credential was already consumed
	Session  *Session
}

// TouchResult reports the outcome of an activity touch (authenticate counts).
type TouchResult struct {
	OK      bool
	Reason  State // terminal State when the session cannot be used
	Session *Session
}

// GovernanceConfig governs the number and lifetimes of concurrent sessions.
type GovernanceConfig struct {
	// MaxActivePerSubject bounds the number of ACTIVE sessions per account.
	// When exceeded, the active session with the oldest LastActivityAt is
	// evicted (ties: older CreatedAt, then smaller ID). <=0 means unbounded.
	MaxActivePerSubject int
	// IdleTTL is the idle lifetime: a session with no activity (authenticate
	// or refresh) for IdleTTL is no longer usable. <=0 disables idle expiry.
	IdleTTL time.Duration
	// AbsoluteTTL is the hard lifetime since creation; renewal can never move
	// it. <=0 disables absolute expiry.
	AbsoluteTTL time.Duration
	// Clock is used for deadline/activity bookkeeping; defaults to time.Now.
	Clock func() time.Time
}

// Store is the concurrency-safe in-memory session store.
type Store interface {
	Create(ctx context.Context, s *Session) (*Session, error)
	Get(ctx context.Context, id string) (*Session, error)
	List(ctx context.Context, subject string) []*Session

	// ListActive returns the currently ACTIVE sessions of a subject, lazily
	// sweeping sessions whose idle/absolute lifetime has elapsed.
	ListActive(ctx context.Context, subject string) []*Session

	// Rotate performs CAS: succeed only when the session is active and its
	// current RefreshJTI equals wantJTI. On mismatch the chain is marked
	// StateInvalid exactly once; concurrent losers observe the invalid state.
	// Idle/absolute lifetimes are evaluated atomically first, and a winning
	// rotation counts as activity (resets the idle clock).
	Rotate(ctx context.Context, id string, wantJTI, nextJTI string, now time.Time) RotateResult

	// Touch records activity on a live session and resets its idle clock.
	// Expired/terminal sessions are returned with their terminal Reason and
	// never mutated back to active.
	Touch(ctx context.Context, id string, now time.Time) TouchResult

	// Kick terminates exactly one session with StateKicked. It reports
	// whether the id named an existing stored session.
	Kick(ctx context.Context, sessionID string, now time.Time) bool

	// KeepOnly terminates every ACTIVE session of subject except keepID with
	// StateKicked, and returns the number of sessions kicked.
	KeepOnly(ctx context.Context, subject, keepID string, now time.Time) int

	// Revoke marks sessions of a subject, or one session when sessionID set.
	Revoke(ctx context.Context, subject, sessionID string)
}

type memStore struct {
	mu       sync.Mutex
	sessions map[string]*Session

	cfg GovernanceConfig
	now func() time.Time
}

// NewStore builds an in-memory store WITHOUT session governance: no per-account
// cap and no idle/absolute expiry. Existing callers keep their exact semantics.
func NewStore() Store {
	return newMemStore(GovernanceConfig{})
}

// NewGovernedStore builds an in-memory store enforcing the given governance
// rules (per-account cap, idle and absolute lifetimes).
func NewGovernedStore(cfg GovernanceConfig) Store {
	return newMemStore(cfg)
}

func newMemStore(cfg GovernanceConfig) *memStore {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &memStore{sessions: make(map[string]*Session), cfg: cfg, now: cfg.Clock}
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

	// Populate governance bookkeeping for freshly created sessions. Only
	// sessions actually created under a governed store inherit its bounds.
	now := m.now()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	if s.LastActivityAt.IsZero() {
		s.LastActivityAt = now
	}
	if m.cfg.IdleTTL > 0 && s.IdleTTL <= 0 {
		s.IdleTTL = m.cfg.IdleTTL
	}
	if m.cfg.AbsoluteTTL > 0 && s.AbsoluteDeadline.IsZero() {
		s.AbsoluteDeadline = s.CreatedAt.Add(m.cfg.AbsoluteTTL)
	}

	stored := clone(s)
	m.sessions[s.ID] = stored

	// Enforce the per-account cap against the live set: first lazily move
	// elapsed sessions to their terminal state, then if active sessions
	// still exceed the cap, evict the oldest by LastActivityAt.
	if m.cfg.MaxActivePerSubject > 0 {
		m.sweepExpiredLocked(stored.Subject, now)
		m.evictLocked(stored.Subject, now)
	}
	return clone(m.sessions[s.ID]), nil
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

func (m *memStore) Rotate(_ context.Context, id, wantJTI, nextJTI string, now time.Time) RotateResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		// Unknown session: same external conclusion as an invalid chain.
		return RotateResult{OK: false, Reason: StateInvalid}
	}

	// Terminal states are sticky and observable identically by every caller.
	// Two-layer lifetimes are evaluated here, atomically, before any CAS.
	st := livenessLocked(s, now)
	if st == StateAbsoluteExpired || st == StateIdleExpired {
		terminateLocked(s, st, now, terminalWhy(st))
	}
	if st != StateActive {
		// A credential already consumed is a replay no matter which terminal
		// state the chain later reached; any other JTI is an attempt on a dead
		// chain carrying that state's specific conclusion.
		if s.consumed[wantJTI] {
			return RotateResult{OK: false, Reason: st, Replayed: true, Session: clone(s)}
		}
		return RotateResult{OK: false, Reason: st, Session: clone(s)}
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
	// JTI joins the consumed set.
	if s.consumed == nil {
		s.consumed = make(map[string]bool)
	}
	s.consumed[wantJTI] = true
	s.RefreshJTI = nextJTI
	s.Version++
	s.LastRotateAt = now
	s.LastActivityAt = now // a successful refresh counts as activity
	return RotateResult{OK: true, Reason: StateActive, Session: clone(s)}
}

func (m *memStore) Revoke(_ context.Context, subject, sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for _, s := range m.sessions {
		if sessionID != "" {
			if s.ID == sessionID {
				s.State = StateRevoked
				s.InvalidatedAt = now
				s.InvalidationWhy = "revoked"
			}
			continue
		}
		if subject != "" && s.Subject == subject {
			s.State = StateRevoked
			s.InvalidatedAt = now
			s.InvalidationWhy = "revoked"
		}
	}
}

// --- session governance ---

// terminateLocked moves a non-terminal session to a terminal state exactly
// once; terminal states are sticky and never overwritten.
func terminateLocked(s *Session, st State, now time.Time, why string) {
	if s.State != StateActive {
		return
	}
	s.State = st
	s.InvalidatedAt = now
	s.InvalidationWhy = why
	s.RefreshJTI = ""
}

// livenessLocked returns the terminal state of a session at instant now, or
// StateActive when it is still usable. Absolute expiry is evaluated before
// idle expiry so the hard-limit conclusion takes precedence.
func livenessLocked(s *Session, now time.Time) State {
	if s.State != StateActive {
		return s.State
	}
	if !s.AbsoluteDeadline.IsZero() && !now.Before(s.AbsoluteDeadline) {
		return StateAbsoluteExpired
	}
	if s.IdleTTL > 0 && !s.LastActivityAt.IsZero() &&
		!now.Before(s.LastActivityAt.Add(s.IdleTTL)) {
		return StateIdleExpired
	}
	return StateActive
}

func terminalWhy(st State) string {
	switch st {
	case StateAbsoluteExpired:
		return "absolute lifetime reached"
	case StateIdleExpired:
		return "idle lifetime reached"
	case StateEvicted:
		return "evicted by a newer session (active session cap exceeded)"
	case StateKicked:
		return "explicitly kicked"
	default:
		return string(st)
	}
}

// sweepExpiredLocked lazily marks elapsed sessions of subject as terminal.
func (m *memStore) sweepExpiredLocked(subject string, now time.Time) {
	for _, s := range m.sessions {
		if s.Subject != subject {
			continue
		}
		if st := livenessLocked(s, now); st == StateAbsoluteExpired || st == StateIdleExpired {
			terminateLocked(s, st, now, terminalWhy(st))
		}
	}
}

// evictLocked brings the number of ACTIVE sessions of subject down to the cap
// by terminating the least recently active sessions. The just-created session
// always has the newest activity and is therefore never the victim.
func (m *memStore) evictLocked(subject string, now time.Time) {
	active := make([]*Session, 0)
	for _, s := range m.sessions {
		if s.Subject == subject && s.State == StateActive {
			active = append(active, s)
		}
	}
	for len(active) > m.cfg.MaxActivePerSubject {
		// Find the session with the oldest LastActivityAt; ties broken by
		// older CreatedAt, then the smaller ID for deterministic ordering.
		victim := 0
		for i := 1; i < len(active); i++ {
			a, b := active[i], active[victim]
			if a.LastActivityAt.Before(b.LastActivityAt) ||
				(a.LastActivityAt.Equal(b.LastActivityAt) &&
					(a.CreatedAt.Before(b.CreatedAt) ||
						(a.CreatedAt.Equal(b.CreatedAt) && a.ID < b.ID))) {
				victim = i
			}
		}
		v := active[victim]
		terminateLocked(v, StateEvicted, now, terminalWhy(StateEvicted))
		active = append(active[:victim], active[victim+1:]...)
	}
}

func (m *memStore) ListActive(_ context.Context, subject string) []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	out := make([]*Session, 0)
	for _, s := range m.sessions {
		if s.Subject != subject {
			continue
		}
		// Lazily settle elapsed sessions so visibility reflects reality.
		if st := livenessLocked(s, now); st == StateAbsoluteExpired || st == StateIdleExpired {
			terminateLocked(s, st, now, terminalWhy(st))
		}
		if s.State == StateActive {
			out = append(out, clone(s))
		}
	}
	return out
}

func (m *memStore) Touch(_ context.Context, id string, now time.Time) TouchResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		// Unknown session: same external conclusion as a dead chain.
		return TouchResult{OK: false, Reason: StateInvalid}
	}

	// Terminal states are sticky; report them verbatim.
	if st := livenessLocked(s, now); st != StateActive {
		if st == StateAbsoluteExpired || st == StateIdleExpired {
			terminateLocked(s, st, now, terminalWhy(st))
		}
		return TouchResult{OK: false, Reason: st, Session: clone(s)}
	}

	s.LastActivityAt = now
	return TouchResult{OK: true, Reason: StateActive, Session: clone(s)}
}

func (m *memStore) Kick(_ context.Context, sessionID string, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return false
	}
	// Kicking an already-terminal session is idempotent but still confirms
	// the named session exists.
	terminateLocked(s, StateKicked, now, terminalWhy(StateKicked))
	return true
}

func (m *memStore) KeepOnly(_ context.Context, subject, keepID string, now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.sessions {
		if s.Subject != subject || s.ID == keepID {
			continue
		}
		// Only live sessions are kicked; terminal ones keep their original,
		// distinguishable conclusion.
		if s.State == StateActive {
			terminateLocked(s, StateKicked, now, terminalWhy(StateKicked))
			n++
		}
	}
	return n
}
