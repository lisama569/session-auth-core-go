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
	StateActive  State = "active"
	StateRevoked State = "revoked"
	StateInvalid State = "invalid" // replay/concurrent reuse or explicit invalidation
	StateExpired State = "expired"
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
	Reason   State // StateInvalid on replay; StateRevoked/StateExpired as applicable
	Replayed bool  // presented refresh credential was already consumed
	Session  *Session
}

// Store is the concurrency-safe in-memory session store.
type Store interface {
	Create(ctx context.Context, s *Session) (*Session, error)
	Get(ctx context.Context, id string) (*Session, error)
	List(ctx context.Context, subject string) []*Session

	// Rotate performs CAS: succeed only when the session is active and its
	// current RefreshJTI equals wantJTI. On mismatch the chain is marked
	// StateInvalid exactly once; concurrent losers observe the invalid state.
	Rotate(ctx context.Context, id string, wantJTI, nextJTI string, now time.Time) RotateResult

	// Revoke marks sessions of a subject, or one session when sessionID set.
	Revoke(ctx context.Context, subject, sessionID string)
}

type memStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

// NewStore builds an in-memory store.
func NewStore() Store {
	return &memStore{sessions: make(map[string]*Session)}
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
	stored := clone(s)
	m.sessions[s.ID] = stored
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

func (m *memStore) Rotate(_ context.Context, id, wantJTI, nextJTI string, now time.Time) RotateResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		// Unknown session: same external conclusion as an invalid chain.
		return RotateResult{OK: false, Reason: StateInvalid}
	}

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
	case StateRevoked:
		return RotateResult{OK: false, Reason: StateRevoked, Session: clone(s)}
	case StateExpired:
		return RotateResult{OK: false, Reason: StateExpired, Session: clone(s)}
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
