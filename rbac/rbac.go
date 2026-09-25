// Package rbac maintains the live role -> scope policy. Revocations take
// effect immediately for already-issued sessions because every access
// decision evaluates scopes against the current policy snapshot rather than
// the set captured at login.
package rbac

import (
	"context"
	"sync"
)

// Policy resolves roles to the scopes in force right now.
type Policy interface {
	// Scopes returns a copy of the current scope set for a role.
	Scopes(ctx context.Context, role string) map[string]bool
	// Revoke removes scopes from a role for all future decisions.
	Revoke(ctx context.Context, role string, scopes ...string)
	// Grant adds scopes to a role.
	Grant(ctx context.Context, role string, scopes ...string)
}

type memPolicy struct {
	mu    sync.RWMutex
	roles map[string]map[string]bool
}

// NewPolicy builds an in-memory policy seeded with role -> scopes.
func NewPolicy(seed map[string][]string) Policy {
	p := &memPolicy{roles: make(map[string]map[string]bool, len(seed))}
	for role, scopes := range seed {
		set := make(map[string]bool, len(scopes))
		for _, sc := range scopes {
			set[sc] = true
		}
		p.roles[role] = set
	}
	return p
}

func (p *memPolicy) Scopes(_ context.Context, role string) map[string]bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]bool)
	for sc := range p.roles[role] {
		out[sc] = true
	}
	return out
}

func (p *memPolicy) Revoke(_ context.Context, role string, scopes ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	set := p.roles[role]
	for _, sc := range scopes {
		delete(set, sc)
	}
}

func (p *memPolicy) Grant(_ context.Context, role string, scopes ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	set := p.roles[role]
	if set == nil {
		set = make(map[string]bool)
		p.roles[role] = set
	}
	for _, sc := range scopes {
		set[sc] = true
	}
}
