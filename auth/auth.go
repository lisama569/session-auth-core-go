// Package auth is the single entry-point facade tying together locally signed
// credentials, session chains with one-time refresh rotation, live RBAC
// policy and account/source rate limiting.
//
// Normalization: every failure returned to callers is an *autherr.Error with
// a distinct Reason; crypto/parse/storage error text is never propagated.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"

	"github.com/lisama569/session-auth-core-go/autherr"
	"github.com/lisama569/session-auth-core-go/ratelimit"
	"github.com/lisama569/session-auth-core-go/rbac"
	"github.com/lisama569/session-auth-core-go/session"
	"github.com/lisama569/session-auth-core-go/token"
)

// CredentialBundle is returned by login and successful refresh.
type CredentialBundle struct {
	Access         string
	Refresh        string
	SessionID      string
	AccessExpires  time.Time
	RefreshExpires time.Time
}

// Principal is the authenticated identity plus the EFFECTIVE scopes at the
// moment of the decision: live policy scopes intersected with the scopes the
// credential itself carries. Revoking a scope therefore disables it on every
// existing access credential immediately.
type Principal struct {
	Subject   string
	Role      string
	SessionID string
	Scopes    map[string]bool
}

// Decision explains an access decision (useful for structured logging).
type Decision struct {
	Allowed        bool
	Subject        string
	Role           string
	RequiredScope  string
	EffectiveScope map[string]bool
	Basis          string
}

// userRec is a local account record. Passwords are stored only as a salted
// SHA-256 digest (this package simulates a real login chain locally).
type userRec struct {
	id   string
	name string
	role string
	salt []byte
	hash []byte
}

// Service is the auth facade.
type Service struct {
	signer  token.Signer
	store   session.Store
	policy  rbac.Policy
	limiter ratelimit.Limiter

	accessTTL  time.Duration
	refreshTTL time.Duration
	now        func() time.Time

	usersMu sync.RWMutex
	users   map[string]userRec
}

// Config configures a Service.
type Config struct {
	Signer     token.Signer
	Store      session.Store
	Policy     rbac.Policy
	Limiter    ratelimit.Limiter
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	// Clock defaults to time.Now; inject a controllable clock in tests.
	Clock func() time.Time
}

// NewService constructs a facade.
func NewService(cfg Config) *Service {
	s := &Service{
		signer:     cfg.Signer,
		store:      cfg.Store,
		policy:     cfg.Policy,
		limiter:    cfg.Limiter,
		accessTTL:  cfg.AccessTTL,
		refreshTTL: cfg.RefreshTTL,
		now:        cfg.Clock,
		users:      make(map[string]userRec),
	}
	if s.accessTTL <= 0 {
		s.accessTTL = 10 * time.Minute
	}
	if s.refreshTTL <= 0 {
		s.refreshTTL = 24 * time.Hour
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// AddUser registers a local account with a fresh per-user salt.
func (s *Service) AddUser(id, name, role, password string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return autherr.Internal()
	}
	h := sha256.Sum256(append(salt, []byte(password)...))
	rec := userRec{id: id, name: name, role: role, salt: salt, hash: h[:]}
	s.usersMu.Lock()
	s.users[id] = rec
	s.usersMu.Unlock()
	return nil
}

// Login verifies local credentials, applies account+source rate limits, opens
// a session chain and returns the first credential bundle.
func (s *Service) Login(ctx context.Context, subject, password, source string) (*CredentialBundle, error) {
	now := s.now()

	// Every attempt (including bad-password ones) consumes both buckets so
	// brute force from one source or against one account is bounded.
	if d := s.limiter.Allow(ctx, ratelimit.Key{Type: ratelimit.KeyAccount, ID: subject}, now); !d.Allowed {
		return nil, autherr.RateLimited()
	}
	if d := s.limiter.Allow(ctx, ratelimit.Key{Type: ratelimit.KeySource, ID: source}, now); !d.Allowed {
		return nil, autherr.RateLimited()
	}

	s.usersMu.RLock()
	rec, ok := s.users[subject]
	s.usersMu.RUnlock()
	if !ok || !passwordOK(rec, password) {
		// Same normalized reason for unknown user and wrong password.
		return nil, autherr.InvalidCredential()
	}

	sess, err := s.store.Create(ctx, &session.Session{
		ID:         newID("sess"),
		Subject:    rec.id,
		Role:       rec.role,
		Source:     source,
		State:      session.StateActive,
		CreatedAt:  now,
		RefreshJTI: newID("rt"),
	})
	if err != nil {
		return nil, autherr.Normalize(err)
	}

	return s.mintBundle(ctx, sess)
}

// Refresh consumes a refresh credential exactly once. Concurrent or repeated
// submission of the same refresh credential: exactly one caller wins; the
// losers receive autherr.ReasonReusedRefresh and the whole session chain is
// moved to session.StateInvalid. Later submissions on that chain receive
// autherr.ReasonSessionInvalid.
func (s *Service) Refresh(ctx context.Context, rawRefresh, source string) (*CredentialBundle, error) {
	now := s.now()

	// Source-side protection before touching crypto; account-side after the
	// subject is known.
	if d := s.limiter.Allow(ctx, ratelimit.Key{Type: ratelimit.KeySource, ID: source}, now); !d.Allowed {
		return nil, autherr.RateLimited()
	}

	claims, err := s.signer.Verify(ctx, rawRefresh)
	if err != nil {
		// Parse failure or bad signature: invalid credential, nothing leaks.
		return nil, autherr.InvalidCredential()
	}
	if claims.Version != token.V2 || claims.Kind != token.KindRefresh ||
		claims.SessionID == "" || claims.JTI == "" {
		// v1 credentials and non-refresh credentials cannot be refreshed.
		return nil, autherr.InvalidCredential()
	}
	if claims.Expired(now) {
		return nil, autherr.ExpiredCredential()
	}
	if d := s.limiter.Allow(ctx, ratelimit.Key{Type: ratelimit.KeyAccount, ID: claims.Subject}, now); !d.Allowed {
		return nil, autherr.RateLimited()
	}

	// Atomic compare-and-swap is the single decision point: it distinguishes
	// a replayed credential (refresh_replayed) from a dead chain
	// (session_invalid) even under concurrent submissions.
	res := s.store.Rotate(ctx, claims.SessionID, claims.JTI, newID("rt"), now)
	if !res.OK {
		if res.Replayed {
			// Lost the race or presented an already-consumed credential:
			// the chain is now explicitly invalid.
			return nil, autherr.ReusedRefresh()
		}
		return nil, sessionStateError(res.Reason)
	}

	return s.mintBundle(ctx, res.Session)
}

// Authenticate parses and verifies an access credential, checks the bound
// session state, and resolves effective scopes against the live policy. It
// does not by itself require any particular scope.
func (s *Service) Authenticate(ctx context.Context, rawAccess string) (*Principal, error) {
	p, _, err := s.authenticate(ctx, rawAccess)
	return p, err
}

// Authorize combines authentication with a required-scope decision. A missing
// scope (including one revoked after login, and every scope check against a
// legacy v1 credential, which can never carry scopes) is a stable denial.
func (s *Service) Authorize(ctx context.Context, rawAccess, requiredScope string) (*Principal, *Decision, error) {
	p, basis, err := s.authenticate(ctx, rawAccess)
	if err != nil {
		return nil, nil, err
	}
	d := &Decision{
		Subject:        p.Subject,
		Role:           p.Role,
		RequiredScope:  requiredScope,
		EffectiveScope: copySet(p.Scopes),
	}
	if requiredScope == "" {
		d.Allowed = true
		d.Basis = basis + "; no scope required -> allow"
		return p, d, nil
	}
	if p.Scopes[requiredScope] {
		d.Allowed = true
		d.Basis = basis + "; required scope present in live effective set -> allow"
		return p, d, nil
	}
	d.Allowed = false
	d.Basis = basis + "; required scope absent (never granted, revoked, or legacy credential with no scopes) -> deny"
	return p, d, autherr.PermissionDenied()
}

// Revoke revokes one session (sessionID set) or all sessions of a subject.
func (s *Service) Revoke(ctx context.Context, subject, sessionID string) {
	s.store.Revoke(ctx, subject, sessionID)
}

// SessionInfo is the owner-visible view of one active session.
type SessionInfo struct {
	SessionID    string
	Source       string
	CreatedAt    time.Time
	LastActiveAt time.Time
	Version      int
}

// ListSessions returns the subject's currently active sessions (idle/absolute
// expiry is applied first), most recently active first.
func (s *Service) ListSessions(ctx context.Context, subject string) []SessionInfo {
	active := s.store.ListActive(ctx, subject, s.now())
	out := make([]SessionInfo, 0, len(active))
	for _, sess := range active {
		out = append(out, SessionInfo{
			SessionID:    sess.ID,
			Source:       sess.Source,
			CreatedAt:    sess.CreatedAt,
			LastActiveAt: sess.LastActiveAt,
			Version:      sess.Version,
		})
	}
	return out
}

// KickSession terminates exactly one session. Other sessions of the same
// account are unaffected; the kicked session observes session_kicked on any
// later access or refresh attempt.
func (s *Service) KickSession(ctx context.Context, sessionID string) {
	s.store.Kick(ctx, sessionID, s.now())
}

// KickOtherSessions terminates every session of the subject except keepID
// (typically the caller's current session).
func (s *Service) KickOtherSessions(ctx context.Context, subject, keepSessionID string) {
	s.store.KickOthers(ctx, subject, keepSessionID, s.now())
}

// ResetLimit clears a rate-limit bucket (test/admin utility).
func (s *Service) ResetLimit(ctx context.Context, k ratelimit.Key) {
	s.limiter.Reset(ctx, k)
}

// ---------------------------------------------------------------------------

func (s *Service) authenticate(ctx context.Context, rawAccess string) (*Principal, string, error) {
	if rawAccess == "" {
		return nil, "", autherr.MissingCredential()
	}
	now := s.now()
	claims, err := s.signer.Verify(ctx, rawAccess)
	if err != nil {
		// Tampered/malformed credential: same distinguishable reason always.
		return nil, "", autherr.InvalidCredential()
	}
	if claims.Kind != token.KindAccess {
		return nil, "", autherr.InvalidCredential()
	}
	if claims.Expired(now) {
		return nil, "", autherr.ExpiredCredential()
	}

	// v2 credentials are bound to a live session chain; v1 legacy credentials
	// are not (fixed compatibility semantics, see package token).
	sessionBasis := "legacy v1 credential: no session binding"
	if claims.Version == token.V2 {
		if claims.SessionID == "" {
			return nil, "", autherr.InvalidCredential()
		}
		// Touch is the single decision point for session-bound access: it
		// applies lazy expiry, records this authentication as activity
		// (resetting the idle clock) and returns the state, all atomically.
		sess, state, err := s.store.Touch(ctx, claims.SessionID, now)
		if err != nil {
			return nil, "", autherr.SessionInvalid()
		}
		if state != session.StateActive {
			return nil, "", sessionStateError(state)
		}
		sessionBasis = "session " + sess.ID + " active at chain v" + itoa(sess.Version)
	}

	// Effective scopes = live policy scopes intersected with credential scopes.
	policyScopes := s.policy.Scopes(ctx, claims.Role)
	effective := make(map[string]bool)
	for sc := range policyScopes {
		if claims.HasScope(sc) {
			effective[sc] = true
		}
	}
	// Legacy v1 claims carry no scopes: intersection is empty and no scope is
	// ever granted by default.
	basis := "subject=" + claims.Subject + " role=" + claims.Role +
		" format=" + string(claims.Version) + "; " + sessionBasis
	return &Principal{
		Subject:   claims.Subject,
		Role:      claims.Role,
		SessionID: claims.SessionID,
		Scopes:    effective,
	}, basis, nil
}

func (s *Service) mintBundle(ctx context.Context, sess *session.Session) (*CredentialBundle, error) {
	now := s.now()
	scopes := setToSlice(s.policy.Scopes(ctx, sess.Role))

	accessClaims := &token.Claims{
		Version: token.V2, Kind: token.KindAccess,
		Subject: sess.Subject, Role: sess.Role, Scopes: scopes,
		SessionID: sess.ID, JTI: newID("at"),
		IssuedAt: now, ExpiresAt: now.Add(s.accessTTL),
	}
	refreshClaims := &token.Claims{
		Version: token.V2, Kind: token.KindRefresh,
		Subject: sess.Subject, Role: sess.Role,
		SessionID: sess.ID, JTI: sess.RefreshJTI,
		IssuedAt: now, ExpiresAt: now.Add(s.refreshTTL),
	}
	access, err := s.signer.Sign(ctx, accessClaims)
	if err != nil {
		return nil, autherr.Normalize(err)
	}
	refresh, err := s.signer.Sign(ctx, refreshClaims)
	if err != nil {
		return nil, autherr.Normalize(err)
	}
	return &CredentialBundle{
		Access:         access,
		Refresh:        refresh,
		SessionID:      sess.ID,
		AccessExpires:  accessClaims.ExpiresAt,
		RefreshExpires: refreshClaims.ExpiresAt,
	}, nil
}

// sessionStateError maps a terminal session state to its normalized,
// distinguishable rejection reason. Replay-invalidated chains and explicit
// revocations stay on the historical session_invalid reason; the governance
// outcomes (evicted / idle / absolute / kicked) each get their own reason so
// callers can tell them apart from credential problems.
func sessionStateError(state session.State) *autherr.Error {
	switch state {
	case session.StateEvicted:
		return autherr.SessionEvicted()
	case session.StateIdleExpired:
		return autherr.SessionIdleExpired()
	case session.StateAbsExpired:
		return autherr.SessionAbsoluteExpired()
	case session.StateKicked:
		return autherr.SessionKicked()
	case session.StateRevoked:
		return autherr.New(autherr.ReasonSessionInvalid, "session has been revoked")
	case session.StateExpired:
		return autherr.New(autherr.ReasonSessionInvalid, "session has expired")
	default:
		return autherr.SessionInvalid()
	}
}

func passwordOK(rec userRec, password string) bool {
	h := sha256.Sum256(append(rec.salt, []byte(password)...))
	return subtle.ConstantTimeCompare(h[:], rec.hash) == 1
}

func newID(prefix string) string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is environmental: normalized, not leaked.
		return prefix + "-fallback"
	}
	return prefix + "_" + hex.EncodeToString(b)
}

func setToSlice(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

func copySet(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k := range in {
		out[k] = true
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [24]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
