// Package token provides locally signed access/refresh credential primitives
// (HMAC over a compact envelope) plus stable parsing semantics for a legacy
// v1 format.
//
// Wire shapes (no third-party dependency):
//
//	v2: b64url(header) "." b64url(payload JSON) "." b64url(HMAC-SHA256)
//	    header  = {"v":"v2","k":"access|refresh"}
//	    payload = {sub,role,scp,sid,jti,iat,exp}
//
//	v1 (legacy): b64url(sub:role:expUnix) "." hex(HMAC-SHA256)
//	    Fixed compatibility semantics:
//	      - a valid v1 credential authenticates subject and role only;
//	      - it NEVER carries scopes (scp is empty) -> scope checks deny;
//	      - it is bound to no session (sid/jti empty) and CANNOT refresh;
//	      - any shape/signature mismatch is an invalid credential, never a
//	        silent pass.
package token

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Version identifies the credential envelope format.
type Version string

const (
	V1 Version = "v1" // legacy: subject + role only, never carries scopes
	V2 Version = "v2" // current: subject + role + scopes + session binding
)

// Kind distinguishes access credentials from refresh credentials.
type Kind string

const (
	KindAccess  Kind = "access"
	KindRefresh Kind = "refresh"
)

// Claims is the parsed content of a credential.
type Claims struct {
	Version   Version
	Kind      Kind
	Subject   string
	Role      string
	Scopes    []string
	SessionID string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Expired reports whether the credential is expired at instant now. The
// expiry instant itself counts as expired.
func (c *Claims) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt)
}

// HasScope reports whether the claims carry scope.
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Sentinel errors are internal: they are normalized before reaching callers.
var (
	errMalformed = errors.New("token: malformed credential")
	errBadMAC    = errors.New("token: signature mismatch")
)

var b64 = base64.RawURLEncoding

// Signer signs and verifies credentials with a locally held key.
type Signer interface {
	Sign(ctx context.Context, c *Claims) (string, error)
	// SignLegacy mints a v1 credential (for migration/compatibility tests).
	SignLegacy(ctx context.Context, subject, role string, expiresAt time.Time) (string, error)
	Verify(ctx context.Context, raw string) (*Claims, error)
}

type localSigner struct {
	key []byte
}

// NewLocalSigner constructs an HMAC signer from a local secret.
func NewLocalSigner(secret []byte) Signer {
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return &localSigner{key: cp}
}

type header struct {
	V Version `json:"v"`
	K Kind    `json:"k"`
}

type payload struct {
	Sub  string   `json:"sub"`
	Role string   `json:"role"`
	Scp  []string `json:"scp,omitempty"`
	Sid  string   `json:"sid,omitempty"`
	Jti  string   `json:"jti,omitempty"`
	Iat  int64    `json:"iat"`
	Exp  int64    `json:"exp"`
}

func (s *localSigner) mac(data []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write(data)
	return m.Sum(nil)
}

// Sign emits a v2 envelope.
func (s *localSigner) Sign(_ context.Context, c *Claims) (string, error) {
	if c == nil || c.Subject == "" {
		return "", errMalformed
	}
	kind := c.Kind
	if kind != KindAccess && kind != KindRefresh {
		return "", errMalformed
	}
	hdr, err := json.Marshal(&header{V: V2, K: kind})
	if err != nil {
		return "", err
	}
	pld, err := json.Marshal(&payload{
		Sub: c.Subject, Role: c.Role, Scp: c.Scopes,
		Sid: c.SessionID, Jti: c.JTI,
		Iat: c.IssuedAt.Unix(), Exp: c.ExpiresAt.Unix(),
	})
	if err != nil {
		return "", err
	}
	hb := b64.EncodeToString(hdr)
	pb := b64.EncodeToString(pld)
	signing := hb + "." + pb
	mb := b64.EncodeToString(s.mac([]byte(signing)))
	return signing + "." + mb, nil
}

// SignLegacy emits the v1 wire shape: b64(sub:role:exp) "." hex(mac).
func (s *localSigner) SignLegacy(_ context.Context, subject, role string, expiresAt time.Time) (string, error) {
	if subject == "" {
		return "", errMalformed
	}
	body := subject + ":" + role + ":" + strconv.FormatInt(expiresAt.Unix(), 10)
	sig := hex.EncodeToString(s.mac([]byte(body)))
	return b64.EncodeToString([]byte(body)) + "." + sig, nil
}

// Verify accepts v2 envelopes and v1 legacy credentials. It is a single
// chokepoint: tampered or malformed input always yields errBadMAC/errMalformed.
func (s *localSigner) Verify(_ context.Context, raw string) (*Claims, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errMalformed
	}
	parts := strings.Split(raw, ".")
	switch len(parts) {
	case 2:
		return s.verifyLegacy(parts[0], parts[1])
	case 3:
		return s.verifyV2(parts[0], parts[1], parts[2])
	default:
		return nil, errMalformed
	}
}

func (s *localSigner) verifyV2(hb, pb, mb string) (*Claims, error) {
	sig, err := b64.DecodeString(mb)
	if err != nil {
		return nil, errMalformed
	}
	signing := hb + "." + pb
	if !hmac.Equal(s.mac([]byte(signing)), sig) {
		return nil, errBadMAC
	}
	hj, err := b64.DecodeString(hb)
	if err != nil {
		return nil, errMalformed
	}
	var h header
	if err := json.Unmarshal(hj, &h); err != nil || h.V != V2 ||
		(h.K != KindAccess && h.K != KindRefresh) {
		return nil, errMalformed
	}
	pj, err := b64.DecodeString(pb)
	if err != nil {
		return nil, errMalformed
	}
	var p payload
	if err := json.Unmarshal(pj, &p); err != nil {
		return nil, errMalformed
	}
	if p.Sub == "" {
		return nil, errMalformed
	}
	return claimsFromPayload(h.K, &p), nil
}

func (s *localSigner) verifyLegacy(bodyB64, sigHex string) (*Claims, error) {
	body, err := b64.DecodeString(bodyB64)
	if err != nil {
		return nil, errMalformed
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, errMalformed
	}
	if !hmac.Equal(s.mac(body), sig) {
		return nil, errBadMAC
	}
	fields := strings.Split(string(body), ":")
	if len(fields) != 3 || fields[0] == "" {
		return nil, errMalformed
	}
	exp, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, errMalformed
	}
	// Fixed v1 semantics: no scopes, no session binding, access kind only.
	return &Claims{
		Version:   V1,
		Kind:      KindAccess,
		Subject:   fields[0],
		Role:      fields[1],
		Scopes:    nil,
		SessionID: "",
		JTI:       "",
		IssuedAt:  time.Unix(exp, 0).Add(-time.Hour), // v1 carried no iat
		ExpiresAt: time.Unix(exp, 0),
	}, nil
}

func claimsFromPayload(k Kind, p *payload) *Claims {
	c := &Claims{
		Version: V2, Kind: k,
		Subject: p.Sub, Role: p.Role, Scopes: p.Scp,
		SessionID: p.Sid, JTI: p.Jti,
		IssuedAt: time.Unix(p.Iat, 0), ExpiresAt: time.Unix(p.Exp, 0),
	}
	if c.Scopes == nil {
		c.Scopes = []string{}
	}
	return c
}

// ParseLegacy parses a v1 credential without a signer, performing structural
// validation only (signature cannot be checked without the local key).
// Prefer Signer.Verve when a key is available.
func ParseLegacy(raw string) (*Claims, error) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("%w: bad shape", errMalformed)
	}
	body, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: bad body", errMalformed)
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return nil, fmt.Errorf("%w: bad signature", errMalformed)
	}
	fields := strings.Split(string(body), ":")
	if len(fields) != 3 || fields[0] == "" {
		return nil, fmt.Errorf("%w: bad fields", errMalformed)
	}
	exp, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: bad expiry", errMalformed)
	}
	return &Claims{
		Version: V1, Kind: KindAccess,
		Subject: fields[0], Role: fields[1],
		ExpiresAt: time.Unix(exp, 0),
	}, nil
}
