package token

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	signer := NewLocalSigner([]byte("local-test-secret"))
	now := time.Now().Truncate(time.Second)
	claims := &Claims{
		Version: V2, Kind: KindAccess,
		Subject: "u-1", Role: "reader", Scopes: []string{"read:doc"},
		SessionID: "sess_1", JTI: "at_1",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	raw, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	t.Logf("input claims=%+v raw=%q", claims, raw)

	got, err := signer.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Logf("parsed claims=%+v", got)
	if got.Subject != "u-1" || got.Role != "reader" || got.SessionID != "sess_1" || got.JTI != "at_1" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if !got.HasScope("read:doc") || got.HasScope("write:doc") {
		t.Fatalf("scope mismatch: %+v", got.Scopes)
	}
}

func TestTamperedCredentialRejected(t *testing.T) {
	signer := NewLocalSigner([]byte("local-test-secret"))
	now := time.Now()
	raw, err := signer.Sign(context.Background(), &Claims{
		Version: V2, Kind: KindAccess, Subject: "u-1", Role: "reader",
		SessionID: "sess_1", JTI: "at_1", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	cases := map[string]string{
		"flipped payload char": raw[:len(raw)/2] + flip(raw[len(raw)/2]) + raw[len(raw)/2+1:],
		"truncated":            raw[:len(raw)-2],
		"extra segment":        raw + ".extra",
		"garbage":              "not-a-credential",
	}
	for name, bad := range cases {
		if _, err := signer.Verify(context.Background(), bad); err == nil {
			t.Errorf("case %q: expected rejection for tampered input %q", name, bad)
		} else {
			t.Logf("case %q input=%q -> rejected (%v)", name, bad, err)
		}
	}
}

func TestWrongKeyRejected(t *testing.T) {
	a := NewLocalSigner([]byte("key-a"))
	b := NewLocalSigner([]byte("key-b"))
	now := time.Now()
	raw, err := a.Sign(context.Background(), &Claims{
		Version: V2, Kind: KindAccess, Subject: "u-1", Role: "reader",
		SessionID: "s", JTI: "j", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := b.Verify(context.Background(), raw); err == nil {
		t.Fatal("credential signed with key-a must not verify under key-b")
	}
	t.Logf("input=%q signed with key-a -> rejected under key-b", raw)
}

func TestLegacyV1Semantics(t *testing.T) {
	signer := NewLocalSigner([]byte("local-test-secret"))
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	raw, err := signer.SignLegacy(context.Background(), "legacy-user", "reader", exp)
	if err != nil {
		t.Fatalf("sign legacy: %v", err)
	}
	t.Logf("legacy input=%q", raw)

	got, err := signer.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("verify legacy: %v", err)
	}
	t.Logf("legacy parsed=%+v", got)
	if got.Version != V1 || got.Subject != "legacy-user" || got.Role != "reader" {
		t.Fatalf("legacy identity mismatch: %+v", got)
	}
	// Fixed compatibility semantics: no scopes, no session binding, access kind.
	if len(got.Scopes) != 0 || got.HasScope("read:doc") {
		t.Fatalf("legacy credential must never carry scopes: %+v", got.Scopes)
	}
	if got.SessionID != "" || got.JTI != "" || got.Kind != KindAccess {
		t.Fatalf("legacy credential must not be session-bound or refreshable: %+v", got)
	}

	// Structural parser agrees on shape.
	parsed, err := ParseLegacy(raw)
	if err != nil {
		t.Fatalf("ParseLegacy: %v", err)
	}
	if parsed.Subject != "legacy-user" || !parsed.ExpiresAt.Equal(exp) {
		t.Fatalf("ParseLegacy mismatch: %+v", parsed)
	}

	// Tampered legacy credential must not pass.
	bad := raw[:len(raw)-2] + "00"
	if _, err := signer.Verify(context.Background(), bad); err == nil {
		t.Fatal("tampered legacy credential must be rejected")
	}
	if _, err := ParseLegacy("junk"); err == nil {
		t.Fatal("malformed legacy input must be rejected")
	}
}

func TestExpiredBoundary(t *testing.T) {
	exp := time.Now()
	c := &Claims{ExpiresAt: exp}
	if !c.Expired(exp) {
		t.Fatal("expiry instant itself must count as expired")
	}
	if c.Expired(exp.Add(-time.Second)) {
		t.Fatal("one second before expiry must not be expired")
	}
	t.Logf("exp=%v: at exp -> expired, exp-1s -> valid", exp)
}

func flip(c byte) string {
	if c == 'a' {
		return "b"
	}
	return "a"
}

var _ = strings.TrimSpace
