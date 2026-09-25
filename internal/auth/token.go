package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// tokenKind 区分访问凭据与刷新凭据。
type tokenKind string

const (
	kindAccess  tokenKind = "access"
	kindRefresh tokenKind = "refresh"
)

// tokenVersion 标识凭据格式版本。
type tokenVersion string

const (
	versionV1 tokenVersion = "v1" // 旧格式：兼容语义固定，默认不享有新作用域
	versionV2 tokenVersion = "v2" // 当前格式
)

// 内部哨兵错误：不直接透出给调用方，由 Service 归一化到可区分的错误码。
var (
	errTokenMalformed    = errors.New("token malformed")
	errTokenBadSignature = errors.New("token signature mismatch")
	errTokenExpired      = errors.New("token expired")
	errTokenVersion      = errors.New("token version unsupported")
)

// Claims 是凭据的内部声明结构。
type Claims struct {
	Version   tokenVersion `json:"ver"`
	Kind      tokenKind    `json:"k,omitempty"` // v1 无此字段（旧格式只有访问凭据）
	Subject   string       `json:"sub"`
	SessionID string       `json:"sid,omitempty"`
	TokenID   string       `json:"jti,omitempty"`
	Role      string       `json:"role,omitempty"`
	Scopes    []string     `json:"scp,omitempty"` // v2 仅做携带；鉴权以会话实时作用域为准
	IssuedAt  int64        `json:"iat"`
	ExpiresAt int64        `json:"exp"`
}

// TokenManager 使用本地 HMAC-SHA256 密钥完成凭据签发与校验。
type TokenManager struct {
	key []byte
}

// NewTokenManager 以本地密钥构造签名管理器。
func NewTokenManager(key []byte) *TokenManager {
	return &TokenManager{key: append([]byte(nil), key...)}
}

var b64 = base64.RawURLEncoding

// GenerateKey 生成本地随机签名密钥（32 字节）。
func GenerateKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// newID 生成随机的会话/凭据标识。
func newID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + b64.EncodeToString(b), nil
}

func (m *TokenManager) sign(signingInput string) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(signingInput))
	return b64.EncodeToString(mac.Sum(nil))
}

// encode 生成 ver.<payload>.<sig> 三段式凭据。
func (m *TokenManager) encode(c *Claims) (string, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	payload := b64.EncodeToString(raw)
	head := string(c.Version)
	signingInput := head + "." + payload
	return signingInput + "." + m.sign(signingInput), nil
}

func (m *TokenManager) issue(kind tokenKind, subject, sessionID, role string, scopes []string, now time.Time, ttl time.Duration) (string, *Claims, error) {
	jti, err := newID("jti_")
	if err != nil {
		return "", nil, err
	}
	c := &Claims{
		Version:   versionV2,
		Kind:      kind,
		Subject:   subject,
		SessionID: sessionID,
		TokenID:   jti,
		Role:      role,
		Scopes:    append([]string(nil), scopes...),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
	raw, err := m.encode(c)
	return raw, c, err
}

// IssueAccess 签发 v2 访问凭据，返回凭据串及其 jti。
func (m *TokenManager) IssueAccess(subject, sessionID, role string, scopes []string, now time.Time, ttl time.Duration) (string, string, error) {
	raw, c, err := m.issue(kindAccess, subject, sessionID, role, scopes, now, ttl)
	if err != nil {
		return "", "", err
	}
	return raw, c.TokenID, nil
}

// IssueRefresh 签发 v2 刷新凭据，返回凭据串及其 jti。
func (m *TokenManager) IssueRefresh(subject, sessionID, role string, scopes []string, now time.Time, ttl time.Duration) (string, string, error) {
	raw, c, err := m.issue(kindRefresh, subject, sessionID, role, scopes, now, ttl)
	if err != nil {
		return "", "", err
	}
	return raw, c.TokenID, nil
}

// IssueLegacy 签发 v1 旧格式访问凭据。
// 固定语义：不携带会话标识与作用域；可解析出 sub/role/iat/exp。
// 仅用于兼容性测试与灰度入口，绝不默认获得新作用域。
func (m *TokenManager) IssueLegacy(subject, role string, now time.Time, ttl time.Duration) (string, error) {
	c := &Claims{
		Version:   versionV1,
		Subject:   subject,
		Role:      role,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
	return m.encode(c)
}

// Parse 校验签名并解析凭据。
// 过期 -> errTokenExpired；被篡改/格式错误 -> errTokenBadSignature/errTokenMalformed。
func (m *TokenManager) Parse(raw string, now time.Time) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, errTokenMalformed
	}
	ver, payload, sig := parts[0], parts[1], parts[2]
	signingInput := ver + "." + payload

	expected := m.sign(signingInput)
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return nil, errTokenBadSignature
	}

	body, err := b64.DecodeString(payload)
	if err != nil {
		return nil, errTokenMalformed
	}
	c := &Claims{}
	if err := json.Unmarshal(body, c); err != nil {
		return nil, errTokenMalformed
	}
	switch tokenVersion(ver) {
	case versionV1:
		c.Version = versionV1
	case versionV2:
		c.Version = versionV2
		if c.Kind != kindAccess && c.Kind != kindRefresh {
			return nil, errTokenMalformed
		}
	default:
		return nil, errTokenVersion
	}
	if c.Subject == "" || c.ExpiresAt == 0 {
		return nil, errTokenMalformed
	}
	if now.Unix() >= c.ExpiresAt {
		return c, errTokenExpired
	}
	return c, nil
}

// String 用于测试日志，避免直接打印完整凭据。
func (c *Claims) String() string {
	return fmt.Sprintf("Claims{ver=%s kind=%s sub=%s sid=%s jti=%s role=%s scp=%v iat=%d exp=%d}",
		c.Version, c.Kind, c.Subject, c.SessionID, c.TokenID, c.Role, c.Scopes, c.IssuedAt, c.ExpiresAt)
}
