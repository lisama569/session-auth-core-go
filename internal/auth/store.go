package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"sync"
	"time"
)

// User 是内存用户记录。
type User struct {
	Username     string
	PasswordHash []byte // 本地模拟：salt 拼接后的 SHA-256 摘要
	Salt         []byte
	Role         string
}

// Session 是一条会话链的实时状态。
type Session struct {
	ID           string
	Username     string
	Role         string
	Scopes       []string // 实时作用域；权限收回后立即生效
	RefreshJTI   string   // 当前有效的刷新凭据标识
	Revoked      bool     // 会话链是否已明确失效
	RevokeReason string
	CreatedAt    time.Time
	LastRotateAt time.Time
}

// cloneSession 返回快照副本，避免调用方在锁外修改内部状态。
func cloneSession(in *Session) *Session {
	if in == nil {
		return nil
	}
	out := *in
	out.Scopes = append([]string(nil), in.Scopes...)
	return &out
}

// hashPassword 是本地模拟的口令存储方案（salt + SHA-256）。
// 本项目密钥与会话均为内存态，不依赖外部认证设施。
func hashPassword(salt []byte, password string) []byte {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	return h.Sum(nil)
}

func verifyPassword(u *User, password string) bool {
	got := hashPassword(u.Salt, password)
	return subtle.ConstantTimeCompare(got, u.PasswordHash) == 1
}

// MemoryStore 是用户与会话的并发安全内存存储。
type MemoryStore struct {
	mu       sync.RWMutex
	users    map[string]*User
	sessions map[string]*Session
}

// NewMemoryStore 构造空存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{users: map[string]*User{}, sessions: map[string]*Session{}}
}

func (s *MemoryStore) PutUser(u *User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[u.Username] = u
}

func (s *MemoryStore) GetUser(username string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[username]
	if !ok {
		return nil
	}
	cp := *u
	cp.Salt = append([]byte(nil), u.Salt...)
	cp.PasswordHash = append([]byte(nil), u.PasswordHash...)
	return &cp
}

func (s *MemoryStore) CreateSession(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = cloneSession(sess)
}

// GetSession 返回会话快照；不存在返回 nil。
func (s *MemoryStore) GetSession(id string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSession(s.sessions[id])
}

// RevokeSession 将整条会话链置为失效。
// 已失效的会话保持原有失效原因不变，返回当前是否为失效态。
func (s *MemoryStore) RevokeSession(id, reason string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return false
	}
	if !sess.Revoked {
		sess.Revoked = true
		sess.RevokeReason = reason
	}
	return sess.Revoked
}

// SetSessionScopes 实时替换会话作用域，用于权限收回/调整。
func (s *MemoryStore) SetSessionScopes(id string, scopes []string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || sess.Revoked {
		return false
	}
	sess.Scopes = append([]string(nil), scopes...)
	return true
}

// RevokeScopes 从会话实时作用域中删除指定作用域。
func (s *MemoryStore) RevokeScopes(id string, scopes ...string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || sess.Revoked {
		return false
	}
	drop := make(map[string]struct{}, len(scopes))
	for _, sc := range scopes {
		drop[sc] = struct{}{}
	}
	kept := sess.Scopes[:0]
	for _, sc := range sess.Scopes {
		if _, bad := drop[sc]; !bad {
			kept = append(kept, sc)
		}
	}
	sess.Scopes = append([]string(nil), kept...)
	return true
}

// RotateRefresh 以原子 CAS 方式完成刷新凭据轮换：
// 仅当会话存在、未失效且当前 jti == oldJTI 时写入 newJTI 并轮换时间。
// 重复或并发提交同一刷新凭据时，有且仅有一个请求得到 true。
func (s *MemoryStore) RotateRefresh(id, oldJTI, newJTI string, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || sess.Revoked {
		return false
	}
	if sess.RefreshJTI != oldJTI {
		return false
	}
	sess.RefreshJTI = newJTI
	sess.LastRotateAt = at
	return true
}
