package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

// 会话失效原因（内部记录，决定对外返回哪个可区分错误码）。
const (
	revokeReasonAdmin = "revoked_by_admin"
	revokeReasonReuse = "refresh_token_reuse"
)

// Config 是 Service 的本地配置。
type Config struct {
	SigningKey       []byte
	AccessTTL        time.Duration
	RefreshTTL       time.Duration
	LoginMaxAttempts int
	RateWindow       time.Duration
	// AllowLegacyAccess 决定 Authorize 入口是否接受旧格式(v1)凭据。
	// 默认 false：旧凭据不放行；开启后其能力也固定为 legacy:read。
	AllowLegacyAccess bool
	Clock             Clock
}

// TokenPair 是登录/刷新成功后签发的凭据对。
type TokenPair struct {
	AccessToken   string
	RefreshToken  string
	AccessExpiry  time.Time
	RefreshExpiry time.Time
	SessionID     string
}

// Principal 是鉴权成功后呈现给调用方的身份与实时权限快照。
type Principal struct {
	Username  string
	SessionID string
	Role      string
	Scopes    []string
	Legacy    bool // 是否为旧格式(v1)凭据
}

// Service 是对外统一门面：登录、刷新轮换、访问判定、权限/会话管理。
type Service struct {
	cfg     Config
	tokens  *TokenManager
	store   *MemoryStore
	policy  *Policy
	limiter *RateLimiter
	clock   Clock
	logger  *log.Logger
}

// NewService 构造 Service，并补齐确定性的本地默认值。
func NewService(cfg Config) (*Service, error) {
	if cfg.Clock == nil {
		cfg.Clock = SystemClock{}
	}
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = 15 * time.Minute
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 24 * time.Hour
	}
	if cfg.LoginMaxAttempts <= 0 {
		cfg.LoginMaxAttempts = 5
	}
	if cfg.RateWindow <= 0 {
		cfg.RateWindow = time.Minute
	}
	key := cfg.SigningKey
	if len(key) == 0 {
		k, err := GenerateKey()
		if err != nil {
			return nil, normalizeError(err)
		}
		key = k
	}
	return &Service{
		cfg:     cfg,
		tokens:  NewTokenManager(key),
		store:   NewMemoryStore(),
		policy:  NewPolicy(),
		limiter: NewRateLimiter(cfg.Clock, cfg.LoginMaxAttempts, cfg.RateWindow),
		clock:   cfg.Clock,
		logger:  log.New(os.Stderr, "[auth] ", log.LstdFlags|log.Lmicroseconds),
	}, nil
}

// SetLogOutput 重定向审计/判定日志（测试可据此捕获日志内容）。
func (s *Service) SetLogOutput(w io.Writer) {
	s.logger = log.New(w, "[auth] ", log.LstdFlags|log.Lmicroseconds)
}

// audit 打印一次入口调用的输入摘要与判定依据。
// 凭据只打印指纹，不输出明文；错误只打印归一化码，不打印底层细节。
func (s *Service) audit(event string, fields ...string) {
	s.logger.Printf("%s %s", event, strings.Join(fields, " "))
}

// fingerprint 返回凭据的短指纹，便于日志区分却不泄露凭据本身。
func fingerprint(raw string) string {
	if raw == "" {
		return "-"
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:4])
}

func (s *Service) now() time.Time { return s.clock.Now() }

// AddUser 注册一个本地用户，口令以 salt+SHA-256 保存于内存。
func (s *Service) AddUser(username, password, role string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return normalizeError(err)
	}
	s.store.PutUser(&User{
		Username:     username,
		Salt:         salt,
		PasswordHash: hashPassword(salt, password),
		Role:         role,
	})
	return nil
}

// rateEnter 在入口记录一次尝试并立即判定：
// 窗口内第 1..max 次尝试放行，把计数推过阈值的第 max+1 次尝试本身即被拒绝。
func (s *Service) rateEnter(keys ...string) *AuthError {
	for _, k := range keys {
		if !s.limiter.Allow(k) {
			return newError(CodeRateLimited, "尝试过于频繁，请稍后再试", nil)
		}
	}
	return nil
}

// Login 校验账密并签发凭据对。
func (s *Service) Login(username, password, source string) (*TokenPair, error) {
	userKey, srcKey := "login:user:"+username, "login:src:"+source
	if ae := s.rateEnter(userKey, srcKey); ae != nil {
		s.audit("login.deny", "user="+username, "src="+source, "reason="+string(ae.Code),
			"retry_after="+s.limiter.RetryAfter(userKey).String())
		return nil, ae
	}

	user := s.store.GetUser(username)
	if user == nil || !verifyPassword(user, password) {
		count, _, _ := s.limiter.State(userKey)
		s.audit("login.deny", "user="+username, "src="+source,
			"reason="+string(CodeInvalidCredentials), "attempts="+itoa(count))
		return nil, newError(CodeInvalidCredentials, "用户名或密码错误", nil)
	}

	sid, err := newID("sess_")
	if err != nil {
		return nil, normalizeError(err)
	}
	now := s.now()
	scopes := s.policy.ScopesForRole(user.Role)
	sess := &Session{
		ID:        sid,
		Username:  username,
		Role:      user.Role,
		Scopes:    scopes,
		CreatedAt: now,
	}
	pair, err := s.issuePair(sess, now)
	if err != nil {
		return nil, err
	}
	s.limiter.Reset(userKey)
	s.limiter.Reset(srcKey)
	s.audit("login.ok", "user="+username, "src="+source, "sid="+sid,
		"role="+user.Role, "scopes="+strings.Join(scopes, ","))
	return pair, nil
}

// issuePair 为会话签发新的凭据对，并把刷新凭据 jti 注册为会话当前有效值。
func (s *Service) issuePair(sess *Session, now time.Time) (*TokenPair, error) {
	access, _, err := s.tokens.IssueAccess(sess.Username, sess.ID, sess.Role, sess.Scopes, now, s.cfg.AccessTTL)
	if err != nil {
		return nil, normalizeError(err)
	}
	refresh, rjti, err := s.tokens.IssueRefresh(sess.Username, sess.ID, sess.Role, sess.Scopes, now, s.cfg.RefreshTTL)
	if err != nil {
		return nil, normalizeError(err)
	}
	if sess.RefreshJTI == "" {
		// 登录：先建会话
		sess.RefreshJTI = rjti
		s.store.CreateSession(sess)
	} else {
		// 刷新轮换：CAS 由调用方保证成功，这里同步存储层的 jti。
		if !s.store.RotateRefresh(sess.ID, sess.RefreshJTI, rjti, now) {
			return nil, newError(CodeRefreshReused, "刷新凭据已被使用，会话已失效", nil)
		}
	}
	return &TokenPair{
		AccessToken:   access,
		RefreshToken:  refresh,
		AccessExpiry:  now.Add(s.cfg.AccessTTL),
		RefreshExpiry: now.Add(s.cfg.RefreshTTL),
		SessionID:     sess.ID,
	}, nil
}

// mapParseError 把令牌解析的内部哨兵错误映射为可区分的对外错误码。
func mapParseError(err error) *AuthError {
	switch {
	case errors.Is(err, errTokenExpired):
		return newError(CodeTokenExpired, "凭据已过期", err)
	case errors.Is(err, errTokenBadSignature):
		return newError(CodeInvalidCredentials, "凭据签名无效（可能被篡改）", err)
	case errors.Is(err, errTokenMalformed), errors.Is(err, errTokenVersion):
		return newError(CodeInvalidCredentials, "凭据格式无效", err)
	default:
		return normalizeError(err)
	}
}

// Refresh 使用刷新凭据轮换出新凭据对。
// 刷新凭据有且仅有一次有效：重放/并发输家会得到 refresh_token_reused，
// 且整条会话链被置为明确的失效状态。
func (s *Service) Refresh(refreshToken, source string) (*TokenPair, error) {
	srcKey := "refresh:src:" + source
	if ae := s.rateEnter(srcKey); ae != nil {
		s.audit("refresh.deny", "fp="+fingerprint(refreshToken), "src="+source, "reason="+string(ae.Code))
		return nil, ae
	}
	if strings.TrimSpace(refreshToken) == "" {
		return nil, newError(CodeMissingCredentials, "缺少刷新凭据", nil)
	}
	claims, err := s.tokens.Parse(refreshToken, s.now())
	if err != nil {
		ae := mapParseError(err)
		s.audit("refresh.deny", "fp="+fingerprint(refreshToken), "src="+source,
			"reason="+string(ae.Code), "basis=parse")
		return nil, ae
	}
	if claims.Version == versionV1 {
		// 旧格式只有访问凭据，刷新入口确定拒绝，绝不放行。
		return nil, newError(CodeLegacyDenied, "旧格式凭据不支持刷新", nil)
	}
	if claims.Kind != kindRefresh {
		return nil, newError(CodeRefreshInvalid, "凭据类型不是刷新凭据", nil)
	}

	sess := s.store.GetSession(claims.SessionID)
	if sess == nil {
		s.audit("refresh.deny", "fp="+fingerprint(refreshToken), "sub="+claims.Subject,
			"sid="+claims.SessionID, "reason="+string(CodeRefreshInvalid), "basis=session_missing")
		return nil, newError(CodeRefreshInvalid, "刷新凭据无效", nil)
	}
	if sess.Revoked {
		return nil, s.revokedRefreshError(sess)
	}
	if sess.RefreshJTI != claims.TokenID {
		// 提交的是已轮换下去的旧刷新凭据：明确失效整条链。
		s.store.RevokeSession(sess.ID, revokeReasonReuse)
		s.audit("refresh.deny", "fp="+fingerprint(refreshToken), "sid="+sess.ID,
			"reason="+string(CodeRefreshReused), "basis=jti_mismatch")
		return nil, newError(CodeRefreshReused, "刷新凭据已被使用，会话已失效", nil)
	}

	// 原子 CAS：并发/重复提交同一 jti 时只有一个赢家。
	newRefresh, newJTI, err := s.tokens.IssueRefresh(sess.Username, sess.ID, sess.Role, sess.Scopes, s.now(), s.cfg.RefreshTTL)
	if err != nil {
		return nil, normalizeError(err)
	}
	if !s.store.RotateRefresh(sess.ID, claims.TokenID, newJTI, s.now()) {
		// CAS 输家：说明同凭据被并发使用。把会话链标记为重放失效（幂等）。
		s.store.RevokeSession(sess.ID, revokeReasonReuse)
		s.audit("refresh.deny", "fp="+fingerprint(refreshToken), "sid="+sess.ID,
			"reason="+string(CodeRefreshReused), "basis=cas_lost")
		return nil, newError(CodeRefreshReused, "刷新凭据已被使用，会话已失效", nil)
	}

	now := s.now()
	access, _, err := s.tokens.IssueAccess(sess.Username, sess.ID, sess.Role, sess.Scopes, now, s.cfg.AccessTTL)
	if err != nil {
		return nil, normalizeError(err)
	}
	s.audit("refresh.ok", "fp="+fingerprint(refreshToken), "new_fp="+fingerprint(newRefresh),
		"sid="+sess.ID, "sub="+sess.Username, "basis=cas_win")
	return &TokenPair{
		AccessToken:   access,
		RefreshToken:  newRefresh,
		AccessExpiry:  now.Add(s.cfg.AccessTTL),
		RefreshExpiry: now.Add(s.cfg.RefreshTTL),
		SessionID:     sess.ID,
	}, nil
}

func (s *Service) revokedRefreshError(sess *Session) *AuthError {
	switch sess.RevokeReason {
	case revokeReasonReuse:
		s.audit("refresh.deny", "sid="+sess.ID, "reason="+string(CodeRefreshReused), "basis=session_revoked_reuse")
		return newError(CodeRefreshReused, "刷新凭据已被使用，会话已失效", nil)
	default:
		s.audit("refresh.deny", "sid="+sess.ID, "reason="+string(CodeSessionRevoked), "basis=session_revoked")
		return newError(CodeSessionRevoked, "会话已失效", nil)
	}
}

// Authorize 校验访问凭据并按会话的实时作用域判定。
func (s *Service) Authorize(accessToken, requiredScope, source string) (*Principal, error) {
	srcKey := "access:src:" + source
	if ae := s.rateEnter(srcKey); ae != nil {
		s.audit("access.deny", "fp="+fingerprint(accessToken), "src="+source,
			"need="+requiredScope, "reason="+string(ae.Code))
		return nil, ae
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, newError(CodeMissingCredentials, "缺少访问凭据", nil)
	}
	claims, err := s.tokens.Parse(accessToken, s.now())
	if err != nil {
		ae := mapParseError(err)
		s.audit("access.deny", "fp="+fingerprint(accessToken), "src="+source,
			"need="+requiredScope, "reason="+string(ae.Code), "basis=parse")
		return nil, ae
	}

	if claims.Version == versionV1 {
		return s.authorizeLegacy(claims, requiredScope)
	}
	if claims.Kind != kindAccess {
		return nil, newError(CodeRefreshInvalid, "凭据类型不是访问凭据", nil)
	}

	sess := s.store.GetSession(claims.SessionID)
	if sess == nil {
		s.audit("access.deny", "fp="+fingerprint(accessToken), "sid="+claims.SessionID,
			"need="+requiredScope, "reason="+string(CodeInvalidCredentials), "basis=session_missing")
		return nil, newError(CodeInvalidCredentials, "凭据对应的会话不存在", nil)
	}
	if sess.Revoked {
		s.audit("access.deny", "fp="+fingerprint(accessToken), "sid="+sess.ID,
			"need="+requiredScope, "reason="+string(CodeSessionRevoked), "basis=session_revoked")
		return nil, newError(CodeSessionRevoked, "会话已失效", nil)
	}

	// 关键语义：以会话上的实时角色/作用域为准，而非令牌内的快照，
	// 因而权限收回后既有会话立即失去被收回的能力。
	if !s.policy.Authorize(sess.Scopes, requiredScope) {
		s.audit("access.deny", "fp="+fingerprint(accessToken), "sid="+sess.ID,
			"sub="+sess.Username, "role="+sess.Role, "need="+requiredScope,
			"live_scopes="+strings.Join(sess.Scopes, ","),
			"reason="+string(CodeInsufficientScope), "basis=live_scopes")
		return nil, newError(CodeInsufficientScope, "权限不足", nil)
	}
	s.audit("access.ok", "fp="+fingerprint(accessToken), "sid="+sess.ID,
		"sub="+sess.Username, "role="+sess.Role, "need="+requiredScope,
		"live_scopes="+strings.Join(sess.Scopes, ","), "basis=live_scopes")
	return &Principal{
		Username:  sess.Username,
		SessionID: sess.ID,
		Role:      sess.Role,
		Scopes:    append([]string(nil), sess.Scopes...),
	}, nil
}

// authorizeLegacy 固定 v1 旧格式凭据的兼容语义：
// 未显式开启 -> 默认拒绝；开启后只享有固定 legacy:read，其余作用域一律拒绝。
func (s *Service) authorizeLegacy(c *Claims, requiredScope string) (*Principal, error) {
	if !s.cfg.AllowLegacyAccess {
		s.audit("access.deny", "sub="+c.Subject, "ver=v1",
			"need="+requiredScope, "reason="+string(CodeLegacyDenied), "basis=legacy_disabled")
		return nil, newError(CodeLegacyDenied, "旧格式凭据已不再接受", nil)
	}
	scopes := LegacyScopes()
	if requiredScope != ScopeLegacyRead {
		s.audit("access.deny", "sub="+c.Subject, "ver=v1",
			"need="+requiredScope, "legacy_scopes="+strings.Join(scopes, ","),
			"reason="+string(CodeInsufficientScope), "basis=legacy_fixed_scopes")
		return nil, newError(CodeInsufficientScope, "旧格式凭据权限不足", nil)
	}
	s.audit("access.ok", "sub="+c.Subject, "ver=v1",
		"need="+requiredScope, "basis=legacy_fixed_scopes")
	return &Principal{
		Username: c.Subject,
		Role:     c.Role,
		Scopes:   scopes,
		Legacy:   true,
	}, nil
}

// RevokeSession 主动注销整条会话链；之后该会话的访问与刷新都以 session_revoked 拒绝。
func (s *Service) RevokeSession(sessionID string) bool {
	ok := s.store.RevokeSession(sessionID, revokeReasonAdmin)
	s.audit("session.revoke", "sid="+sessionID, "ok="+boolStr(ok))
	return ok
}

// RevokeScopes 从会话实时作用域中收回指定作用域，对既有会话立即生效。
func (s *Service) RevokeScopes(sessionID string, scopes ...string) bool {
	ok := s.store.RevokeScopes(sessionID, scopes...)
	s.audit("session.revoke_scopes", "sid="+sessionID, "drop="+strings.Join(scopes, ","), "ok="+boolStr(ok))
	return ok
}

// GrantRole 配置角色静态作用域（通常在启动时调用）。
func (s *Service) GrantRole(role string, scopes ...string) {
	s.policy.Grant(role, scopes...)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
