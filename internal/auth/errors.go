package auth

// ErrorCode 是对外暴露的、可区分的归一化拒绝原因。
type ErrorCode string

const (
	// CodeMissingCredentials 请求未携带凭据。
	CodeMissingCredentials ErrorCode = "missing_credentials"
	// CodeInvalidCredentials 用户名/密码错误，或凭据签名被篡改、无法解析。
	CodeInvalidCredentials ErrorCode = "invalid_credentials"
	// CodeTokenExpired 凭据已过期。
	CodeTokenExpired ErrorCode = "token_expired"
	// CodeInsufficientScope 已认证但角色/作用域不足。
	CodeInsufficientScope ErrorCode = "insufficient_scope"
	// CodeSessionRevoked 会话已失效（主动注销或刷新重放导致的整条链失效）。
	CodeSessionRevoked ErrorCode = "session_revoked"
	// CodeRefreshReused 刷新凭据被重复/并发使用（旧值已轮换）。
	CodeRefreshReused ErrorCode = "refresh_token_reused"
	// CodeRefreshInvalid 刷新凭据类型错误或不属于已知会话。
	CodeRefreshInvalid ErrorCode = "refresh_invalid"
	// CodeRateLimited 同一账号/来源尝试过于频繁，处于限制期。
	CodeRateLimited ErrorCode = "rate_limited"
	// CodeLegacyDenied 旧格式(v1)凭据在不允许的入口使用，默认拒绝、不放行。
	CodeLegacyDenied ErrorCode = "legacy_token_denied"
	// CodeInternal 内部错误的统一归一化结果，底层细节不透出。
	CodeInternal ErrorCode = "internal_error"
)

// AuthError 是所有对外错误的统一形态。
// Message 可安全展示给调用方；cause 仅用于服务端日志，不对外透出。
type AuthError struct {
	Code    ErrorCode
	Message string
	cause   error
}

func (e *AuthError) Error() string { return string(e.Code) + ": " + e.Message }

// Unwrap 便于服务端内部判定/日志记录。
func (e *AuthError) Unwrap() error { return e.cause }

func newError(code ErrorCode, message string, cause error) *AuthError {
	return &AuthError{Code: code, Message: message, cause: cause}
}

// AsAuthError 从任意错误中提取 *AuthError。
func AsAuthError(err error) (*AuthError, bool) {
	if err == nil {
		return nil, false
	}
	if ae, ok := err.(*AuthError); ok {
		return ae, true
	}
	return nil, false
}

// normalizeError 把内部错误（签名失败、解析失败等）归一化：
// 已是 AuthError 的保留其可区分原因；其他未知错误一律归为 CodeInternal，
// 绝不把底层错误文本（如签名细节）直接返回给调用方。
func normalizeError(err error) *AuthError {
	if err == nil {
		return nil
	}
	if ae, ok := err.(*AuthError); ok {
		return ae
	}
	return newError(CodeInternal, "内部认证处理失败", err)
}
