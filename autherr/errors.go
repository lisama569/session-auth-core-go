// Package autherr defines normalized, distinguishable rejection reasons used
// across every entry point of the session-auth core. Internal failures
// (crypto/parse errors, storage inconsistencies) are collapsed into
// ReasonInternal so no underlying error text ever reaches a caller.
package autherr

import "errors"

// Reason is the normalized machine-readable rejection reason returned to
// callers.
type Reason string

const (
	ReasonNone              Reason = ""
	ReasonInvalidCredential Reason = "invalid_credential"       // malformed or tampered credential
	ReasonMissingCredential Reason = "missing_credential"       // no credential presented
	ReasonExpiredCredential Reason = "credential_expired"       // well-formed but past expiry
	ReasonReusedRefresh     Reason = "refresh_replayed"         // refresh credential already consumed
	ReasonSessionInvalid    Reason = "session_invalid"          // chain invalidated by replay/revocation
	ReasonSessionEvicted    Reason = "session_evicted"          // pushed out by a newer session (LRU cap)
	ReasonSessionIdleExp    Reason = "session_idle_expired"     // no activity within idle lifetime
	ReasonSessionAbsExp     Reason = "session_absolute_expired" // absolute lifetime reached
	ReasonSessionKicked     Reason = "session_kicked"           // explicitly kicked by the account owner
	ReasonPermissionDenied  Reason = "permission_denied"        // authenticated but scope absent/revoked
	ReasonRateLimited       Reason = "rate_limited"             // too many attempts for account/source
	ReasonInternal          Reason = "internal_error"           // normalized non-disclosing failure
)

// Error is the normalized error type exposed to callers.
type Error struct {
	Reason Reason
	msg    string
}

func (e *Error) Error() string { return e.msg }

// New builds a normalized error with an explicit message.
func New(reason Reason, msg string) *Error {
	if msg == "" {
		msg = string(reason)
	}
	return &Error{Reason: reason, msg: msg}
}

// Convenience constructors with fixed, stable wording.
func MissingCredential() *Error { return New(ReasonMissingCredential, "missing credential") }
func InvalidCredential() *Error { return New(ReasonInvalidCredential, "invalid credential") }
func ExpiredCredential() *Error { return New(ReasonExpiredCredential, "credential expired") }
func ReusedRefresh() *Error {
	return New(ReasonReusedRefresh, "refresh credential has already been used")
}
func SessionInvalid() *Error { return New(ReasonSessionInvalid, "session is no longer valid") }
func SessionEvicted() *Error {
	return New(ReasonSessionEvicted, "session was evicted by a newer login")
}
func SessionIdleExpired() *Error {
	return New(ReasonSessionIdleExp, "session expired after inactivity")
}
func SessionAbsoluteExpired() *Error {
	return New(ReasonSessionAbsExp, "session reached its absolute lifetime; log in again")
}
func SessionKicked() *Error    { return New(ReasonSessionKicked, "session was kicked") }
func PermissionDenied() *Error { return New(ReasonPermissionDenied, "permission denied") }
func RateLimited() *Error      { return New(ReasonRateLimited, "too many attempts; try again later") }
func Internal() *Error         { return New(ReasonInternal, "internal error") }

// ReasonOf extracts the normalized Reason from an error.
func ReasonOf(err error) Reason {
	var ae *Error
	if errors.As(err, &ae) {
		return ae.Reason
	}
	return ReasonInternal
}

// Normalize maps any error to a normalized *Error. An error that is already
// normalized passes through; anything else (crypto/parse/driver errors) is
// collapsed to ReasonInternal without preserving its text.
func Normalize(err error) *Error {
	if err == nil {
		return nil
	}
	var ae *Error
	if errors.As(err, &ae) {
		return ae
	}
	return Internal()
}
