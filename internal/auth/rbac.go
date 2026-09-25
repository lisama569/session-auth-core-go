package auth

// 作用域常量：避免各入口出现魔法字符串。
const (
	ScopeProfileRead  = "profile:read"
	ScopeProfileWrite = "profile:write"
	ScopeAdminRead    = "admin:read"
	ScopeAdminWrite   = "admin:write"
	ScopeLegacyRead   = "legacy:read"
)

// Policy 描述“角色 -> 静态作用域集合”的授权关系。
// 运行期判定以会话上的实时作用域为准，Policy 负责作用域集合的语义判定。
type Policy struct {
	roleScopes map[string]map[string]struct{}
}

// NewPolicy 构造空策略。
func NewPolicy() *Policy {
	return &Policy{roleScopes: map[string]map[string]struct{}{}}
}

// Grant 给角色授予一个或多个作用域。
func (p *Policy) Grant(role string, scopes ...string) {
	set, ok := p.roleScopes[role]
	if !ok {
		set = map[string]struct{}{}
		p.roleScopes[role] = set
	}
	for _, sc := range scopes {
		set[sc] = struct{}{}
	}
}

// ScopesForRole 返回角色静态作用域的副本；未知角色返回空（不默认放行）。
func (p *Policy) ScopesForRole(role string) []string {
	set, ok := p.roleScopes[role]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(set))
	for sc := range set {
		out = append(out, sc)
	}
	return out
}

// Authorize 判定实时作用域集合是否满足所需作用域。
// 语义确定：要求非空作用域时，空集合必然拒绝（不放行）。
func (p *Policy) Authorize(liveScopes []string, requiredScope string) bool {
	if requiredScope == "" {
		return true
	}
	for _, sc := range liveScopes {
		if sc == requiredScope {
			return true
		}
	}
	return false
}

// legacyScopeSet 是旧格式(v1)凭据的固定兼容作用域。
// 确定且稳定：v1 永远只能得到 legacy:read，
// 不能访问 v2 才有的 profile/admin 作用域，也不随角色升级而扩大。
var legacyScopeSet = []string{ScopeLegacyRead}

// LegacyScopes 返回 v1 凭据的固定兼容作用域。
func LegacyScopes() []string {
	return append([]string(nil), legacyScopeSet...)
}
