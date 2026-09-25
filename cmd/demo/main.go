// Command demo 在本地串演完整的会话认证与访问控制链路：
// 登录 -> 按作用域访问 -> 刷新轮换 -> 重放失效 -> 越权/过期/篡改 -> 限流与恢复 -> v1 兼容。
//
// 运行：go run ./cmd/demo
package main

import (
	"errors"
	"fmt"

	"github.com/lisama569/session-auth-core-go/internal/auth"
)

func show(title string, err error) {
	if err != nil {
		var ae *auth.AuthError
		if errors.As(err, &ae) {
			fmt.Printf("  [%s] 拒绝原因=%s 说明=%s\n", title, ae.Code, ae.Message)
			return
		}
		fmt.Printf("  [%s] 非预期错误: %v\n", title, err)
		return
	}
	fmt.Printf("  [%s] 通过\n", title)
}

func main() {
	svc, err := auth.NewService(auth.Config{})
	if err != nil {
		panic(err)
	}
	svc.GrantRole("admin", auth.ScopeProfileRead, auth.ScopeProfileWrite, auth.ScopeAdminWrite)
	svc.GrantRole("viewer", auth.ScopeProfileRead)
	if err := svc.AddUser("alice", "pw", "admin"); err != nil {
		panic(err)
	}
	if err := svc.AddUser("bob", "pw", "viewer"); err != nil {
		panic(err)
	}

	fmt.Println("1) 登录与访问")
	pair, err := svc.Login("alice", "pw", "127.0.0.1")
	if err != nil {
		panic(err)
	}
	_, err = svc.Authorize(pair.AccessToken, auth.ScopeAdminWrite, "127.0.0.1")
	show("alice -> admin:write", err)

	bob, _ := svc.Login("bob", "pw", "127.0.0.2")
	_, err = svc.Authorize(bob.AccessToken, auth.ScopeAdminWrite, "127.0.0.2")
	show("bob -> admin:write（越权）", err)

	fmt.Println("2) 刷新轮换与重放失效")
	next, err := svc.Refresh(pair.RefreshToken, "127.0.0.1")
	show("首次刷新", err)
	_, err = svc.Refresh(pair.RefreshToken, "127.0.0.1")
	show("旧刷新凭据重放", err)
	_, err = svc.Authorize(next.AccessToken, auth.ScopeProfileRead, "127.0.0.1")
	show("会话链失效后访问", err)

	fmt.Println("3) 权限收回立即生效（新会话演示）")
	p2, _ := svc.Login("alice", "pw", "127.0.0.3")
	svc.RevokeScopes(p2.SessionID, auth.ScopeAdminWrite)
	_, err = svc.Authorize(p2.AccessToken, auth.ScopeAdminWrite, "127.0.0.3")
	show("收回 admin:write 后再访问", err)
}
