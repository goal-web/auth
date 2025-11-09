// Package auth provides authentication functionality and singleton access.
// 包 auth 提供认证功能和单例访问。
package auth

import (
	"github.com/goal-web/contracts"
)

// GuardException represents an error related to authentication guards.
// GuardException 表示与认证守卫相关的错误。
type GuardException struct {
	contracts.Exception

	Ctx contracts.Context // Ctx holds the context of the request.
	                        // Ctx 保存请求的上下文。
}

// UserProviderException represents an error related to user providers.
// UserProviderException 表示与用户提供者相关的错误。
type UserProviderException struct {
	contracts.Exception
}
