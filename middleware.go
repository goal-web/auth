// Package auth provides authentication functionality and singleton access.
// 包 auth 提供认证功能和单例访问。
package auth

import (
	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/exceptions"
)

// Guard creates a middleware that checks authentication using the specified guards.
// Guard 创建使用指定守卫检查认证的中间件。
func Guard(guards ...string) any {
	return func(request contracts.HttpRequest, next contracts.Pipe, auth contracts.Auth, config contracts.Config) any {
		if len(guards) == 0 {
			guards = append(guards, config.Get("auth").(Config).Defaults.Guard)
		}

		for _, guard := range guards {
			user := auth.Guard(guard, request).User()
			if user == nil {
				panic(GuardException{
					Exception: exceptions.New("auth.middleware: " + guard + " guard authentication failed"),
					Ctx:       request,
				})
			}
		}

		return next(request)
	}
}

// Middleware ensures that the user is authenticated.
// Middleware 确保用户已认证。
func Middleware(request contracts.HttpRequest, next contracts.Pipe, auth contracts.Auth, config contracts.Config, guards ...string) any {
	if len(guards) == 0 {
		guards = append(guards, config.Get("auth").(Config).Defaults.Guard)
	}

	for _, guard := range guards {
		if auth.Guard(guard, request).Guest() {
			panic(GuardException{
				Exception: exceptions.New("auth.middleware: " + guard + " guard authentication failed"),
				Ctx:       request,
			})
		}
	}

	return next(request)
}

// GuestMiddleware ensures that the user is a guest (not authenticated).
// GuestMiddleware 确保用户是访客（未认证）。
func GuestMiddleware(request contracts.HttpRequest, next contracts.Pipe, auth contracts.Auth, config contracts.Config, guards ...string) any {
	if len(guards) == 0 {
		guards = append(guards, config.Get("auth").(Config).Defaults.Guard)
	}

	for _, guard := range guards {
		if !auth.Guard(guard, request).Guest() {
			panic(GuardException{
				Exception: exceptions.New("auth.middleware: " + guard + " guard authentication failed"),
				Ctx:       request,
			})
		}
	}

	return next(request)
}
