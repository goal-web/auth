// Package auth provides authentication functionality and singleton access.
// 包 auth 提供认证功能和单例访问。
package auth

import (
	"sync"

	"github.com/goal-web/application"
	"github.com/goal-web/contracts"
)

// singleton holds the singleton instance of the auth service.
// singleton 保存认证服务的单例实例。
var singleton contracts.Auth

// once ensures the singleton is initialized only once.
// once 确保单例只被初始化一次。
var once sync.Once

// Default returns the singleton instance of the auth service.
// Default 返回认证服务的单例实例。
func Default() contracts.Auth {
	once.Do(func() {
		singleton = application.Get("auth").(contracts.Auth)
	})

	return singleton
}

// ExtendUserProvider extends the user provider with a custom driver.
// ExtendUserProvider 使用自定义驱动扩展用户提供者。
func ExtendUserProvider(name string, provider contracts.UserProviderDriver) {
	Default().ExtendUserProvider(name, provider)
}

// ExtendGuard extends the guard with a custom driver.
// ExtendGuard 使用自定义驱动扩展守卫。
func ExtendGuard(name string, guard contracts.GuardDriver) {
	Default().ExtendGuard(name, guard)
}

// GetGuard returns the authentication guard with the given name.
// GetGuard 返回指定名称的认证守卫。
func GetGuard(name string, ctx contracts.Context) contracts.Guard {
	return Default().Guard(name, ctx)
}

// UserProvider returns the user provider with the given name.
// UserProvider 返回指定名称的用户提供者。
func UserProvider(name string) contracts.UserProvider {
	return Default().UserProvider(name)
}
