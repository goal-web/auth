// Package auth provides authentication functionality and singleton access.
// 包 auth 提供认证功能和单例访问。
package auth

import (
	"fmt"
	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/exceptions"
	"github.com/goal-web/supports/utils"
	"sync"
)

// Auth implements the authentication service interface.
// Auth 实现认证服务接口。
type Auth struct {
	authConfig Config

	mutex         sync.RWMutex                       // mutex provides thread-safe access to the auth service.
	                                                  // mutex 提供对认证服务的线程安全访问。
	guardDrivers  map[string]contracts.GuardDriver   // guardDrivers holds registered guard drivers.
	                                                  // guardDrivers 保存已注册的守卫驱动。
	userProviders map[string]contracts.UserProvider  // userProviders holds instantiated user providers.
	                                                  // userProviders 保存已实例化的用户提供者。
	userDrivers   map[string]contracts.UserProviderDriver // userDrivers holds registered user provider drivers.
	                                                  // userDrivers 保存已注册的用户驱动。
}

// ExtendUserProvider registers a custom user provider driver.
// ExtendUserProvider 注册自定义用户提供者驱动。
func (auth *Auth) ExtendUserProvider(key string, provider contracts.UserProviderDriver) {
	auth.mutex.Lock()
	defer auth.mutex.Unlock()
	auth.userDrivers[key] = provider
}

// ExtendGuard registers a custom guard driver.
// ExtendGuard 注册自定义守卫驱动。
func (auth *Auth) ExtendGuard(key string, guard contracts.GuardDriver) {
	auth.mutex.Lock()
	defer auth.mutex.Unlock()
	auth.guardDrivers[key] = guard
}

// Guard returns an authentication guard instance with the given name.
// Guard 返回指定名称的认证守卫实例。
func (auth *Auth) Guard(key string, ctx contracts.Context) contracts.Guard {
	config := auth.authConfig.Guards[key]
	driver := utils.GetStringField(config, "driver")

	if guardDriver, existsDriver := auth.guardDrivers[driver]; existsDriver {
		return guardDriver(key, config, ctx, auth.UserProvider(utils.GetStringField(config, "provider")))
	}

	panic(GuardException{
		Exception: exceptions.New("unsupported guard driver：" + driver),
		Ctx:       ctx,
	})
}

// UserProvider returns a user provider instance with the given name.
// UserProvider 返回指定名称的用户提供者实例。
func (auth *Auth) UserProvider(key string) contracts.UserProvider {
	if userProvider, existsUserProvider := auth.userProviders[key]; existsUserProvider {
		return userProvider
	}

	config := auth.authConfig.Users[key]
	driver := utils.GetStringField(config, "driver")

	if userDriver, existsProvider := auth.userDrivers[driver]; existsProvider {
		auth.mutex.Lock()
		defer auth.mutex.Unlock()
		auth.userProviders[key] = userDriver(config)
		return auth.userProviders[key]
	}

	panic(UserProviderException{
		Exception: exceptions.WithError(fmt.Errorf("unsupported user driver：%s", driver)),
	})
}
