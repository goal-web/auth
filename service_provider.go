// Package auth provides authentication functionality and singleton access.
// 包 auth 提供认证功能和单例访问。
package auth

import (
	"github.com/goal-web/auth/guards"
	"github.com/goal-web/auth/providers"
	"github.com/goal-web/contracts"
)

// serviceProvider implements the contracts.ServiceProvider interface for auth service.
// serviceProvider 实现认证服务的 contracts.ServiceProvider 接口。
type serviceProvider struct {
}

// NewService creates a new instance of the auth service provider.
// NewService 创建认证服务提供者的新实例。
func NewService() contracts.ServiceProvider {
	return serviceProvider{}
}

// Start starts the auth service provider.
// Start 启动认证服务提供者。
func (provider serviceProvider) Start() error {
	return nil
}

// Stop stops the auth service provider.
// Stop 停止认证服务提供者。
func (provider serviceProvider) Stop() {
}

// Register registers the auth service and related components in the container.
// Register 在容器中注册认证服务和相关组件。
func (provider serviceProvider) Register(container contracts.Application) {
	container.Singleton("auth", func(config contracts.Config, factory contracts.RedisFactory) contracts.Auth {
		authConfig := config.Get("auth").(Config)

		return &Auth{
			authConfig: authConfig,
			guardDrivers: map[string]contracts.GuardDriver{
				"jwt": func(name string, config contracts.Fields, ctx contracts.Context, provider contracts.UserProvider) contracts.Guard {
					guard := guards.JwtGuard(name, config, ctx, provider)

					if factory != nil { // 有 redis 的话
						if redisConnName, ok := config["redis"].(string); ok {
							guard.SetRedis(factory.Connection(redisConnName))
						} else {
							guard.SetRedis(factory.Connection())
						}
					}

					return guard
				},
				"session": guards.SessionGuard,
			},
			userDrivers: map[string]contracts.UserProviderDriver{
				"db": providers.DBDriver,
			},
			userProviders: make(map[string]contracts.UserProvider),
		}
	})
	container.Bind("auth.guard", func(config contracts.Config, auth contracts.Auth, ctx contracts.Context) contracts.Guard {
		return auth.Guard(config.Get("auth").(Config).Defaults.Guard, ctx)
	})
	container.Call(func(middleware contracts.Middleware) {
		middleware.Register("auth", Middleware)
		middleware.Register("guest", GuestMiddleware)
	})
}
