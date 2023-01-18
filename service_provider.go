package auth

import (
	"github.com/goal-web/auth/guards"
	"github.com/goal-web/auth/providers"
	"github.com/goal-web/contracts"
)

type serviceProvider struct {
}

func NewService() contracts.ServiceProvider {
	return serviceProvider{}
}

func (provider serviceProvider) Start() error {
	return nil
}

func (provider serviceProvider) Stop() {
}

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
}
