package auth

import (
	"github.com/goal-web/auth/gate"
	"github.com/goal-web/auth/guards"
	"github.com/goal-web/auth/providers"
	"github.com/goal-web/contracts"
)

type ServiceProvider struct {
}

func (this ServiceProvider) Start() error {
	return nil
}

func (this ServiceProvider) Stop() {

}

func (this ServiceProvider) Register(container contracts.Application) {
	container.Singleton("auth", func(config contracts.Config) contracts.Auth {
		authConfig := config.Get("auth").(Config)

		return &Auth{
			authConfig: authConfig,
			guardDrivers: map[string]contracts.GuardDriver{
				"jwt":     guards.JwtGuard,
				"session": guards.SessionGuard,
			},
			userDrivers: map[string]contracts.UserProviderDriver{
				"db": providers.DBDriver,
			},
			userProviders: make(map[string]contracts.UserProvider),
		}
	})
	container.Bind("auth.guard", func(config contracts.Config, auth contracts.Auth, request contracts.HttpRequest) contracts.Guard {
		authConfig := config.Get("auth").(Config)
		return auth.Guard(authConfig.Defaults.Guard, request)
	})

	container.Singleton("gate.factory", func() contracts.GateFactory {
		return gate.NewFactory()
	})
	container.Bind("gate.factory", func(factory contracts.GateFactory, ctx contracts.Context) contracts.Gate {
		instance, exists := ctx.Get("access.gate").(contracts.Gate)
		if exists {
			return instance
		}
		user, _ := ctx.Get("user").(contracts.Authorizable)
		instance = gate.NewGate(factory, user)
		ctx.Set("access.gate", instance)
		return instance
	})
}
