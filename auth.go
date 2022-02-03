package auth

import (
	"fmt"
	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/exceptions"
	"github.com/goal-web/supports/utils"
)

type Auth struct {
	authConfig Config

	guardDrivers  map[string]contracts.GuardDriver
	userProviders map[string]contracts.UserProvider
	userDrivers   map[string]contracts.UserProviderDriver
}

func (this *Auth) ExtendUserProvider(key string, provider contracts.UserProviderDriver) {
	this.userDrivers[key] = provider
}

func (this *Auth) ExtendGuard(key string, guard contracts.GuardDriver) {
	this.guardDrivers[key] = guard
}

func (this *Auth) Guard(key string, ctx contracts.Context) contracts.Guard {
	config := this.authConfig.Guards[key]
	driver := utils.GetStringField(config, "driver")

	if guardDriver, existsDriver := this.guardDrivers[driver]; existsDriver {
		return guardDriver(key, config, ctx, this.UserProvider(utils.GetStringField(config, "provider")))
	}

	panic(GuardException{
		Exception: exceptions.New(fmt.Sprintf("unsupported guard driver：%s", driver), config),
	})
}

func (this *Auth) UserProvider(key string) contracts.UserProvider {
	if userProvider, existsUserProvider := this.userProviders[key]; existsUserProvider {
		return userProvider
	}

	config := this.authConfig.Users[key]
	driver := utils.GetStringField(config, "driver")

	if userDriver, existsProvider := this.userDrivers[driver]; existsProvider {
		this.userProviders[key] = userDriver(config)
		return this.userProviders[key]
	}

	panic(UserProviderException{
		Exception: exceptions.New(fmt.Sprintf("unsupported user driver：%s", driver), config),
	})
}
