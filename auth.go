package auth

import (
	"errors"
	"fmt"
	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/utils"
)

type Auth struct {
	authConfig Config

	guardDrivers  map[string]contracts.GuardDriver
	userProviders map[string]contracts.UserProvider
	userDrivers   map[string]contracts.UserProviderDriver
}

func (auth *Auth) ExtendUserProvider(key string, provider contracts.UserProviderDriver) {
	auth.userDrivers[key] = provider
}

func (auth *Auth) ExtendGuard(key string, guard contracts.GuardDriver) {
	auth.guardDrivers[key] = guard
}

func (auth *Auth) Guard(key string, ctx contracts.Context) contracts.Guard {
	config := auth.authConfig.Guards[key]
	driver := utils.GetStringField(config, "driver")

	if guardDriver, existsDriver := auth.guardDrivers[driver]; existsDriver {
		return guardDriver(key, config, ctx, auth.UserProvider(utils.GetStringField(config, "provider")))
	}

	panic(GuardException{Err: errors.New("unsupported guard driver：" + driver)})
}

func (auth *Auth) UserProvider(key string) contracts.UserProvider {
	if userProvider, existsUserProvider := auth.userProviders[key]; existsUserProvider {
		return userProvider
	}

	config := auth.authConfig.Users[key]
	driver := utils.GetStringField(config, "driver")

	if userDriver, existsProvider := auth.userDrivers[driver]; existsProvider {
		auth.userProviders[key] = userDriver(config)
		return auth.userProviders[key]
	}

	panic(UserProviderException{Err: fmt.Errorf("unsupported user driver：%s", driver)})
}
