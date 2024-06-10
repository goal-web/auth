package auth

import (
	"fmt"
	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/exceptions"
	"github.com/goal-web/supports/utils"
	"sync"
)

type Auth struct {
	authConfig Config

	mutex         sync.Mutex
	guardDrivers  map[string]contracts.GuardDriver
	userProviders map[string]contracts.UserProvider
	userDrivers   map[string]contracts.UserProviderDriver
}

func (auth *Auth) ExtendUserProvider(key string, provider contracts.UserProviderDriver) {
	auth.mutex.Lock()
	defer auth.mutex.Unlock()
	auth.userDrivers[key] = provider
}

func (auth *Auth) ExtendGuard(key string, guard contracts.GuardDriver) {
	auth.mutex.Lock()
	defer auth.mutex.Unlock()
	auth.guardDrivers[key] = guard
}

func (auth *Auth) Guard(key string, ctx contracts.Context) contracts.Guard {
	auth.mutex.Lock()
	defer auth.mutex.Unlock()
	config := auth.authConfig.Guards[key]
	driver := utils.GetStringField(config, "driver")

	if guardDriver, existsDriver := auth.guardDrivers[driver]; existsDriver {
		return guardDriver(key, config, ctx, auth.UserProvider(utils.GetStringField(config, "provider")))
	}

	panic(GuardException{exceptions.New("unsupported guard driver：" + driver)})
}

func (auth *Auth) UserProvider(key string) contracts.UserProvider {
	auth.mutex.Lock()
	defer auth.mutex.Unlock()
	if userProvider, existsUserProvider := auth.userProviders[key]; existsUserProvider {
		return userProvider
	}

	config := auth.authConfig.Users[key]
	driver := utils.GetStringField(config, "driver")

	if userDriver, existsProvider := auth.userDrivers[driver]; existsProvider {
		auth.userProviders[key] = userDriver(config)
		return auth.userProviders[key]
	}

	panic(UserProviderException{exceptions.WithError(fmt.Errorf("unsupported user driver：%s", driver))})
}
