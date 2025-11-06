package auth

import (
	"sync"

	"github.com/goal-web/application"
	"github.com/goal-web/contracts"
)

var singleton contracts.Auth
var once sync.Once

func Default() contracts.Auth {
	once.Do(func() {
		singleton = application.Get("auth").(contracts.Auth)
	})

	return singleton
}

func ExtendUserProvider(name string, provider contracts.UserProviderDriver) {
	Default().ExtendUserProvider(name, provider)
}

func ExtendGuard(name string, guard contracts.GuardDriver) {
	Default().ExtendGuard(name, guard)
}

func GetGuard(name string, ctx contracts.Context) contracts.Guard {
	return Default().Guard(name, ctx)
}

func UserProvider(name string) contracts.UserProvider {
	return Default().UserProvider(name)
}
