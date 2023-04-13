package auth

import (
	"errors"
	"github.com/goal-web/contracts"
)

func Guard(guards ...string) any {
	return func(request contracts.HttpRequest, next contracts.Pipe, auth contracts.Auth, config contracts.Config) any {

		if len(guards) == 0 {
			guards = append(guards, config.Get("auth").(Config).Defaults.Guard)
		}

		for _, guard := range guards {
			if auth.Guard(guard, request).Guest() {
				panic(Exception{Err: errors.New(guard + " guard authentication failed")})
			}
		}

		return next(request)
	}
}
