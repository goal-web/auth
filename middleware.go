package auth

import (
	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/exceptions"
)

func Guard(guards ...string) interface{} {
	return func(request contracts.HttpRequest, next contracts.Pipe, auth contracts.Auth, config contracts.Config) interface{} {

		if len(guards) == 0 {
			guards = append(guards, config.Get("auth").(Config).Defaults.Guard)
		}

		for _, guard := range guards {
			if auth.Guard(guard, request).Guest() {
				panic(Exception{
					Exception: exceptions.New(guard+" guard authentication failed", contracts.Fields{
						"guards": guards,
					}),
				})
			}
		}

		return next(request)
	}
}
