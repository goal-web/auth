package auth

import (
	"github.com/goal-web/contracts"
	"github.com/goal-web/pipeline"
	"github.com/goal-web/supports/exceptions"
)

func Guard(guards ...string) interface{} {
	return func(request contracts.HttpRequest, next pipeline.Pipe, auth contracts.Auth) interface{} {

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
