package auth

import (
	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/exceptions"
)

func Guard(guards ...string) any {
	return func(request contracts.HttpRequest, next contracts.Pipe, auth contracts.Auth, config contracts.Config) any {
		if len(guards) == 0 {
			guards = append(guards, config.Get("auth").(Config).Defaults.Guard)
		}

		for _, guard := range guards {
			user := auth.Guard(guard, request).User()
			if user == nil {
				panic(GuardException{
					Exception: exceptions.New("auth.middleware: " + guard + " guard authentication failed"),
					Ctx:       request,
				})
			}
		}

		return next(request)
	}
}

func Middleware(request contracts.HttpRequest, next contracts.Pipe, auth contracts.Auth, config contracts.Config, guards ...string) any {
	if len(guards) == 0 {
		guards = append(guards, config.Get("auth").(Config).Defaults.Guard)
	}

	for _, guard := range guards {
		if auth.Guard(guard, request).Guest() {
			panic(GuardException{
				Exception: exceptions.New("auth.middleware: " + guard + " guard authentication failed"),
				Ctx:       request,
			})
		}
	}

	return next(request)
}

func GuestMiddleware(request contracts.HttpRequest, next contracts.Pipe, auth contracts.Auth, config contracts.Config, guards ...string) any {
	if len(guards) == 0 {
		guards = append(guards, config.Get("auth").(Config).Defaults.Guard)
	}

	for _, guard := range guards {
		if !auth.Guard(guard, request).Guest() {
			panic(GuardException{
				Exception: exceptions.New("auth.middleware: " + guard + " guard authentication failed"),
				Ctx:       request,
			})
		}
	}

	return next(request)
}
