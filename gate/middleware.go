package gate

import "github.com/goal-web/contracts"

func Authorize(ability string, arguments ...any) any {
	return func(request contracts.HttpRequest, next contracts.Pipe, gate contracts.Gate) any {
		gate.Authorize(ability, arguments...)
		return next(request)
	}
}
