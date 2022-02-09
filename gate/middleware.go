package gate

import "github.com/goal-web/contracts"

func Authorize(ability string, arguments ...interface{}) interface{} {
	return func(request contracts.HttpRequest, next contracts.Pipe, gate contracts.Gate) interface{} {
		gate.Authorize(ability, arguments...)
		return next(request)
	}
}
