package gate

import (
	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/exceptions"
)

type Gate struct {
	factory contracts.GateFactory
	user    contracts.Authorizable
}

func NewGate(factory contracts.GateFactory, user contracts.Authorizable) contracts.Gate {
	return &Gate{
		factory: factory,
		user:    user,
	}
}

func (gate *Gate) Allows(ability string, arguments ...interface{}) bool {
	return gate.factory.Check(gate.user, ability, arguments...)
}

func (gate *Gate) Denies(ability string, arguments ...interface{}) bool {
	return !gate.factory.Check(gate.user, ability, arguments...)
}

func (gate *Gate) Check(abilities []string, arguments ...interface{}) bool {
	for _, ability := range abilities {
		if !gate.factory.Check(gate.user, ability, arguments...) {
			return false
		}
	}
	return true
}

func (gate *Gate) Any(abilities []string, arguments ...interface{}) bool {
	for _, ability := range abilities {
		if gate.factory.Check(gate.user, ability, arguments...) {
			return true
		}
	}
	return false
}

func (gate *Gate) Authorize(ability string, arguments ...interface{}) {
	if gate.Denies(ability, arguments...) {
		panic(Exception{
			Exception: exceptions.New("no operating authority", nil),
			User:      gate.user,
			Ability:   ability,
			Arguments: arguments,
		})
	}
}

func (gate *Gate) Inspect(ability string, arguments ...interface{}) contracts.HttpResponse {
	if gate.Allows(ability, arguments...) {
		return &Response{
			Allowed: true,
			Message: "ok",
			Code:    1,
		}
	}
	return &Response{
		Allowed: false,
		Message: "no operating authority",
		Code:    0,
	}
}

func (gate *Gate) ForUser(user contracts.Authorizable) contracts.Gate {
	gate.user = user
	return gate
}
