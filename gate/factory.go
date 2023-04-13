package gate

import (
	"fmt"
	"github.com/goal-web/contracts"
)

type Factory struct {
	abilities map[string]contracts.GateChecker

	policies map[string]contracts.Policy

	beforeHooks []contracts.GateHook
	afterHooks  []contracts.GateHook
}

var factory *Factory

func Check(user contracts.Authorizable, ability string, arguments ...any) bool {
	return factory.Check(user, ability, arguments...)
}

func GetFactory() contracts.GateFactory {
	if factory == nil {
		factory = &Factory{
			abilities:   map[string]contracts.GateChecker{},
			policies:    map[string]contracts.Policy{},
			beforeHooks: make([]contracts.GateHook, 0),
			afterHooks:  make([]contracts.GateHook, 0),
		}
	}
	return factory
}

func (factory *Factory) Check(user contracts.Authorizable, ability string, arguments ...any) bool {
	factory.runBeforeHooks(user, ability, arguments...)
	defer factory.runAfterHooks(user, ability, arguments...)

	checker, exists := factory.get(ability, arguments...)

	if exists {
		return checker(user, arguments...)
	}
	return false
}

func (factory *Factory) Has(ability string) bool {
	_, exists := factory.abilities[ability]
	return exists
}

func (factory *Factory) runBeforeHooks(user contracts.Authorizable, ability string, arguments ...any) {
	for _, hook := range factory.beforeHooks {
		hook(user, ability, arguments...)
	}
}
func (factory *Factory) runAfterHooks(user contracts.Authorizable, ability string, arguments ...any) {
	for _, hook := range factory.afterHooks {
		hook(user, ability, arguments...)
	}
}

func (factory *Factory) get(ability string, arguments ...any) (contracts.GateChecker, bool) {
	checker, exists := factory.abilities[ability]

	if exists {
		return checker, exists
	}

	// todo
	//if len(arguments) > 0 {
	//	var classname string
	//	if class, isClass := arguments[0].(contracts.Class); isClass {
	//		classname = class.ClassName()
	//	} else if model, isModel := arguments[0].(contracts.Model); isModel {
	//		classname = model.GetClass().ClassName()
	//	} else {
	//		classname = utils.GetTypeKey(reflect.TypeOf(arguments[0]))
	//	}
	//	if factory.policies[classname] != nil {
	//		checker, exists = factory.policies[classname][ability]
	//	}
	//}

	return checker, exists
}

func (factory *Factory) Define(ability string, callback contracts.GateChecker) contracts.GateFactory {
	factory.abilities[ability] = callback
	return factory
}

func (factory *Factory) Policy(class contracts.Class[contracts.Authenticatable], policy contracts.Policy) contracts.GateFactory {
	factory.policies[class.ClassName()] = policy
	return factory
}

func (factory *Factory) Before(callable contracts.GateHook) contracts.GateFactory {
	factory.beforeHooks = append(factory.beforeHooks, callable)
	return factory
}

func (factory *Factory) After(callable contracts.GateHook) contracts.GateFactory {
	factory.afterHooks = append(factory.afterHooks, callable)
	return factory
}

func (factory *Factory) Abilities() []string {
	var abilities []string

	for ability, _ := range factory.abilities {
		abilities = append(abilities, ability)
	}

	for name, policy := range factory.policies {
		for ability, _ := range policy {
			abilities = append(abilities, fmt.Sprintf("%s@%s", name, ability))
		}
	}

	return abilities
}
