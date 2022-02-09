package gate

import (
	"fmt"
	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/utils"
	"reflect"
)

type Factory struct {
	abilities map[string]contracts.GateChecker

	policies map[string]contracts.Policy

	beforeHooks []contracts.GateHook
	afterHooks  []contracts.GateHook
}

func NewFactory() contracts.GateFactory {
	return &Factory{
		abilities:   map[string]contracts.GateChecker{},
		policies:    map[string]contracts.Policy{},
		beforeHooks: make([]contracts.GateHook, 0),
		afterHooks:  make([]contracts.GateHook, 0),
	}
}

func (this *Factory) Check(user contracts.Authorizable, ability string, arguments ...interface{}) bool {
	this.runBeforeHooks(user, ability, arguments...)
	defer this.runAfterHooks(user, ability, arguments...)
	checker, exists := this.get(ability, arguments...)
	if exists {
		return checker(user, arguments...)
	}
	return false
}

func (this *Factory) Has(ability string) bool {
	_, exists := this.abilities[ability]
	return exists
}

func (this *Factory) runBeforeHooks(user contracts.Authorizable, ability string, arguments ...interface{}) {
	for _, hook := range this.beforeHooks {
		hook(user, ability, arguments...)
	}
}
func (this *Factory) runAfterHooks(user contracts.Authorizable, ability string, arguments ...interface{}) {
	for _, hook := range this.afterHooks {
		hook(user, ability, arguments...)
	}
}

func (this *Factory) get(ability string, arguments ...interface{}) (contracts.GateChecker, bool) {
	checker, exists := this.abilities[ability]

	if exists {
		return checker, exists
	}

	if len(arguments) > 0 {
		classname := utils.GetTypeKey(reflect.TypeOf(arguments[0]))
		if this.policies[classname] != nil {
			checker, exists = this.policies[classname][ability]
		}
	}

	return checker, exists
}

func (this *Factory) Define(ability string, callback contracts.GateChecker) contracts.GateFactory {
	this.abilities[ability] = callback
	return this
}

func (this *Factory) Policy(class contracts.Class, policy contracts.Policy) contracts.GateFactory {
	this.policies[class.ClassName()] = policy
	return this
}

func (this *Factory) Before(callable contracts.GateHook) contracts.GateFactory {
	this.beforeHooks = append(this.beforeHooks, callable)
	return this
}

func (this *Factory) After(callable contracts.GateHook) contracts.GateFactory {
	this.afterHooks = append(this.afterHooks, callable)
	return this
}

func (this *Factory) Abilities() []string {
	var abilities []string

	for ability, _ := range this.abilities {
		abilities = append(abilities, ability)
	}

	for name, policy := range this.policies {
		for ability, _ := range policy {
			abilities = append(abilities, fmt.Sprintf("%s@%s", name, ability))
		}
	}

	return abilities
}
