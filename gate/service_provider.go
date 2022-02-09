package gate

import (
	"github.com/goal-web/contracts"
)

type ServiceProvider struct {
	app      contracts.Application
	Policies map[contracts.Class]contracts.Policy
}

func (this *ServiceProvider) Register(application contracts.Application) {
	this.app = application
	application.Singleton("gate.factory", func() contracts.GateFactory {
		return GetFactory()
	})
	application.Bind("gate", func(factory contracts.GateFactory, guard contracts.Guard, ctx contracts.Context) contracts.Gate {
		instance, exists := ctx.Get("access.gate").(contracts.Gate)
		if exists {
			return instance
		}
		user, _ := guard.User().(contracts.Authorizable)
		instance = NewGate(factory, user)
		ctx.Set("access.gate", instance)
		return instance
	})
}

func (this *ServiceProvider) Start() error {
	this.app.Call(func(gateFactory contracts.GateFactory) {
		for class, policy := range this.Policies {
			gateFactory.Policy(class, policy)
		}
	})
	return nil
}

func (this *ServiceProvider) Stop() {
}
