package gate

import (
	"github.com/goal-web/contracts"
)

// todo
type ServiceProvider struct {
	app contracts.Application
	//Policies map[contracts.Class]contracts.Policy
}

func (provider *ServiceProvider) Register(application contracts.Application) {
	provider.app = application
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

func (provider *ServiceProvider) Start() error {
	provider.app.Call(func(gateFactory contracts.GateFactory) {
		//for class, policy := range provider.Policies {
		//	gateFactory.Policy(class, policy)
		//}
	})
	return nil
}

func (provider *ServiceProvider) Stop() {
}
