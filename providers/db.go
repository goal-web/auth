package providers

import (
	"github.com/goal-web/contracts"
)

type DB struct {
	userFactory func(string) contracts.Authenticatable
}

func DBDriver(config contracts.Fields) contracts.UserProvider {
	return &DB{
		userFactory: config["provider"].(func(string) contracts.Authenticatable),
	}
}

func (db *DB) RetrieveById(identifier string) contracts.Authenticatable {
	return db.userFactory(identifier)
}
