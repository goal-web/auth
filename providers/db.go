package providers

import (
	"github.com/goal-web/contracts"
)

type DB struct {
	model contracts.Query[contracts.Authenticatable]
}

func DBDriver(config contracts.Fields) contracts.UserProvider {
	return &DB{model: config["model"].(contracts.Query[contracts.Authenticatable])}
}

func (db *DB) RetrieveById(identifier string) contracts.Authenticatable {
	if user := db.model.Find(identifier); user != nil {
		return *user
	}
	return nil
}
