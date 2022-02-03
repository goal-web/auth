package providers

import (
	"github.com/goal-web/contracts"
	"github.com/goal-web/database/table"
)

type DB struct {
	model contracts.Model
}

func DBDriver(config contracts.Fields) contracts.UserProvider {
	return &DB{model: config["model"].(contracts.Model)}
}

func (db *DB) RetrieveById(identifier string) contracts.Authenticatable {
	if user := table.FromModel(db.model).Where(db.model.GetPrimaryKey(), identifier).First(); user != nil {
		return user.(contracts.Authenticatable)
	}
	return nil
}
