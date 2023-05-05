package providers

import (
	"github.com/goal-web/contracts"
	"github.com/goal-web/database/table"
	"github.com/goal-web/supports/utils"
)

type DB struct {
	class contracts.Class[contracts.Authenticatable]
	table string
	id    string
}

func DBDriver(config contracts.Fields) contracts.UserProvider {
	return &DB{
		class: config["class"].(contracts.Class[contracts.Authenticatable]),
		table: utils.ToString(config["table"], "users"),
		id:    utils.ToString(config["id"], "id"),
	}
}

func (db *DB) RetrieveById(identifier string) contracts.Authenticatable {
	if user := table.Auth(db.class, db.table, db.id).Find(identifier); user != nil {
		return *user
	}
	return nil
}
