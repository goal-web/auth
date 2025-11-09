// Package providers contains authentication user provider implementations.
// 包 providers 包含认证用户提供者的实现。
package providers

import (
	"github.com/goal-web/contracts"
)

// DB implements a database-based user provider.
// DB 实现基于数据库的用户提供者。
type DB struct {
	userFactory func(string) contracts.Authenticatable // userFactory creates user instances by identifier.
	                                                     // userFactory 通过标识符创建用户实例。
}

// DBDriver creates a new database-based user provider driver.
// DBDriver 创建新的基于数据库的用户提供者驱动。
func DBDriver(config contracts.Fields) contracts.UserProvider {
	return &DB{
		userFactory: config["provider"].(func(string) contracts.Authenticatable),
	}
}

// RetrieveById retrieves a user by their identifier.
// RetrieveById 根据标识符获取用户。
func (db *DB) RetrieveById(identifier string) contracts.Authenticatable {
	return db.userFactory(identifier)
}
