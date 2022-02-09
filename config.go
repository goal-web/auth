package auth

import "github.com/goal-web/contracts"

type Defaults struct {
	Guard string
	User  string
}

type Config struct {
	Defaults Defaults
	Guards   map[string]contracts.Fields
	Users    map[string]contracts.Fields
}
