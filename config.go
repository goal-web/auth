package auth

import "github.com/goal-web/contracts"

type Config struct {
	Defaults struct {
		Guard string
		User  string
	}
	Guards map[string]contracts.Fields
	Users  map[string]contracts.Fields
}
