package auth

import (
	"github.com/goal-web/contracts"
)

type GuardException struct {
	contracts.Exception

	Ctx contracts.Context
}

type UserProviderException struct {
	contracts.Exception
}
