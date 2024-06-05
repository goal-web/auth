package auth

import (
	"github.com/goal-web/contracts"
)

type Exception struct {
	contracts.Exception
}

type GuardException struct {
	contracts.Exception
}

type UserProviderException struct {
	contracts.Exception
}
