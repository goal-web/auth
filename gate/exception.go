package gate

import "github.com/goal-web/contracts"

type Exception struct {
	contracts.Exception

	User      contracts.Authorizable
	Ability   string
	Arguments []any
}
