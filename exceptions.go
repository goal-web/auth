package auth

import "github.com/goal-web/supports/exceptions"

type Exception struct {
	exceptions.Exception
}

type GuardException struct {
	exceptions.Exception
}

type UserProviderException struct {
	exceptions.Exception
}
