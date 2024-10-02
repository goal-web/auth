package guards

import (
	"github.com/goal-web/contracts"
)

func SessionGuard(name string, config contracts.Fields, ctx contracts.Context, provider contracts.UserProvider) contracts.Guard {
	if guard, ok := ctx.Get("guard:" + name).(contracts.Guard); ok {
		return guard
	}
	guard := &Session{
		session:    ctx.Get("session").(contracts.Session),
		ctx:        ctx,
		users:      provider,
		sessionKey: config["session_key"].(string),
	}

	ctx.Set("guard:"+name, guard)

	return guard
}

type Session struct {
	sessionKey string
	isVerified bool
	session    contracts.Session
	ctx        contracts.Context
	users      contracts.UserProvider
	current    contracts.Authenticatable
}

func (session *Session) Logout() error {
	session.session.Remove(session.sessionKey)
	session.current = nil
	return nil
}

func (session *Session) Error() error {
	return nil
}

func (session *Session) Once(user contracts.Authenticatable) {
	session.current = user
	session.isVerified = true
}

func (session *Session) Login(user contracts.Authenticatable) any {
	session.session.Put(session.sessionKey, user.GetAuthenticatableKey())

	session.Once(user)

	return true
}

func (session *Session) User() contracts.Authenticatable {
	if !session.isVerified {
		session.isVerified = true
		if userId := session.session.Get(session.sessionKey, ""); userId != "" {
			session.current = session.users.RetrieveById(userId)
		}
	}

	return session.current
}

func (session *Session) GetAuthenticatableKey() (id string) {
	if user := session.User(); user != nil {
		id = user.GetAuthenticatableKey()
	}
	return
}

func (session *Session) Check() bool {
	return session.User() != nil
}

func (session *Session) Guest() bool {
	return session.User() == nil
}
