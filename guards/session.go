package guards

import (
	"github.com/goal-web/contracts"
)

func SessionGuard(config contracts.Fields, ctx contracts.Context, provider contracts.UserProvider) contracts.Guard {
	if guard, ok := ctx.Get("jwt_guard").(contracts.Guard); ok {
		return guard
	}
	guard := &Session{
		session:    ctx.Get("session").(contracts.Session),
		ctx:        ctx,
		users:      provider,
		sessionKey: config["session_key"].(string),
	}

	ctx.Set("jwt_guard", guard)

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

func (this *Session) Once(user contracts.Authenticatable) {
	this.current = user
	this.isVerified = true
}

func (this *Session) Login(user contracts.Authenticatable) interface{} {
	this.session.Put(this.sessionKey, user.GetId())

	this.Once(user)

	return true
}

func (this *Session) User() contracts.Authenticatable {
	if !this.isVerified {
		this.isVerified = true
		if userId := this.session.Get(this.sessionKey, ""); userId != "" {
			this.current = this.users.RetrieveById(userId)
		}
	}

	return this.current
}

func (this *Session) GetId() (id string) {
	if user := this.User(); user != nil {
		id = user.GetId()
	}
	return
}

func (this *Session) Check() bool {
	return this.User() != nil
}

func (this *Session) Guest() bool {
	return this.User() == nil
}
