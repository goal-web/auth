// Package guards contains authentication guard implementations.
// 包 guards 包含认证守卫的实现。
package guards

import (
	"github.com/goal-web/contracts"
)

// SessionGuard creates a session-based authentication guard.
// SessionGuard 创建基于会话的认证守卫。
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

// Session implements a session-based authentication guard.
// Session 实现基于会话的认证守卫。
type Session struct {
	sessionKey string                           // sessionKey holds the key for the session storage.
	                                            // sessionKey 保存会话存储的键。
	isVerified bool                           // isVerified indicates if the authentication status has been checked.
	                                            // isVerified 指示认证状态是否已检查。
	session    contracts.Session              // session provides session storage.
	                                            // session 提供会话存储。
	ctx        contracts.Context              // ctx provides request context.
	                                            // ctx 提供请求上下文。
	users      contracts.UserProvider         // users provides user retrieval.
	                                            // users 提供用户获取。
	current    contracts.Authenticatable      // current holds the currently authenticated user.
	                                            // current 保存当前认证的用户。
}

// Logout logs the user out of the session.
// Logout 从会话中注销用户。
func (session *Session) Logout() error {
	session.session.Remove(session.sessionKey)
	session.current = nil
	return nil
}

// Error returns any authentication errors.
// Error 返回任何认证错误。
func (session *Session) Error() error {
	return nil
}

// Once authenticates the user without storing in session.
// Once 认证用户但不存储在会话中。
func (session *Session) Once(user contracts.Authenticatable) {
	session.current = user
	session.isVerified = true
}

// Login authenticates the user and stores in session.
// Login 认证用户并存储在会话中。
func (session *Session) Login(user contracts.Authenticatable) any {
	session.session.Put(session.sessionKey, user.GetAuthenticatableKey())

	session.Once(user)

	return true
}

// User returns the currently authenticated user.
// User 返回当前认证的用户。
func (session *Session) User() contracts.Authenticatable {
	if !session.isVerified {
		session.isVerified = true
		if userId := session.session.Get(session.sessionKey, ""); userId != "" {
			session.current = session.users.RetrieveById(userId)
		}
	}

	return session.current
}

// GetAuthenticatableKey returns the key of the authenticated user.
// GetAuthenticatableKey 返回认证用户的键。
func (session *Session) GetAuthenticatableKey() (id string) {
	if user := session.User(); user != nil {
		id = user.GetAuthenticatableKey()
	}
	return
}

// Check verifies if a user is authenticated.
// Check 验证用户是否已认证。
func (session *Session) Check() bool {
	return session.User() != nil
}

// Guest verifies if the user is a guest (not authenticated).
// Guest 验证用户是否为访客（未认证）。
func (session *Session) Guest() bool {
	return session.User() == nil
}
