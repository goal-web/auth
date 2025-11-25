// Package guards contains authentication guard implementations.
// 包 guards 包含认证守卫的实现。
package guards

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/logs"
	"github.com/goal-web/supports/utils"
	"github.com/golang-jwt/jwt"
)

const (
	// BlacklistRedisKey is the Redis key pattern for JWT blacklist.
	// BlacklistRedisKey 是 JWT 黑名单的 Redis 键模式。
	BlacklistRedisKey = "auth:blacklist:%s"
)

// JwtGuard creates a JWT-based authentication guard.
// JwtGuard 创建基于 JWT 的认证守卫。
func JwtGuard(name string, config contracts.Fields, ctx contracts.Context, provider contracts.UserProvider) *Jwt {
	if guard, ok := ctx.Get("guard:" + name).(*Jwt); ok {
		return guard
	}
	guard := &Jwt{
		secret:     []byte(utils.GetStringField(config, "secret")),
		signMethod: config["method"].(jwt.SigningMethod),
		ctx:        ctx,
		name:       name,
		users:      provider,
		lifetime:   time.Duration(utils.GetIntField(config, "lifetime", 60*60*24*int(time.Second))),
	}

	ctx.Set("guard:"+name, guard)

	return guard
}

// Jwt implements a JWT-based authentication guard.
// Jwt 实现基于 JWT 的认证守卫。
type Jwt struct {
	secret     []byte                          // secret holds the JWT signing secret.
	                                           // secret 保存 JWT 签名密钥。
	isVerified bool                          // isVerified indicates if the authentication status has been checked.
	                                           // isVerified 指示认证状态是否已检查。
	lifetime   time.Duration                 // lifetime specifies the JWT token lifetime.
	                                           // lifetime 指定 JWT 令牌生存时间。
	signMethod jwt.SigningMethod             // signMethod specifies the JWT signing method.
	                                           // signMethod 指定 JWT 签名方法。
	ctx        contracts.Context             // ctx provides request context.
	                                           // ctx 提供请求上下文。
	users      contracts.UserProvider        // users provides user retrieval.
	                                           // users 提供用户获取。
	current    contracts.Authenticatable     // current holds the currently authenticated user.
	                                           // current 保存当前认证的用户。
	redis      contracts.RedisConnection     // redis provides Redis connection for token blacklisting.
	                                           // redis 提供用于令牌黑名单的 Redis 连接。
	err        error                         // err holds any authentication errors.
	                                           // err 保存任何认证错误。
	token      string                        // token holds the current JWT token.
	                                           // token 保存当前 JWT 令牌。
	name       string                        // name holds the guard name.
	                                           // name 保存守卫名称。
}

// SetRedis sets the Redis connection for token blacklisting.
// SetRedis 设置用于令牌黑名单的 Redis 连接。
func (jwf *Jwt) SetRedis(redis contracts.RedisConnection) {
	jwf.redis = redis
}

// SetToken sets the JWT token to be used for authentication.
// SetToken 设置用于认证的 JWT 令牌。
func (jwf *Jwt) SetToken(token string) {
	jwf.token = token
}

// JwtAuthClaims represents the claims in a JWT token for authentication.
// JwtAuthClaims 表示用于认证的 JWT 令牌中的声明。
type JwtAuthClaims struct {
	UserId string `json:"user_id"`          // UserId holds the authenticated user ID.
	                                        // UserId 保存认证用户 ID。
	Guard  string `json:"guard"`            // Guard holds the guard name.
	                                        // Guard 保存守卫名称。
	jwt.StandardClaims                       // StandardClaims holds standard JWT claims.
	                                        // StandardClaims 保存标准 JWT 声明。
}

// parseToken extracts the JWT token from various sources.
// parseToken 从各种来源提取 JWT 令牌。
func (jwf *Jwt) parseToken() string {
	if jwf.token != "" {
		return jwf.token
	}

	var token, ok = jwf.ctx.Get("token").(string)
	if ok && token != "" {
		return token
	}

	if request, isHttpRequest := jwf.ctx.(contracts.HttpRequest); isHttpRequest {
		if token = request.QueryParam("token"); token != "" {
			return token
		} else if token = request.GetHeader("Authorization"); strings.Contains(token, "Bearer ") {
			return strings.ReplaceAll(token, "Bearer ", "")
		} else if token = request.GetHeader("token"); token != "" {
			return token
		} else if token = request.FormValue("token"); token != "" {
			return token
		}
	}

	logs.WithField("token", jwf.ctx.Get("token")).Debug("jwt guard parseToken error")

	return ""
}

// Once authenticates the user without storing in session.
// Once 认证用户但不存储在会话中。
func (jwf *Jwt) Once(user contracts.Authenticatable) {
	jwf.current = user
	jwf.isVerified = true
}

// Logout logs the user out by blacklisting the JWT token.
// Logout 通过将 JWT 令牌列入黑名单来注销用户。
func (jwf *Jwt) Logout() error {
	if jwf.redis == nil {
		return errors.New("redis dependencies are missing")
	}

	if jwf.Check() {
		_, err := jwf.redis.Set(fmt.Sprintf(BlacklistRedisKey, jwf.parseToken()), "1", jwf.lifetime)
		return err
	}

	return nil
}

// Error returns any authentication errors.
// Error 返回任何认证错误。
func (jwf *Jwt) Error() error {
	return jwf.err
}

// Login authenticates the user and generates a JWT token.
// Login 认证用户并生成 JWT 令牌。
func (jwf *Jwt) Login(user contracts.Authenticatable) any {
	token, err := jwt.NewWithClaims(jwf.signMethod, JwtAuthClaims{
		UserId: user.GetAuthenticatableKey(),
		Guard:  jwf.name,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(jwf.lifetime).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "goal",
		},
	}).SignedString(jwf.secret)

	if err != nil {
		panic(err)
	}

	jwf.Once(user)

	return token
}

// User returns the currently authenticated user.
// User 返回当前认证的用户。
func (jwf *Jwt) User() contracts.Authenticatable {
	if !jwf.isVerified {
		jwf.current = jwf.Verify(jwf.parseToken())
		jwf.isVerified = true
	}

	return jwf.current
}

// GetAuthenticatableKey returns the key of the authenticated user.
// GetAuthenticatableKey 返回认证用户的键。
func (jwf *Jwt) GetAuthenticatableKey() (id string) {
	if user := jwf.User(); user != nil {
		id = user.GetAuthenticatableKey()
	}
	return
}

// Check verifies if a user is authenticated.
// Check 验证用户是否已认证。
func (jwf *Jwt) Check() bool {
	return jwf.User() != nil
}

// Guest verifies if the user is a guest (not authenticated).
// Guest 验证用户是否为访客（未认证）。
func (jwf *Jwt) Guest() bool {
	return jwf.User() == nil
}

// Verify validates a JWT token and returns the authenticated user.
// Verify 验证 JWT 令牌并返回认证用户。
func (jwf *Jwt) Verify(tokenString string) contracts.Authenticatable {
	if jwf.redis != nil {
		exists, _ := jwf.redis.Exists(fmt.Sprintf(BlacklistRedisKey, jwf.parseToken()))

		if exists > 0 {
			jwf.err = errors.New("token has been blacklisted")
			return nil
		}
	}

	token, err := jwt.ParseWithClaims(tokenString, &JwtAuthClaims{}, func(token *jwt.Token) (any, error) {
		return jwf.secret, nil
	})

	if err != nil {
		jwf.err = err
		logs.WithError(err).WithField("token", tokenString).Debug("jwt guard Verify err")

		return nil
	}

	if claims, ok := token.Claims.(*JwtAuthClaims); ok && token.Valid {
		if claims.Guard != jwf.name {
			jwf.err = errors.New("guard mismatch")
			return nil
		}

		user := jwf.users.RetrieveById(claims.UserId)
		if user == nil {
			jwf.err = errors.New("user does not exist")
		}

		return user
	}

	jwf.err = errors.New("jwt guard Verify err")
	return nil
}
