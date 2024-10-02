package guards

import (
	"errors"
	"fmt"
	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/logs"
	"github.com/goal-web/supports/utils"
	"github.com/golang-jwt/jwt"
	"strings"
	"time"
)

const (
	BlacklistRedisKey = "auth:blacklist:%s"
)

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

type Jwt struct {
	secret     []byte
	isVerified bool
	lifetime   time.Duration
	signMethod jwt.SigningMethod
	ctx        contracts.Context
	users      contracts.UserProvider
	current    contracts.Authenticatable
	redis      contracts.RedisConnection
	err        error
	token      string
	name       string
}

func (jwf *Jwt) SetRedis(redis contracts.RedisConnection) {
	jwf.redis = redis
}

func (jwf *Jwt) SetToken(token string) {
	jwf.token = token
}

type JwtAuthClaims struct {
	UserId string `json:"user_id"`
	Guard  string `json:"guard"`
	jwt.StandardClaims
}

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

func (jwf *Jwt) Once(user contracts.Authenticatable) {
	jwf.current = user
	jwf.isVerified = true
}

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

func (jwf *Jwt) Error() error {
	return jwf.err
}

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

func (jwf *Jwt) User() contracts.Authenticatable {
	if !jwf.isVerified {
		jwf.current = jwf.Verify(jwf.parseToken())
		jwf.isVerified = true
	}

	return jwf.current
}

func (jwf *Jwt) GetAuthenticatableKey() (id string) {
	if user := jwf.User(); user != nil {
		id = user.GetAuthenticatableKey()
	}
	return
}

func (jwf *Jwt) Check() bool {
	return jwf.User() != nil
}

func (jwf *Jwt) Guest() bool {
	return jwf.User() == nil
}

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
