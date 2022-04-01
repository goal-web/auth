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
		lifetime:   time.Duration(utils.GetIntField(config, "lifetime", 60*60*24)),
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

func (this *Jwt) SetRedis(redis contracts.RedisConnection) {
	this.redis = redis
}

func (this *Jwt) SetToken(token string) {
	this.token = token
}

type JwtAuthClaims struct {
	UserId string `json:"user_id"`
	Guard  string `json:"guard"`
	jwt.StandardClaims
}

func (this *Jwt) parseToken() string {
	if this.token != "" {
		return this.token
	}

	var token, ok = this.ctx.Get("token").(string)
	if ok && token != "" {
		return token
	}

	if request, isHttpRequest := this.ctx.(contracts.HttpRequest); isHttpRequest {
		if token = request.QueryParam("token"); token != "" {
			return token
		} else if token = request.Request().Header.Get("Authorization"); strings.Contains(token, "Bearer ") {
			return strings.ReplaceAll(token, "Bearer ", "")
		} else if token = request.Request().Header.Get("token"); token != "" {
			return token
		} else if token = request.FormValue("token"); token != "" {
			return token
		}
	}

	logs.WithField("token", this.ctx.Get("token")).Debug("jwt guard parseToken error")

	return ""
}

func (this *Jwt) Once(user contracts.Authenticatable) {
	this.current = user
	this.isVerified = true
}

func (this *Jwt) Logout() error {
	if this.redis == nil {
		return errors.New("redis dependencies are missing")
	}

	if this.Check() {
		_, err := this.redis.Set(fmt.Sprintf(BlacklistRedisKey, this.parseToken()), "1", this.lifetime)
		return err
	}

	return nil
}

func (this *Jwt) Error() error {
	return this.err
}

func (this *Jwt) Login(user contracts.Authenticatable) interface{} {
	token, err := jwt.NewWithClaims(this.signMethod, JwtAuthClaims{
		UserId: user.GetId(),
		Guard:  this.name,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(this.lifetime * time.Second).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    "goal",
		},
	}).SignedString(this.secret)

	if err != nil {
		panic(err)
	}

	this.Once(user)

	return token
}

func (this *Jwt) User() contracts.Authenticatable {
	if !this.isVerified {
		this.current = this.Verify(this.parseToken())
		this.isVerified = true
	}

	return this.current
}

func (this *Jwt) GetId() (id string) {
	if user := this.User(); user != nil {
		id = user.GetId()
	}
	return
}

func (this *Jwt) Check() bool {
	return this.User() != nil
}

func (this *Jwt) Guest() bool {
	return this.User() == nil
}

func (this *Jwt) Verify(tokenString string) contracts.Authenticatable {
	if this.redis != nil {
		exists, _ := this.redis.Exists(fmt.Sprintf(BlacklistRedisKey, this.parseToken()))

		if exists > 0 {
			this.err = errors.New("token has been blacklisted")
			return nil
		}
	}

	token, err := jwt.ParseWithClaims(tokenString, &JwtAuthClaims{}, func(token *jwt.Token) (interface{}, error) {
		return this.secret, nil
	})

	if err != nil {
		this.err = err
		logs.WithError(err).WithField("token", tokenString).Debug("jwt guard Verify err")

		return nil
	}

	if claims, ok := token.Claims.(*JwtAuthClaims); ok && token.Valid {
		if claims.Guard != this.name {
			this.err = errors.New("guard mismatch")
			return nil
		}

		user := this.users.RetrieveById(claims.UserId)
		if user == nil {
			this.err = errors.New("user does not exist")
		}

		return user
	}

	this.err = errors.New("jwt guard Verify err")
	return nil
}
