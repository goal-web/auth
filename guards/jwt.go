package guards

import (
	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/logs"
	"github.com/goal-web/supports/utils"
	"github.com/golang-jwt/jwt"
	"time"
)

func JwtGuard(config contracts.Fields, ctx contracts.Context, provider contracts.UserProvider) contracts.Guard {
	if guard, ok := ctx.Get("jwt_guard").(contracts.Guard); ok {
		return guard
	}
	guard := &Jwt{
		secret:     []byte(utils.GetStringField(config, "secret")),
		signMethod: config["method"].(jwt.SigningMethod),
		ctx:        ctx,
		users:      provider,
	}

	ctx.Set("jwt_guard", guard)

	return guard
}

type Jwt struct {
	secret     []byte
	isVerified bool
	signMethod jwt.SigningMethod
	ctx        contracts.Context
	users      contracts.UserProvider
	current    contracts.Authenticatable
}

type JwtAuthClaims struct {
	UserId string `json:"user_id"`
	jwt.StandardClaims
}

func (this *Jwt) parseToken() string {
	token, ok := this.ctx.Get("token").(string)
	if ok {
		return token
	}

	logs.WithField("token", this.ctx.Get("token")).Debug("jwt guard parseToken error")

	return ""
}

func (this *Jwt) Once(user contracts.Authenticatable) {
	this.current = user
	this.isVerified = true
}

func (this *Jwt) Login(user contracts.Authenticatable) interface{} {
	token, err := jwt.NewWithClaims(this.signMethod, JwtAuthClaims{
		UserId: user.GetId(),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
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

	token, err := jwt.ParseWithClaims(tokenString, &JwtAuthClaims{}, func(token *jwt.Token) (interface{}, error) {
		return this.secret, nil
	})

	if err != nil {
		logs.WithError(err).WithField("token", tokenString).Debug("jwt guard Verify err")

		return nil
	}

	if claims, ok := token.Claims.(*JwtAuthClaims); ok && token.Valid {
		return this.users.RetrieveById(claims.UserId)
	}

	logs.WithError(err).Debug("jwt guard Verify err")
	return nil
}
