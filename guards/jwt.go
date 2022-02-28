package guards

import (
	"github.com/goal-web/contracts"
	"github.com/goal-web/supports/logs"
	"github.com/goal-web/supports/utils"
	"github.com/golang-jwt/jwt"
	"strings"
	"time"
)

func JwtGuard(name string, config contracts.Fields, ctx contracts.Context, provider contracts.UserProvider) contracts.Guard {
	if guard, ok := ctx.Get("guard:" + name).(contracts.Guard); ok {
		return guard
	}
	guard := &Jwt{
		secret:     []byte(utils.GetStringField(config, "secret")),
		signMethod: config["method"].(jwt.SigningMethod),
		ctx:        ctx,
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
}

type JwtAuthClaims struct {
	UserId string `json:"user_id"`
	jwt.StandardClaims
}

func (this *Jwt) parseToken() string {
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

func (this *Jwt) Login(user contracts.Authenticatable) interface{} {
	token, err := jwt.NewWithClaims(this.signMethod, JwtAuthClaims{
		UserId: user.GetId(),
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
