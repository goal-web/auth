# Goal-web/auth
[goal-web/auth](https://github.com/goal-web/auth)  
goal 框架的用户认证组件，你可以在 `http`、`websocket` 或者其他环境使用，有上下文即可。

## 安装 - install
```bash
go get github.com/goal-web/auth
```

## 使用 - usage
goal 的脚手架自带了绝大多数开发一个 web 应用的所需要的功能和组件，当然这也包括了认证组件。一般情况下，我们只需要在 .env 修改自己的认证配置即可，比如 `jwt` 驱动的 secret、`session` 驱动的 session_key。

### 配置 - config
默认情况下，`config/auth.go` 配置文件像下面那样，默认添加了 `jwt`、`session` 两个守卫配置

```go
package config

import (
	"github.com/goal-web/auth"
	"github.com/goal-web/contracts"
	"github.com/goal-web/example/models"
	"github.com/golang-jwt/jwt"
)

func init() {
	configs["auth"] = func(env contracts.Env) any {
		return auth.Config{
			Defaults: struct {
				Guard string
				User  string
			}{
				Guard: env.StringOptional("auth.default", "jwt"), // 默认守卫
				User:  env.StringOptional("auth.user", "db"), // 默认用户提供者
			},
			Guards: map[string]contracts.Fields{
				"jwt": { // 守卫名称
					"driver":   "jwt", // 驱动,目前支持jwt、session
					"secret":   env.GetString("auth.jwt.secret"), // jwt 签名所需的 secret，不同的守卫建议不同的secret
					"method":   jwt.SigningMethodHS256, // jwt 签名方法
					"lifetime": 60 * 60 * 24, // token有效时长，单位：秒
					"provider": "db", // 用户提供者名
				},
				"session": { // 守卫名称
					"driver":      "session", // 驱动名
					"provider":    "db", // 用户提供者名
					// session驱动所需的参数，如果应用需要配置多个session驱动的守卫，那么需要配置不一样的 session_key
					"session_key": env.StringOptional("auth.session.key", "auth_session"), 
				},
			},
			Users: map[string]contracts.Fields{ // 用户提供者，目前只支持 db
				"db": { // 用户提供者名称
					"driver": "db", // 驱动名称
					"model":  models.UserModel, // 用户模型
				},
			},
		}
	}
}
```

`.env` 的数据库相关配置

```bash
auth.jwt.secret=jwt_secret
auth.default=jwt
```

### 定义模型 - define a model
`app/models/user.go` 文件

```go
package models

import (
	"github.com/goal-web/database/table"
	"github.com/goal-web/supports/class"
)

var (
	UserModel = table.NewModel(class.Make(new(User)), "users")
)

func UserQuery() *table.Table {
	return table.FromModel(UserModel)
}

type User struct {
	Id       string `json:"id"`
	NickName string `json:"name"`
}

// GetId 实现了 contracts.Authenticatable 接口，此方法必不可少
func (u User) GetId() string {
	return u.Id
}
```

### 用法 - method of use
```go
package controllers

import (
	"github.com/goal-web/contracts"
	"github.com/goal-web/example/models"
)

func LoginExample(guard contracts.Guard) contracts.Fields {
	//  这是伪代码
	user := models.UserQuery().First().(models.User)

	return contracts.Fields{
		"token": guard.Login(user), // jwt 返回 token，session 返回 true
	}
}

func GetCurrentUser(guard contracts.Guard) any {
	return contracts.Fields{
		"user": guard.User(), // 已登录返回用户模型，否则返回 nil
	}
}
```

### 使用中间件
```go
package routes

import (
	"github.com/goal-web/auth"
	"github.com/goal-web/contracts"
	"github.com/goal-web/example/app/http/controllers"
	"github.com/goal-web/session"
)

func ApiRoutes(router contracts.Router) {
    
    v1 := router.Group("", session.StartSession)
    
    // 直接应用在路由上
    v1.Get("/myself", controllers.GetCurrentUser, auth.Guard("jwt"))
    
    // 应用在路由组上
    authRouter := v1.Group("", auth.Guard("jwt"))
    authRouter.Get("/myself", controllers.GetCurrentUser, auth.Guard("jwt"))

}
```

### 守卫API - guard api
```go
type Guard interface {
	Once(user Authenticatable)
	User() Authenticatable
	GetId() string
	Check() bool
	Guest() bool
	Login(user Authenticatable) any
}
```

### 扩展守卫和用户提供者 - extension
这部分内容比较多，这里暂时不展开讲，后面会专门录视频介绍，欢迎大家点赞订阅


### 在 goal 之外的框架使用 - use in frameworks other than goal
这部分内容比较多，这里暂时不展开讲，后面会专门录视频介绍，欢迎大家点赞订阅


[goal-web](https://github.com/goal-web/goal)  
[goal-web/auth](https://github.com/goal-web/auth)  
qbhy0715@qq.com
