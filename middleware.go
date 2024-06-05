package auth

import (
	"github.com/goal-web/contracts"
	"github.com/goal-web/database/table"
	"github.com/goal-web/supports/exceptions"
	"reflect"
)

func Guard[T contracts.Authenticatable](query *table.Table[T], guards ...string) any {
	return func(request contracts.HttpRequest, next contracts.Pipe, auth contracts.Auth, config contracts.Config) any {

		if len(guards) == 0 {
			guards = append(guards, config.Get("auth").(Config).Defaults.Guard)
		}

		for _, guard := range guards {
			user := auth.Guard(guard, request).User()
			value := reflect.ValueOf(user)
			if user == nil {
				panic(Exception{exceptions.New("auth.middleware: " + guard + " guard authentication failed")})
			}
			model := value.Elem().FieldByName("Model")
			if model.CanSet() {
				model.Set(reflect.ValueOf(table.Model[T]{
					Table:           query.GetTable(),
					PrimaryKeyField: query.GetPrimayKeyField(),
					Value:           value,
					Class:           query.GetClass(),
				}))
				value.Elem().FieldByName("Model").FieldByName("Data").Set(value)
			}

		}

		return next(request)
	}
}
