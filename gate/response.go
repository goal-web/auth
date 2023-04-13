package gate

import (
	"github.com/goal-web/contracts"
	"net/http"
)

type Response struct {
	Allowed bool   `json:"allowed"`
	Message string `json:"message"`
	Code    any    `json:"code"`
}

func (this *Response) Status() int {
	if this.Allowed {
		return http.StatusOK
	}

	return http.StatusUnauthorized
}

func (this *Response) Response(ctx contracts.HttpContext) error {
	return ctx.JSON(this.Status(), this)
}
