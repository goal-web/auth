package gate

import (
	"net/http"
)

type Response struct {
	Allowed bool   `json:"allowed"`
	Message string `json:"message"`
	Code    any    `json:"code"`
}

func (response *Response) Headers() http.Header {
	//TODO implement me
	panic("implement me")
}

func (response *Response) Bytes() []byte {
	//TODO implement me
	panic("implement me")
}

func (response *Response) Status() int {
	if response.Allowed {
		return http.StatusOK
	}

	return http.StatusUnauthorized
}
