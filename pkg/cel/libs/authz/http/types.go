package http

import (
	"io"
	"net/http"

	"github.com/google/cel-go/common/types"
)

var (
	RequestType           = types.NewObjectType("http.CheckRequest")
	RequestAttributesType = types.NewObjectType("http.CheckRequestAttributes")
	ResponseType          = types.NewObjectType("http.CheckResponse")
	ResponseOkType        = types.NewObjectType("http.CheckResponseOk")
	ResponseDeniedType    = types.NewObjectType("http.CheckResponseDenied")
)

type (
	header = map[string][]string
	query  = map[string][]string
)

type CheckRequest struct {
	Attributes CheckRequestAttributes `json:"attributes" cel:"attributes"`
}

type CheckRequestAttributes struct {
	Method        string `json:"method"        cel:"method"`
	Header        header `json:"header"        cel:"header"`
	Host          string `json:"host"          cel:"host"`
	Protocol      string `json:"protocol"      cel:"protocol"`
	ContentLength int64  `json:"contentLength" cel:"contentLength"`
	Body          []byte `json:"body"          cel:"body"`
	Scheme        string `json:"scheme"        cel:"scheme"`
	Path          string `json:"path"          cel:"path"`
	Query         query  `json:"query"         cel:"query"`
	Fragment      string `json:"fragment"      cel:"fragment"`
}

type CheckResponse struct {
	Ok     *CheckResponseOk     `json:"ok,omitempty"     cel:"ok"`
	Denied *CheckResponseDenied `json:"denied,omitempty" cel:"denied"`
}

type CheckResponseOk struct{}

type CheckResponseDenied struct {
	Reason string `cel:"reason"`
}

func NewRequest(r *http.Request) (CheckRequest, error) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return CheckRequest{}, err
	}
	return CheckRequest{
		Attributes: CheckRequestAttributes{
			Method:        r.Method,
			Header:        r.Header,
			Path:          r.URL.Path,
			Host:          r.Host,
			Protocol:      r.Proto,
			Body:          bodyBytes,
			Query:         r.URL.Query(),
			ContentLength: int64(len(bodyBytes)),
			Fragment:      r.URL.Fragment,
			Scheme:        r.URL.Scheme,
		},
	}, nil
}
