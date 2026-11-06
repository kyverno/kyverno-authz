package extproc

import "github.com/google/cel-go/common/types"

var (
	InputType    = types.NewObjectType("extproc.Input")
	RequestType  = types.NewObjectType("extproc.Request")
	ResponseType = types.NewObjectType("extproc.Response")
	ResultType   = types.NewObjectType("extproc.Result")
)

type Input struct {
	Phase    string   `json:"phase" cel:"phase"`
	Request  Request  `json:"request" cel:"request"`
	Response Response `json:"response" cel:"response"`
}

type Request struct {
	Method  string            `json:"method" cel:"method"`
	Path    string            `json:"path" cel:"path"`
	Headers map[string]string `json:"headers" cel:"headers"`
	Body    string            `json:"body" cel:"body"`
}

type Response struct {
	Status  int64             `json:"status" cel:"status"`
	Headers map[string]string `json:"headers" cel:"headers"`
	Body    string            `json:"body" cel:"body"`
	Events  []SSEEvent        `json:"events" cel:"events"`
}

type SSEEvent struct {
	Event string `json:"event" cel:"event"`
	ID    string `json:"id" cel:"id"`
	Data  string `json:"data" cel:"data"`
}

type HeaderMutation struct {
	Name   string `json:"name" cel:"name"`
	Value  string `json:"value" cel:"value"`
	Remove bool   `json:"remove" cel:"remove"`
}

type Result struct {
	Action      string           `json:"action" cel:"action"`
	Status      int64            `json:"status" cel:"status"`
	Body        string           `json:"body" cel:"body"`
	ReplaceBody bool             `json:"replaceBody" cel:"replaceBody"`
	Headers     []HeaderMutation `json:"headers" cel:"headers"`
}
