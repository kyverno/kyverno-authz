package http

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/google/cel-go/common/types"
	celimpl "github.com/kyverno/kyverno-authz/pkg/cel/impl"
	mcplibs "github.com/kyverno/kyverno-authz/pkg/cel/libs/mcp"
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
	// Mcp holds the pre-parsed MCP request for zero-cost access in CEL via object.mcp.request.
	// Mcp is a value (not a pointer) so object.mcp is always safe to access.
	// Mcp.Request is always non-nil; Method is empty for non-MCP traffic.
	Mcp MCPCheckData `json:"mcp" cel:"mcp"`
}

// MCPCheckData materializes the MCP request object so policies can use
// object.mcp.request.Method and object.mcp.request.Get*Argument() without mcp.Parse().
type MCPCheckData struct {
	Request *mcplibs.MCPRequest `json:"request" cel:"request"`
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
		Mcp: MCPCheckData{Request: parseMCPRequest(bodyBytes)},
	}, nil
}

// parseMCPRequest builds an MCPRequest from raw body bytes.
// It always returns a non-nil result. For bodies that carry a JSON-RPC
// method field but have unparseable params, Method and ID are preserved
// from the envelope so that matchConditions like
// object.mcp.request.Method == 'tools/call' still evaluate correctly
// even when param parsing fails.
func parseMCPRequest(body []byte) *mcplibs.MCPRequest {
	// First pass: extract method/ID from the JSON-RPC envelope cheaply.
	var envelope struct {
		Method string `json:"method"`
	}
	hasMethod := json.Unmarshal(body, &envelope) == nil && envelope.Method != ""

	// Second pass: attempt full params parsing.
	if parsed, err := (&celimpl.MCPImpl{}).Parse(body); err == nil && parsed != nil {
		return parsed
	}

	// Full parse failed. If the body looked like JSON-RPC, preserve Method so
	// method-based matchConditions are not silently bypassed.
	req := &mcplibs.MCPRequest{}
	if hasMethod {
		req.Method = envelope.Method
	}
	return req
}
