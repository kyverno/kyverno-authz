package events

import (
	"encoding/json"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	httpauth "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
	"google.golang.org/protobuf/proto"
)

const redacted = "[REDACTED]"

func sensitiveHeader(name string) bool {
	name = strings.ToLower(name)
	switch name {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key":
		return true
	}
	return strings.Contains(name, "token") || strings.Contains(name, "secret")
}

// marshalRequest keeps credentials and request bodies out of event descriptions.
// Clone before redacting: the request is also used for policy evaluation and metrics.
func marshalRequest(request any) ([]byte, error) {
	switch r := request.(type) {
	case *authv3.CheckRequest:
		if r == nil {
			return json.Marshal(nil)
		}
		clone := proto.Clone(r).(*authv3.CheckRequest)
		http := clone.GetAttributes().GetRequest().GetHttp()
		if http != nil {
			for name := range http.Headers {
				if sensitiveHeader(name) {
					http.Headers[name] = redacted
				}
			}
			for _, header := range http.GetHeaderMap().GetHeaders() {
				if sensitiveHeader(header.GetKey()) {
					header.Value = redacted
					header.RawValue = nil
				}
			}
			http.Body = ""
			http.RawBody = nil
		}
		return json.Marshal(clone)
	case httpauth.CheckRequest:
		return marshalHTTPRequest(r)
	case *httpauth.CheckRequest:
		if r == nil {
			return json.Marshal(nil)
		}
		return marshalHTTPRequest(*r)
	default:
		return json.Marshal(request)
	}
}

func marshalHTTPRequest(r httpauth.CheckRequest) ([]byte, error) {
	headers := make(map[string][]string, len(r.Attributes.Header))
	for name, values := range r.Attributes.Header {
		if sensitiveHeader(name) {
			headers[name] = []string{redacted}
		} else {
			headers[name] = append([]string(nil), values...)
		}
	}
	r.Attributes.Header = headers
	r.Attributes.Body = nil
	// MCP data is parsed from the body and can contain the same sensitive payload.
	data, err := json.Marshal(r.Attributes)
	if err != nil {
		return nil, err
	}
	var attributes map[string]json.RawMessage
	if err := json.Unmarshal(data, &attributes); err != nil {
		return nil, err
	}
	delete(attributes, "body")
	return json.Marshal(map[string]any{"attributes": attributes})
}

func requestProperties(request any) map[string]string {
	switch r := request.(type) {
	case *authv3.CheckRequest:
		http := r.GetAttributes().GetRequest().GetHttp()
		return map[string]string{"method": http.GetMethod(), "path": http.GetPath(), "host": http.GetHost()}
	case httpauth.CheckRequest:
		return map[string]string{"method": r.Attributes.Method, "path": r.Attributes.Path, "host": r.Attributes.Host}
	case *httpauth.CheckRequest:
		if r != nil {
			return requestProperties(*r)
		}
	}
	return map[string]string{}
}
