package events

import (
	"encoding/json"
	"strconv"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	httpauth "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
)

// Reports use an allowlist, not a copy of headers or the request body.
func requestProperties(request any) map[string]string {
	properties := map[string]string{}
	switch r := request.(type) {
	case *authv3.CheckRequest:
		http := r.GetAttributes().GetRequest().GetHttp()
		properties["method"] = http.GetMethod()
		properties["path"], _, _ = strings.Cut(http.GetPath(), "?")
		properties["host"] = http.GetHost()
		properties["request-id"] = http.GetId()
		properties["scheme"] = http.GetScheme()
		properties["protocol"] = http.GetProtocol()
		properties["source-ip"] = r.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress()
		body := http.GetBody()
		if body == "" {
			body = string(http.GetRawBody())
		}
		addBodyProperties(properties, body)
	case httpauth.CheckRequest:
		properties["method"] = r.Attributes.Method
		properties["path"], _, _ = strings.Cut(r.Attributes.Path, "?")
		properties["host"] = r.Attributes.Host
	case *httpauth.CheckRequest:
		if r != nil {
			return requestProperties(*r)
		}
	}
	for key, value := range properties {
		if value == "" {
			delete(properties, key)
		} else if len(value) > 256 {
			properties[key] = value[:256]
		}
	}
	return properties
}

func addBodyProperties(properties map[string]string, body string) {
	if len(body) > 16384 {
		return
	}
	var rpc struct {
		Method string `json:"method"`
		Model  string `json:"model"`
		Params struct {
			Name      string `json:"name"`
			Arguments struct {
				Namespace string      `json:"namespace"`
				Name      string      `json:"name"`
				Replicas  json.Number `json:"replicas"`
			} `json:"arguments"`
		} `json:"params"`
	}
	if json.Unmarshal([]byte(body), &rpc) != nil {
		return
	}
	properties["mcp-method"] = rpc.Method
	properties["model"] = rpc.Model
	if rpc.Method == "tools/call" {
		properties["tool"] = rpc.Params.Name
		properties["namespace"] = rpc.Params.Arguments.Namespace
		properties["workload"] = rpc.Params.Arguments.Name
		if value, err := strconv.ParseFloat(string(rpc.Params.Arguments.Replicas), 64); err == nil {
			properties["replicas"] = strconv.FormatFloat(value, 'g', -1, 64)
		}
	}
}
