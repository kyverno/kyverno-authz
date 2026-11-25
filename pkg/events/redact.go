package events

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	httpauth "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
)

// maxPropertyLength bounds the length, in bytes, of every recorded property value.
const maxPropertyLength = 256

// DefaultReportHeaders lists the request headers that decision records include by default.
var DefaultReportHeaders = []string{"user-agent", "x-request-id"}

// forbiddenReportHeaders carry credentials. Decision records never include them,
// even when they are configured.
var forbiddenReportHeaders = map[string]bool{
	"authorization":        true,
	"proxy-authorization":  true,
	"cookie":               true,
	"set-cookie":           true,
	"x-api-key":            true,
	"x-auth-token":         true,
	"x-amz-security-token": true,
	"x-csrf-token":         true,
	"x-xsrf-token":         true,
}

// RequestRedactor builds the request properties that decision records (stdout
// decision logs, Kubernetes Events, and OpenReports results) include. It uses an
// allow-list: it never records the body, query string, fragment, metadata
// context, context extensions, or any header that isn't allowed.
type RequestRedactor struct {
	headers map[string]bool
}

// NewRequestRedactor returns a RequestRedactor that records the given header
// names. It returns an error when a header carries credentials.
func NewRequestRedactor(headers []string) (*RequestRedactor, error) {
	r := &RequestRedactor{headers: map[string]bool{}}
	for _, header := range headers {
		header = strings.ToLower(strings.TrimSpace(header))
		if header == "" {
			continue
		}
		if forbiddenReportHeaders[header] {
			return nil, fmt.Errorf("header %q carries credentials and can't be recorded in decision records", header)
		}
		r.headers[header] = true
	}
	return r, nil
}

// Properties returns the allow-listed properties of an authorization request.
// A nil RequestRedactor records no headers.
func (r *RequestRedactor) Properties(request any) map[string]string {
	properties := map[string]string{}
	switch req := request.(type) {
	case *authv3.CheckRequest:
		attributes := req.GetAttributes()
		http := attributes.GetRequest().GetHttp()
		properties["method"] = http.GetMethod()
		properties["scheme"] = http.GetScheme()
		properties["host"] = http.GetHost()
		properties["path"] = stripQuery(http.GetPath())
		properties["protocol"] = http.GetProtocol()
		properties["request-id"] = http.GetId()
		properties["source-principal"] = attributes.GetSource().GetPrincipal()
		properties["source-address"] = peerAddress(attributes.GetSource())
		properties["destination-principal"] = attributes.GetDestination().GetPrincipal()
		properties["destination-address"] = peerAddress(attributes.GetDestination())
		for name, value := range http.GetHeaders() {
			r.addHeader(properties, name, value)
		}
		for _, header := range http.GetHeaderMap().GetHeaders() {
			value := header.GetValue()
			if value == "" {
				value = string(header.GetRawValue())
			}
			r.addHeader(properties, header.GetKey(), value)
		}
	case httpauth.CheckRequest:
		properties["method"] = req.Attributes.Method
		properties["scheme"] = req.Attributes.Scheme
		properties["host"] = req.Attributes.Host
		properties["path"] = stripQuery(req.Attributes.Path)
		properties["protocol"] = req.Attributes.Protocol
		for name, values := range req.Attributes.Header {
			r.addHeader(properties, name, strings.Join(values, ","))
		}
	case *httpauth.CheckRequest:
		if req != nil {
			return r.Properties(*req)
		}
	}
	for key, value := range properties {
		if value == "" {
			delete(properties, key)
		} else {
			properties[key] = truncate(value)
		}
	}
	return properties
}

// JSON returns the allow-listed properties of an authorization request as a JSON object.
func (r *RequestRedactor) JSON(request any) string {
	// marshalling a map of strings can't fail, and the keys are sorted
	out, _ := json.Marshal(r.Properties(request))
	return string(out)
}

func (r *RequestRedactor) addHeader(properties map[string]string, name, value string) {
	name = strings.ToLower(name)
	if r == nil || !r.headers[name] || forbiddenReportHeaders[name] {
		return
	}
	key := "header." + name
	if existing, ok := properties[key]; ok && existing != "" {
		value = existing + "," + value
	}
	properties[key] = value
}

func peerAddress(peer *authv3.AttributeContext_Peer) string {
	socket := peer.GetAddress().GetSocketAddress()
	if socket.GetAddress() == "" || socket.GetPortValue() == 0 {
		return socket.GetAddress()
	}
	return net.JoinHostPort(socket.GetAddress(), strconv.FormatUint(uint64(socket.GetPortValue()), 10))
}

func stripQuery(path string) string {
	path, _, _ = strings.Cut(path, "?")
	path, _, _ = strings.Cut(path, "#")
	return path
}

func truncate(value string) string {
	if len(value) <= maxPropertyLength {
		return value
	}
	value = value[:maxPropertyLength]
	// don't cut a multi-byte character in half
	for i := 0; i < utf8.UTFMax && !utf8.ValidString(value); i++ {
		value = value[:len(value)-1]
	}
	return value
}
