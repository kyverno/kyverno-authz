package events

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/go-logr/logr"
	httpauth "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
	mcplibs "github.com/kyverno/kyverno-authz/pkg/cel/libs/mcp"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// secrets lists values that must never appear in a decision record.
var secrets = []string{
	"secret-bearer-token",
	"secret-proxy-credential",
	"secret-session-cookie",
	"secret-api-key",
	"secret-query-token",
	"secret-fragment",
	"secret-body",
	"secret-jwt-claim",
	"secret-context-extension",
	"secret-mcp-argument",
	"secret-unlisted-header",
}

func secretHeaders() map[string]string {
	return map[string]string{
		"authorization":       "Bearer secret-bearer-token",
		"proxy-authorization": "Basic secret-proxy-credential",
		"cookie":              "session=secret-session-cookie",
		"x-api-key":           "secret-api-key",
		"x-internal-secret":   "secret-unlisted-header",
		"user-agent":          "curl/8.0",
		"x-request-id":        "request-1",
	}
}

func secretEnvoyRequest() *authv3.CheckRequest {
	claims, err := structpb.NewStruct(map[string]any{"sub": "secret-jwt-claim"})
	if err != nil {
		panic(err)
	}
	headerMap := &corev3.HeaderMap{}
	for key, value := range secretHeaders() {
		headerMap.Headers = append(headerMap.Headers, &corev3.HeaderValue{Key: key, RawValue: []byte(value)})
	}
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		Source: &authv3.AttributeContext_Peer{
			Principal: "spiffe://cluster.local/ns/default/sa/client",
			Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{
				Address: "10.0.0.1", PortSpecifier: &corev3.SocketAddress_PortValue{PortValue: 51234},
			}}},
		},
		Destination: &authv3.AttributeContext_Peer{Principal: "spiffe://cluster.local/ns/default/sa/server"},
		Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
			Id:        "request-1",
			Method:    "POST",
			Scheme:    "https",
			Host:      "api.example.com",
			Path:      "/v1/items?token=secret-query-token#secret-fragment",
			Query:     "token=secret-query-token",
			Fragment:  "secret-fragment",
			Protocol:  "HTTP/1.1",
			Headers:   secretHeaders(),
			HeaderMap: headerMap,
			Body:      `{"password":"secret-body"}`,
			RawBody:   []byte(`{"password":"secret-body"}`),
		}},
		MetadataContext:   &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{"envoy.filters.http.jwt_authn": claims}},
		ContextExtensions: map[string]string{"tenant": "secret-context-extension"},
	}}
}

func secretHTTPRequest() httpauth.CheckRequest {
	header := map[string][]string{}
	for key, value := range secretHeaders() {
		header[key] = []string{value}
	}
	return httpauth.CheckRequest{
		Attributes: httpauth.CheckRequestAttributes{
			Method:   "POST",
			Scheme:   "https",
			Host:     "api.example.com",
			Path:     "/v1/items?token=secret-query-token",
			Protocol: "HTTP/1.1",
			Header:   header,
			Query:    map[string][]string{"token": {"secret-query-token"}},
			Fragment: "secret-fragment",
			Body:     []byte(`{"password":"secret-body"}`),
		},
		Mcp: httpauth.MCPCheckData{Request: &mcplibs.MCPRequest{
			Method:   "tools/call",
			ToolCall: &mcp.CallToolParams{Name: "scale", Arguments: map[string]any{"token": "secret-mcp-argument"}},
		}},
	}
}

func requireNoSecrets(t *testing.T, sink, output string) {
	t.Helper()
	require.NotEmpty(t, output, sink)
	for _, secret := range secrets {
		require.NotContains(t, output, secret, sink)
	}
	require.Contains(t, output, "/v1/items", sink)
	require.Contains(t, output, "curl/8.0", sink)
}

// sinkOutputs pushes a request through every sink and returns what each one records.
func sinkOutputs[Req any](t *testing.T, req Req, redactor *RequestRedactor) map[string]string {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const format = "[%s] request %s, response: %s\n"
	result := NewResultAccessor(deniedResponse(), nil, "policy")
	outputs := map[string]string{}

	var stdout bytes.Buffer
	NewWriterEventSubscriber[Req](&stdout, logr.Discard(), format, redactor).Push(ctx, time.Now(), req, result)
	outputs["stdout"] = stdout.String()

	client := k8sfake.NewSimpleClientset()
	NewK8sEventSubscriber[Req](ctx, client, "default", logr.Discard(), format, redactor).Push(ctx, time.Now(), req, result)
	require.Eventually(t, func() bool {
		list, err := client.CoreV1().Events("default").List(ctx, metav1.ListOptions{})
		if err != nil || len(list.Items) != 1 {
			return false
		}
		outputs["k8s-event"] = list.Items[0].Message
		return true
	}, time.Second, time.Millisecond)

	reports := &openreportsEventSubscriber[Req]{msgFormat: format, redactor: redactor}
	report, err := reports.newReportResult(time.Now(), req, result)
	require.NoError(t, err)
	outputs["openreports"] = report.Description
	return outputs
}

func TestSinksRedactEnvoyRequests(t *testing.T) {
	redactor, err := NewRequestRedactor(DefaultReportHeaders)
	require.NoError(t, err)
	for sink, output := range sinkOutputs(t, secretEnvoyRequest(), redactor) {
		requireNoSecrets(t, sink, output)
		require.Contains(t, output, "10.0.0.1:51234", sink)
		require.Contains(t, output, "spiffe://cluster.local/ns/default/sa/client", sink)
	}
}

func TestSinksRedactHTTPRequests(t *testing.T) {
	redactor, err := NewRequestRedactor(DefaultReportHeaders)
	require.NoError(t, err)
	for sink, output := range sinkOutputs(t, secretHTTPRequest(), redactor) {
		requireNoSecrets(t, sink, output)
	}
	req := secretHTTPRequest()
	for sink, output := range sinkOutputs(t, &req, redactor) {
		requireNoSecrets(t, sink, output)
	}
}

func TestRequestRedactorProperties(t *testing.T) {
	redactor, err := NewRequestRedactor([]string{" User-Agent ", "X-Request-Id", ""})
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"method":                "POST",
		"scheme":                "https",
		"host":                  "api.example.com",
		"path":                  "/v1/items",
		"protocol":              "HTTP/1.1",
		"request-id":            "request-1",
		"source-principal":      "spiffe://cluster.local/ns/default/sa/client",
		"source-address":        "10.0.0.1:51234",
		"destination-principal": "spiffe://cluster.local/ns/default/sa/server",
		"header.user-agent":     "curl/8.0,curl/8.0",
		"header.x-request-id":   "request-1,request-1",
	}, redactor.Properties(secretEnvoyRequest()))

	// a nil redactor records no headers
	var none *RequestRedactor
	require.NotContains(t, none.JSON(secretHTTPRequest()), "header.")
	require.Equal(t, "{}", none.JSON("unknown request type"))
}

func TestRequestRedactorRejectsCredentialHeaders(t *testing.T) {
	for _, header := range []string{"authorization", "Cookie", "proxy-authorization", "X-API-Key", "set-cookie"} {
		_, err := NewRequestRedactor([]string{"user-agent", header})
		require.Error(t, err, header)
	}
}

func TestRequestRedactorBoundsValues(t *testing.T) {
	redactor, err := NewRequestRedactor([]string{"user-agent"})
	require.NoError(t, err)
	req := secretHTTPRequest()
	req.Attributes.Path = "/" + strings.Repeat("é", maxPropertyLength)
	req.Attributes.Header["user-agent"] = []string{strings.Repeat("a", 10*maxPropertyLength)}
	properties := redactor.Properties(req)
	for key, value := range properties {
		require.LessOrEqual(t, len(value), maxPropertyLength, key)
		require.True(t, utf8.ValidString(value), key)
	}
}
