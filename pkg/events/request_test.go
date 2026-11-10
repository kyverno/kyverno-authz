package events

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/go-logr/logr"
	httpauth "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const jwt = "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.signature"

func envoyRequest() *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
		Method: "POST", Path: "/tools/call", Host: "tools.internal", Size: 42,
		Headers:   map[string]string{"Authorization": jwt, "x-request-id": "request-123"},
		HeaderMap: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{{Key: "AUTHORIZATION", RawValue: []byte(jwt)}, {Key: "x-request-id", Value: "request-123"}}},
		Body:      "private request body", RawBody: []byte("private raw body"),
	}}}}
}

func TestMarshalRequestRedactsCredentialsAndBodies(t *testing.T) {
	names := []string{"Authorization", "PROXY-AUTHORIZATION", "Cookie", "Set-Cookie", "X-Api-Key", "API-KEY", "x-access-ToKeN", "X-Client-SeCrEt"}
	envoy := envoyRequest()
	for _, name := range names {
		envoy.Attributes.Request.Http.Headers[name] = jwt
		envoy.Attributes.Request.Http.HeaderMap.Headers = append(envoy.Attributes.Request.Http.HeaderMap.Headers, &corev3.HeaderValue{Key: name, Value: jwt}, &corev3.HeaderValue{Key: name, RawValue: []byte(jwt)})
	}
	original := proto.Clone(envoy)
	data, err := marshalRequest(envoy)
	require.NoError(t, err)
	assert.NotContains(t, string(data), jwt)
	assert.NotContains(t, string(data), "eyJ")
	assert.NotContains(t, string(data), "body")
	assert.Contains(t, string(data), redacted)
	assert.Contains(t, string(data), "request-123")
	assert.True(t, proto.Equal(original, envoy), "original protobuf was mutated")

	http := httpauth.CheckRequest{Attributes: httpauth.CheckRequestAttributes{
		Method: "POST", Path: "/tools/call", Host: "tools.internal", ContentLength: 42,
		Header: map[string][]string{"X-Request-Id": {"request-123"}}, Body: []byte("private HTTP body"),
	}}
	for _, name := range names {
		http.Attributes.Header[name] = []string{jwt, "another credential"}
	}
	before, err := json.Marshal(http)
	require.NoError(t, err)
	for _, req := range []any{http, &http} {
		data, err := marshalRequest(req)
		require.NoError(t, err)
		assert.NotContains(t, string(data), jwt)
		assert.NotContains(t, string(data), "another credential")
		assert.NotContains(t, string(data), "body")
		assert.NotContains(t, string(data), "mcp")
		assert.Contains(t, string(data), "request-123")
		assert.Contains(t, string(data), `"contentLength":42`)
		var result struct {
			Attributes struct {
				Header map[string][]string `json:"header"`
			} `json:"attributes"`
		}
		require.NoError(t, json.Unmarshal(data, &result))
		for _, name := range names {
			assert.Equal(t, []string{redacted}, result.Attributes.Header[name])
		}
	}
	after, err := json.Marshal(http)
	require.NoError(t, err)
	assert.JSONEq(t, string(before), string(after))
}

func TestReportResultAttribution(t *testing.T) {
	subscriber := &openreportsEventSubscriber[*authv3.CheckRequest]{msgFormat: "[%s] envoy: request %s, response: %s\n"}
	response := &authv3.CheckResponse{HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
		Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden}, Body: "Tool access denied",
	}}}
	result, err := subscriber.newReportResult(time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC), envoyRequest(), NewResultAccessor(response, nil, "tool-guardrails"))
	require.NoError(t, err)
	assert.Equal(t, "tool-guardrails", result.Policy)
	assert.Equal(t, "kyverno-authz", result.Source)
	assert.Equal(t, "fail", string(result.Result))
	assert.Empty(t, result.Rule)
	assert.Equal(t, map[string]string{"status": "403", "reason": "Tool access denied", "method": "POST", "path": "/tools/call", "host": "tools.internal"}, result.Properties)
	assert.NotContains(t, result.Description, jwt)
	assert.NotContains(t, result.Description, "private")
	assert.Contains(t, result.Description, "[REDACTED]")
	assert.Contains(t, result.Description, "Denied")
}

func TestHTTPReportResult(t *testing.T) {
	subscriber := &openreportsEventSubscriber[httpauth.CheckRequest]{msgFormat: "[%s] http: request %s, response: %s"}
	req := httpauth.CheckRequest{Attributes: httpauth.CheckRequestAttributes{Method: "GET", Path: "/admin", Host: "api.internal", Header: map[string][]string{"Authorization": {jwt}}, Body: []byte("private HTTP body")}}
	result, err := subscriber.newReportResult(time.Now(), req, NewResultAccessor(httpauth.CheckResponse{Denied: &httpauth.CheckResponseDenied{Reason: "Admin access required"}}, nil, "admin-only").WithHTTPStatus(403))
	require.NoError(t, err)
	assert.Equal(t, "admin-only", result.Policy)
	assert.Equal(t, "fail", string(result.Result))
	assert.Equal(t, "Admin access required", result.Properties["reason"])
	assert.Equal(t, "403", result.Properties["status"])
	assert.Equal(t, "GET", result.Properties["method"])
	assert.NotContains(t, result.Description, jwt)
	assert.NotContains(t, result.Description, "body")
}

func TestKubernetesEventRedaction(t *testing.T) {
	for _, req := range []any{envoyRequest(), httpauth.CheckRequest{Attributes: httpauth.CheckRequestAttributes{Header: map[string][]string{"Authorization": {jwt}}, Body: []byte("private HTTP body")}}} {
		t.Run("request", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := fake.NewClientset()
			subscriber := NewK8sEventSubscriber[any](ctx, client, "default", logr.Discard(), "[%s] request %s, response: %s")
			subscriber.Push(ctx, time.Now(), req, NewResultAccessor(&authv3.CheckResponse{}, nil))
			require.Eventually(t, func() bool {
				events, err := client.CoreV1().Events("default").List(ctx, metav1.ListOptions{})
				return err == nil && len(events.Items) == 1
			}, time.Second, 10*time.Millisecond)
			events, err := client.CoreV1().Events("default").List(ctx, metav1.ListOptions{})
			require.NoError(t, err)
			assert.NotContains(t, events.Items[0].Message, jwt)
			assert.NotContains(t, events.Items[0].Message, "body")
			assert.Contains(t, events.Items[0].Message, redacted)
		})
	}
}

func TestWriterEventRedaction(t *testing.T) {
	var output bytes.Buffer
	subscriber := NewWriterEventSubscriber[*authv3.CheckRequest](&output, logr.Discard(), "[%s] request %s, response: %s")
	subscriber.Push(context.Background(), time.Now(), envoyRequest(), NewResultAccessor(&authv3.CheckResponse{}, nil))
	assert.NotContains(t, output.String(), jwt)
	assert.NotContains(t, output.String(), "body")
	assert.Contains(t, output.String(), redacted)
}
