package events

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/go-logr/logr"
	httpauth "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
	"github.com/openreports/reports-api/pkg/client/clientset/versioned/fake"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func reportRequest(body string) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
		Http: &authv3.AttributeContext_HttpRequest{
			Method: "POST", Path: "/mcp?secret=hidden-query", Host: "demo.local", Id: "request-123",
			Headers: map[string]string{"authorization": "Bearer hidden-jwt", "cookie": "hidden-cookie", "x-api-key": "hidden-key"},
			Body:    body,
		},
	}}}
}

func deniedResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{HttpResponse: &authv3.CheckResponse_DeniedResponse{
		DeniedResponse: &authv3.DeniedHttpResponse{
			Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
			Body:   "Blocked by Kyverno policy bounded: replicas exceed limit",
		},
	}}
}

func TestReportMetadataAndPrivacy(t *testing.T) {
	request := reportRequest(`{"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":50,"password":"hidden-password"}},"prompt":"hidden-prompt"}`)
	subscriber := &openreportsEventSubscriber[*authv3.CheckRequest]{msgFormat: "[%s] request %s: %s"}
	report, err := subscriber.newReportResult(time.Now(), request, NewResultAccessor(deniedResponse(), nil, "bounded"))
	require.NoError(t, err)
	require.Equal(t, "bounded", report.Policy)
	require.Equal(t, "kyverno-authz", report.Source)
	require.Equal(t, "fail", string(report.Result))
	for key, value := range map[string]string{
		"policy-kind": "ValidatingPolicy", "method": "POST", "path": "/mcp",
		"host": "demo.local", "request-id": "request-123", "status": "403",
		"mcp-method": "tools/call", "tool": "kube-tools__scale_deployment",
		"namespace": "team-a-dev", "workload": "checkout", "replicas": "50",
		"reason": deniedResponse().GetDeniedResponse().GetBody(),
	} {
		require.Equal(t, value, report.Properties[key], key)
	}
	data, err := json.Marshal(report)
	require.NoError(t, err)
	for _, secret := range []string{"hidden-jwt", "hidden-cookie", "hidden-key", "hidden-password", "hidden-prompt", "hidden-query"} {
		require.NotContains(t, string(data), secret)
	}
	require.Contains(t, request.GetAttributes().GetRequest().GetHttp().GetBody(), "hidden-password")
	require.Equal(t, "Bearer hidden-jwt", request.GetAttributes().GetRequest().GetHttp().GetHeaders()["authorization"])
}

func TestReportsFilter(t *testing.T) {
	allowed := NewResultAccessor(&authv3.CheckResponse{}, nil, "allowed")
	denied := NewResultAccessor(deniedResponse(), nil, "bounded")
	errored := NewResultAccessor(nil, errors.New("evaluation failed"), "broken")
	for _, tc := range []struct {
		filter string
		want   []string
	}{
		{"fail,error", []string{"Denied", "Errored"}},
		{"fail", []string{"Denied"}},
		{"pass,fail,error,warn,skip", []string{"Allowed", "Denied", "Errored"}},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			filter, err := ParseReportsFilter(tc.filter)
			require.NoError(t, err)
			// A paused consumer makes it possible to assert filtering before buffering.
			subscriber := &openreportsEventSubscriber[*authv3.CheckRequest]{
				filter: filter, eventChan: make(chan event[*authv3.CheckRequest], 3),
			}
			for _, result := range []*resultAccessorImpl{allowed, denied, errored} {
				subscriber.Push(context.Background(), time.Now(), reportRequest("{}"), result)
			}
			var decisions []string
			for len(subscriber.eventChan) > 0 {
				ev := <-subscriber.eventChan
				decision, _ := ev.res.MustGet()
				decisions = append(decisions, decision)
			}
			require.Equal(t, tc.want, decisions)
		})
	}
	for _, value := range []string{"", "failure", "fail,", "pass;fail"} {
		_, err := ParseReportsFilter(value)
		require.Error(t, err, value)
	}
}

func TestFilteredReportsPersistCountsAndResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := fake.NewSimpleClientset()
	filter, err := ParseReportsFilter("fail,error")
	require.NoError(t, err)
	interval := time.Millisecond
	handler := NewOpenreportsSubscriber[*authv3.CheckRequest](ctx, 2, client.OpenreportsV1alpha1(), &interval, logr.Discard(), "demo-report", "demo", "%[3]s", filter)
	request := reportRequest("{}")
	for i := 0; i < 10; i++ {
		handler.Push(ctx, time.Now(), request, NewResultAccessor(&authv3.CheckResponse{}, nil))
	}
	time.Sleep(10 * time.Millisecond)
	reports, err := client.OpenreportsV1alpha1().Reports("demo").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Empty(t, reports.Items, "excluded passes must not create reports")
	for i := 0; i < 3; i++ {
		handler.Push(ctx, time.Now(), request, NewResultAccessor(deniedResponse(), nil, "bounded"))
	}
	handler.Push(ctx, time.Now(), request, NewResultAccessor(nil, errors.New("evaluation failed"), "broken"))
	require.Eventually(t, func() bool {
		report, err := client.OpenreportsV1alpha1().Reports("demo").Get(ctx, "demo-report", metav1.GetOptions{})
		return err == nil && report.Summary.Fail == 3 && report.Summary.Error == 1 && report.Summary.Pass == 0 &&
			len(report.Results) == 2 && report.Results[1].Policy == "broken"
	}, time.Second, time.Millisecond)
}

func TestRequestPropertiesOnMalformedAndModelRequests(t *testing.T) {
	for _, body := range []string{"", "{", "[]", `{"method":1}`} {
		properties := requestProperties(reportRequest(body))
		require.Equal(t, "/mcp", properties["path"])
		require.Empty(t, properties["mcp-method"])
	}
	require.Equal(t, "demo-pro", requestProperties(reportRequest(`{"model":"demo-pro","messages":[{"content":"not-reported"}]}`))["model"])
	var request *authv3.CheckRequest
	require.Empty(t, requestProperties(request))
}

func TestRequestPropertyBoundsAndRawBody(t *testing.T) {
	request := reportRequest("")
	http := request.Attributes.Request.Http
	http.RawBody = []byte(`{"method":"tools/call","params":{"name":"scale","arguments":{"namespace":"team-a","name":"checkout","replicas":5}}}`)
	require.Equal(t, "5", requestProperties(request)["replicas"])
	http.Host = strings.Repeat("x", 300)
	require.Len(t, requestProperties(request)["host"], 256)
	http.RawBody = []byte(`{"method":"ping","padding":"` + strings.Repeat("x", 16384) + `"}`)
	require.Empty(t, requestProperties(request)["mcp-method"])
}

func TestHTTPReportDoesNotSerializeCredentials(t *testing.T) {
	request := httpauth.CheckRequest{Attributes: httpauth.CheckRequestAttributes{
		Method: "POST", Path: "/api?token=hidden-query", Host: "demo.local",
		Header: map[string][]string{"Authorization": {"Bearer hidden-jwt"}},
		Body:   []byte("hidden-body"),
	}}
	for _, input := range []any{request, &request} {
		subscriber := &openreportsEventSubscriber[any]{msgFormat: "[%s] request %s: %s"}
		report, err := subscriber.newReportResult(time.Now(), input, NewResultAccessor(httpauth.CheckResponse{
			Denied: &httpauth.CheckResponseDenied{Reason: "access denied"},
		}, nil))
		require.NoError(t, err)
		require.Equal(t, "/api", report.Properties["path"])
		require.Empty(t, report.Policy)
		data, err := json.Marshal(report)
		require.NoError(t, err)
		for _, secret := range []string{"hidden-jwt", "hidden-query", "hidden-body"} {
			require.NotContains(t, string(data), secret)
		}
	}
}
