package extproc

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	vpol "github.com/kyverno/api/api/policies.kyverno.io/v1"
	celproc "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/extproc"
	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/kyverno-authz/pkg/engine/compiler"
	enginesources "github.com/kyverno/kyverno-authz/pkg/engine/sources"
	"google.golang.org/grpc/metadata"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

type fixedSource struct{ policies []engine.ProcessorPolicy }

func (s fixedSource) Load(context.Context) ([]engine.ProcessorPolicy, error) { return s.policies, nil }

type fakeStream struct {
	ctx       context.Context
	requests  []*extprocv3.ProcessingRequest
	responses []*extprocv3.ProcessingResponse
	index     int
}

func (s *fakeStream) Send(response *extprocv3.ProcessingResponse) error {
	s.responses = append(s.responses, response)
	return nil
}
func (s *fakeStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if s.index == len(s.requests) {
		return nil, io.EOF
	}
	request := s.requests[s.index]
	s.index++
	return request, nil
}
func (s *fakeStream) SetHeader(metadata.MD) error  { return nil }
func (s *fakeStream) SendHeader(metadata.MD) error { return nil }
func (s *fakeStream) SetTrailer(metadata.MD)       {}
func (s *fakeStream) Context() context.Context     { return s.ctx }
func (s *fakeStream) SendMsg(any) error            { return nil }
func (s *fakeStream) RecvMsg(any) error            { return io.EOF }

func TestProcessFiltersToolsListAndResponds(t *testing.T) {
	loadedPolicies, _, err := enginesources.LoadPolicies(os.DirFS("testdata"))
	if err != nil {
		t.Fatal(err)
	}
	if len(loadedPolicies) != 1 || loadedPolicies[0].Spec.EvaluationMode() != "EnvoyProcessor" {
		t.Fatalf("file policy loader did not accept EnvoyProcessor mode: %#v", loadedPolicies)
	}
	policyDef := loadedPolicies[0]
	compiled, errs := compiler.NewCompiler[dynamic.Interface, celproc.Input, *celproc.Result](nil).Compile(policyDef, nil)
	if err := errs.ToAggregate(); err != nil {
		t.Fatalf("compile example policy: %v", err)
	}
	processor := newService(fixedSource{policies: []engine.ProcessorPolicy{compiled}}, nil, false)
	body := "event: message\nid: 5ba9-test\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"ttlMs\":0,\"cacheScope\":\"public\",\"tools\":[{\"name\":\"runbooks__get_runbook\"},{\"name\":\"kube-tools__scale_deployment\"}]}}\n\n\n"
	stream := &fakeStream{ctx: context.Background(), requests: []*extprocv3.ProcessingRequest{
		requestHeaders(map[string]string{":method": "POST", ":path": "/mcp", "x-user": "alice"}, false),
		requestBody([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`), true),
		responseHeaders(map[string]string{":status": "200", "content-type": "text/event-stream", "transfer-encoding": "chunked"}, false),
		responseBody([]byte(body), true),
	}}
	if err := processor.Process(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 4 {
		t.Fatalf("got %d responses", len(stream.responses))
	}
	mutation := stream.responses[3].GetResponseBody().GetResponse()
	if mutation.GetBodyMutation() == nil {
		t.Fatal("expected response body replacement")
	}
	filtered := string(mutation.GetBodyMutation().GetBody())
	if !strings.HasPrefix(filtered, "event: message\nid: 5ba9-test\ndata: ") || !strings.HasSuffix(filtered, "\n\n") {
		t.Fatalf("SSE event was not framed preserving its event/id: %q", filtered)
	}
	if strings.Contains(filtered, "kube-tools__scale_deployment") || !strings.Contains(filtered, "runbooks__get_runbook") || !strings.Contains(filtered, `"id":2`) || !strings.Contains(filtered, `"cacheScope":"public"`) {
		t.Fatalf("unexpected filtered SSE tools or JSON-RPC metadata: %s", filtered)
	}
	if got := mutation.GetHeaderMutation().GetSetHeaders(); len(got) != 0 {
		t.Fatalf("SSE replacement unexpectedly set headers: %#v", got)
	}

	jsonPolicyYAML := []byte(`apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: json-body-replacement
spec:
  evaluation:
    mode: EnvoyProcessor
  failurePolicy: Fail
  validations:
    - expression: >-
        object.phase == "response"
        ? extproc.ReplaceBody("redacted")
        : null
`)
	var jsonPolicy vpol.ValidatingPolicy
	if err := yaml.Unmarshal(jsonPolicyYAML, &jsonPolicy); err != nil {
		t.Fatal(err)
	}
	jsonCompiled, jsonErrs := compiler.NewCompiler[dynamic.Interface, celproc.Input, *celproc.Result](nil).Compile(&jsonPolicy, nil)
	if err := jsonErrs.ToAggregate(); err != nil {
		t.Fatalf("compile JSON body policy: %v", err)
	}
	jsonProcessor := newService(fixedSource{policies: []engine.ProcessorPolicy{jsonCompiled}}, nil, false)
	jsonStream := &fakeStream{ctx: context.Background(), requests: []*extprocv3.ProcessingRequest{
		requestHeaders(map[string]string{":method": "POST", ":path": "/v1/chat/completions"}, false),
		requestBody([]byte(`{"model":"demo"}`), true),
		responseHeaders(map[string]string{":status": "200", "content-type": "application/json", "content-length": "9"}, false),
		responseBody([]byte("sensitive"), true),
	}}
	if err := jsonProcessor.Process(jsonStream); err != nil {
		t.Fatal(err)
	}
	jsonMutation := jsonStream.responses[3].GetResponseBody().GetResponse()
	if string(jsonMutation.GetBodyMutation().GetBody()) != "redacted" {
		t.Fatalf("replacement body = %q", jsonMutation.GetBodyMutation().GetBody())
	}
	if got := jsonMutation.GetHeaderMutation().GetSetHeaders()[0].GetHeader().GetValue(); got != "8" {
		t.Fatalf("content-length = %q", got)
	}

	bobStream := &fakeStream{ctx: context.Background(), requests: []*extprocv3.ProcessingRequest{
		requestHeaders(map[string]string{":method": "POST", ":path": "/mcp", "x-user": "bob"}, false),
		requestBody([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`), true),
		responseHeaders(map[string]string{":status": "200", "content-type": "text/event-stream"}, false),
		responseBody([]byte(body), true),
	}}
	if err := processor.Process(bobStream); err != nil {
		t.Fatal(err)
	}
	if bobStream.responses[3].GetResponseBody().GetResponse().GetBodyMutation() != nil {
		t.Fatal("bob should retain the scale tool")
	}

	responseOnly := &fakeStream{ctx: context.Background(), requests: []*extprocv3.ProcessingRequest{
		responseHeaders(map[string]string{":status": "403", "content-type": "application/json"}, false),
		responseBody([]byte(`{"error":"denied"}`), true),
	}}
	if err := processor.Process(responseOnly); err != nil {
		t.Fatal(err)
	}
	if responseOnly.responses[0].GetResponseHeaders().GetResponse().GetStatus() != extprocv3.CommonResponse_CONTINUE ||
		responseOnly.responses[1].GetResponseBody().GetResponse().GetStatus() != extprocv3.CommonResponse_CONTINUE {
		t.Fatal("response-only 403 stream should pass through without policy evaluation")
	}

	brokenResponseRequests := []*extprocv3.ProcessingRequest{
		requestHeaders(map[string]string{":method": "POST", ":path": "/mcp", "x-user": "alice"}, false),
		requestBody([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`), true),
		responseHeaders(map[string]string{":status": "200", "content-type": "application/json"}, false),
		responseBody([]byte("not-json"), true),
	}
	failClosedStream := &fakeStream{ctx: context.Background(), requests: brokenResponseRequests}
	if err := processor.Process(failClosedStream); err != nil {
		t.Fatal(err)
	}
	if failClosedStream.responses[3].GetImmediateResponse() == nil || failClosedStream.responses[3].GetImmediateResponse().GetStatus().GetCode() != 500 {
		t.Fatal("evaluation error should fail closed with an immediate 500")
	}
	failOpenProcessor := newService(fixedSource{policies: []engine.ProcessorPolicy{compiled}}, nil, true)
	failOpenStream := &fakeStream{ctx: context.Background(), requests: brokenResponseRequests}
	if err := failOpenProcessor.Process(failOpenStream); err != nil {
		t.Fatal(err)
	}
	if failOpenStream.responses[3].GetResponseBody().GetResponse().GetStatus() != extprocv3.CommonResponse_CONTINUE {
		t.Fatal("fail-open should continue unmodified after evaluation error")
	}

	respondPolicyYAML := []byte(`apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: respond-test
spec:
  evaluation:
    mode: EnvoyProcessor
  failurePolicy: Fail
  validations:
    - expression: >-
        object.phase == "request"
        ? extproc.Respond(403).WithBody("blocked by policy").WithHeader("x-policy", "blocked")
        : null
`)
	var respondPolicy vpol.ValidatingPolicy
	if err := yaml.Unmarshal(respondPolicyYAML, &respondPolicy); err != nil {
		t.Fatal(err)
	}
	respondCompiled, compileErrs := compiler.NewCompiler[dynamic.Interface, celproc.Input, *celproc.Result](nil).Compile(&respondPolicy, nil)
	if err := compileErrs.ToAggregate(); err != nil {
		t.Fatalf("compile respond policy: %v", err)
	}
	respondProcessor := newService(fixedSource{policies: []engine.ProcessorPolicy{respondCompiled}}, nil, false)
	respondStream := &fakeStream{ctx: context.Background(), requests: []*extprocv3.ProcessingRequest{
		requestHeaders(map[string]string{":method": "POST", ":path": "/mcp", "x-user": "alice"}, false),
		requestBody([]byte(`{"method":"tools/call"}`), true),
	}}
	if err := respondProcessor.Process(respondStream); err != nil {
		t.Fatal(err)
	}
	if len(respondStream.responses) != 2 || respondStream.responses[1].GetImmediateResponse() == nil {
		t.Fatal("expected immediate response")
	}
	if got := respondStream.responses[1].GetImmediateResponse().GetStatus().GetCode(); got != 403 {
		t.Fatalf("status = %v", got)
	}
	if got := string(respondStream.responses[1].GetImmediateResponse().GetBody()); got != "blocked by policy" {
		t.Fatalf("body = %q", got)
	}
	if got := respondStream.responses[1].GetImmediateResponse().GetHeaders().GetSetHeaders(); len(got) != 1 || string(got[0].GetHeader().GetRawValue()) != "blocked" {
		t.Fatalf("unexpected immediate response header set: %#v", got)
	}
}

func headerMap(values map[string]string) *corev3.HeaderMap {
	headers := &corev3.HeaderMap{}
	for key, value := range values {
		headers.Headers = append(headers.Headers, &corev3.HeaderValue{Key: key, Value: value})
	}
	return headers
}
func requestHeaders(values map[string]string, end bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{Headers: headerMap(values), EndOfStream: end}}}
}
func responseHeaders(values map[string]string, end bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &extprocv3.HttpHeaders{Headers: headerMap(values), EndOfStream: end}}}
}
func requestBody(body []byte, end bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{RequestBody: &extprocv3.HttpBody{Body: body, EndOfStream: end}}}
}
func responseBody(body []byte, end bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{ResponseBody: &extprocv3.HttpBody{Body: body, EndOfStream: end}}}
}
