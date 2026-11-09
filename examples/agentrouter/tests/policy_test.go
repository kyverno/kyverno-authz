package agentrouter_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/google/cel-go/cel"
	vpol "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/kyverno-authz/pkg/engine/compiler"
	"github.com/kyverno/kyverno-authz/pkg/engine/sources"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
	"sigs.k8s.io/yaml"
)

func readPolicy(t *testing.T, name string) *vpol.ValidatingPolicy {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "policies", "authz", name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var policy vpol.ValidatingPolicy
	if err := yaml.UnmarshalStrict(data, &policy); err != nil {
		t.Fatal(err)
	}
	return &policy
}

// File policies which do not compile are skipped, so validate before deployment.
func TestPoliciesCompile(t *testing.T) {
	for _, name := range []string{"mcp-operations", "llm-models"} {
		t.Run(name, func(t *testing.T) {
			c := compiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](nil)
			if _, errs := c.Compile(readPolicy(t, name), nil); len(errs) != 0 {
				t.Fatal(errs.ToAggregate())
			}
		})
	}
}

func TestMCPMessageValidation(t *testing.T) {
	for _, tc := range []struct {
		name, method, body string
		status             int32
	}{
		{"missing-method", "POST", `{}`, 400},
		{"heartbeat-response", "POST", `{"jsonrpc":"2.0","id":"aigw-server-to-client-ping-test","result":{}}`, 0},
		{"response-numeric-id", "POST", `{"jsonrpc":"2.0","id":1,"result":{}}`, 0},
		{"error-response", "POST", `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`, 0},
		{"response-without-version", "POST", `{"id":1,"result":{}}`, 400},
		{"response-without-id", "POST", `{"jsonrpc":"2.0","result":{}}`, 400},
		{"response-with-invalid-id", "POST", `{"jsonrpc":"2.0","id":{},"result":{}}`, 400},
		{"response-without-outcome", "POST", `{"jsonrpc":"2.0","id":1}`, 400},
		{"response-conflicting-outcomes", "POST", `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-32601,"message":"failed"}}`, 400},
		{"response-with-params", "POST", `{"jsonrpc":"2.0","id":1,"result":{},"params":{"name":"scale"}}`, 400},
		{"invalid-error-response", "POST", `{"jsonrpc":"2.0","id":1,"error":{"code":"oops","message":"failed"}}`, 400},
		{"missing-error-fields", "POST", `{"jsonrpc":"2.0","id":1,"error":{}}`, 400},
		{"out-of-range-error-code", "POST", `{"jsonrpc":"2.0","id":1,"error":{"code":1e100,"message":"failed"}}`, 400},
		{"request-cannot-use-response-bypass", "POST", `{"jsonrpc":"2.0","id":1,"result":{},"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":50}}}`, 403},
		{"non-string-method", "POST", `{"method":1}`, 400},
		{"non-object-message", "POST", `[]`, 400},
		{"missing-params", "POST", `{"method":"tools/call"}`, 400},
		{"missing-arguments", "POST", `{"method":"tools/call","params":{"name":"kube-tools__scale_deployment"}}`, 400},
		{"non-object-arguments", "POST", `{"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":[]}}`, 400},
		{"unsupported-method", "POST", `{"method":"unknown"}`, 403},
		{"ping", "POST", `{"method":"ping"}`, 0},
		{"initialized", "POST", `{"method":"notifications/initialized"}`, 0},
		{"event-stream", "GET", "", 0},
		{"session-delete", "DELETE", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := readPolicy(t, "mcp-operations")
			for i := range policy.Spec.Variables {
				if policy.Spec.Variables[i].Name == "token" {
					policy.Spec.Variables[i].Expression = `{"Valid": dyn(true), "Claims": dyn({"preferred_username": dyn("alice"), "iss": dyn("http://keycloak.agentrouter-demo.svc.cluster.local:8080/realms/demo"), "aud": dyn(["agentrouter-demo"])})}`
				}
			}
			compiled, errs := compiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](nil).Compile(policy, nil)
			if len(errs) != 0 {
				t.Fatal(errs.ToAggregate())
			}
			request := &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: tc.method, Path: "/mcp", Headers: map[string]string{"authorization": "Bearer test"}, Body: tc.body,
				},
			}}}
			result, err := compiled.Evaluate(context.Background(), nil, request)
			if err != nil || result == nil {
				t.Fatalf("message must produce a decision, not an evaluation error: result=%v err=%v", result, err)
			}
			if tc.status == 0 {
				if result.GetOkResponse() == nil {
					t.Fatalf("valid transport or message denied: %v", result)
				}
			} else if int32(result.GetDeniedResponse().GetStatus().GetCode()) != tc.status ||
				!strings.HasPrefix(result.GetDeniedResponse().GetBody(), "Blocked by Kyverno policy agentrouter-bounded-operations: ") {
				t.Fatalf("expected attributed HTTP %d denial: %v", tc.status, result)
			}
		})
	}
}

func TestMCPResponsesRequireIdentity(t *testing.T) {
	policy := readPolicy(t, "mcp-operations")
	for i := range policy.Spec.Variables {
		if policy.Spec.Variables[i].Name == "token" {
			policy.Spec.Variables[i].Expression = `{"Valid": dyn(false)}`
		}
	}
	compiled, errs := compiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](nil).Compile(policy, nil)
	if len(errs) != 0 {
		t.Fatal(errs.ToAggregate())
	}
	for _, headers := range []map[string]string{nil, {"authorization": "Bearer rejected"}} {
		request := &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
			Http: &authv3.AttributeContext_HttpRequest{
				Method: "POST", Path: "/mcp", Headers: headers,
				Body: `{"jsonrpc":"2.0","id":"aigw-server-to-client-ping-test","result":{}}`,
			},
		}}}
		result, err := compiled.Evaluate(context.Background(), nil, request)
		if err != nil || result.GetDeniedResponse().GetStatus().GetCode() != 401 {
			t.Fatalf("response must not bypass authentication: result=%v err=%v", result, err)
		}
	}
}

func TestModelGuardRequiresGatewayAPITargetGroup(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "policies", "admission", "aigatewayroute-guardrails.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var policy vpol.ValidatingPolicy
	if err := yaml.UnmarshalStrict(data, &policy); err != nil {
		t.Fatal(err)
	}
	var expression string
	for _, variable := range policy.Spec.Variables {
		if variable.Name == "guards" {
			expression = variable.Expression
		}
	}
	lookup := `resource.List("gateway.envoyproxy.io/v1alpha1", "securitypolicies", object.metadata.namespace)`
	if !strings.Contains(expression, lookup) {
		t.Fatal("expected SecurityPolicy list lookup")
	}
	env, err := cel.NewEnv(cel.OptionalTypes(), cel.Variable("policies", cel.DynType), cel.Variable("object", cel.DynType))
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := env.Compile(strings.ReplaceAll(expression, lookup, "policies"))
	if issues.Err() != nil {
		t.Fatal(issues.Err())
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"gateway.networking.k8s.io", "other.example.io"} {
		t.Run(group, func(t *testing.T) {
			out, _, err := program.Eval(map[string]any{
				"object": map[string]any{"metadata": map[string]any{"name": "models", "namespace": "agentrouter-demo"}},
				"policies": map[string]any{"items": []any{map[string]any{"spec": map[string]any{
					"targetRefs": []any{map[string]any{"group": group, "kind": "HTTPRoute", "name": "models"}},
					"jwt":        map[string]any{},
					"extAuth": map[string]any{
						"grpc":          map[string]any{"backendRefs": []any{map[string]any{"name": "kyverno-authz"}}},
						"bodyToExtAuth": map[string]any{"maxRequestBytes": 16384},
					},
				}}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			native, err := out.ConvertToNative(reflect.TypeOf([]any{}))
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if group == "gateway.networking.k8s.io" {
				want = 1
			}
			if len(native.([]any)) != want {
				t.Fatalf("group %s: guards=%v", group, out)
			}
		})
	}
}

func TestFileSourceLoadsPolicies(t *testing.T) {
	files := fstest.MapFS{}
	for _, name := range []string{"mcp-operations", "llm-models"} {
		data, err := os.ReadFile(filepath.Join("..", "policies", "authz", name+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		files[name+".yaml"] = &fstest.MapFile{Data: data}
	}
	policies, exceptions, err := sources.LoadPolicies(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 || len(exceptions) != 0 {
		t.Fatalf("file loader: %d policies, %d exceptions", len(policies), len(exceptions))
	}
}

func TestExecutionSARDecisionBranches(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		t.Run(fmt.Sprint(allowed), func(t *testing.T) {
			policy := readPolicy(t, "mcp-operations")
			for i := range policy.Spec.Variables {
				switch policy.Spec.Variables[i].Name {
				case "token":
					policy.Spec.Variables[i].Expression = `{"Valid": dyn(true), "Claims": dyn({"preferred_username": dyn("alice"), "iss": dyn("http://keycloak.agentrouter-demo.svc.cluster.local:8080/realms/demo"), "aud": dyn(["agentrouter-demo"])})}`
				case "sar":
					policy.Spec.Variables[i].Expression = fmt.Sprintf(`{"status":{"allowed":%t}}`, allowed)
				}
			}
			compiled, errs := compiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](nil).Compile(policy, nil)
			if len(errs) != 0 {
				t.Fatal(errs.ToAggregate())
			}
			body, err := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{
				"name":      "kube-tools__scale_deployment",
				"arguments": map[string]any{"namespace": "team-a-dev", "name": "checkout", "replicas": 2},
			}})
			if err != nil {
				t.Fatal(err)
			}
			request := &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "POST", Path: "/mcp", Headers: map[string]string{"authorization": "Bearer sample"}, Body: string(body),
				},
			}}}
			result, err := compiled.Evaluate(context.Background(), nil, request)
			if err != nil {
				t.Fatal(err)
			}
			if result == nil || (allowed && result.GetOkResponse() == nil) || (!allowed && result.GetDeniedResponse() == nil) {
				t.Fatalf("SAR allowed=%t: %v", allowed, result)
			}
			if !allowed && result.GetDeniedResponse().GetBody() != "Blocked by Kyverno policy agentrouter-bounded-operations: Kubernetes SAR denied" {
				t.Fatalf("denial must identify the policy and reason: %v", result)
			}
		})
	}
}

func TestModelPolicyEvaluatesIdentityBeforeBody(t *testing.T) {
	for _, tc := range []struct {
		name, authorization, token string
		wantError                  bool
	}{
		{name: "missing-header"},
		{name: "non-bearer-header", authorization: "Basic sample"},
		{name: "rejected-identity", authorization: "Bearer sample", token: `{"Valid": dyn(false)}`},
		{
			name: "authenticated-malformed-body", authorization: "Bearer sample", wantError: true,
			token: `{"Valid": dyn(true), "Claims": dyn({"preferred_username": dyn("alice"), "iss": dyn("http://keycloak.agentrouter-demo.svc.cluster.local:8080/realms/demo"), "aud": dyn(["agentrouter-demo"])})}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := readPolicy(t, "llm-models")
			if tc.token != "" {
				for i := range policy.Spec.Variables {
					if policy.Spec.Variables[i].Name == "token" {
						policy.Spec.Variables[i].Expression = tc.token
					}
				}
			}
			compiled, errs := compiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](nil).Compile(policy, nil)
			if len(errs) != 0 {
				t.Fatal(errs.ToAggregate())
			}
			headers := map[string]string{}
			if tc.authorization != "" {
				headers["authorization"] = tc.authorization
			}
			request := &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "POST", Path: "/v1/chat/completions", Headers: headers, Body: "{not-json",
				},
			}}}
			result, err := compiled.Evaluate(context.Background(), nil, request)
			if tc.wantError {
				if err == nil {
					t.Fatal("authenticated malformed JSON must fail closed, not evaluate fallback data")
				}
			} else if err != nil || result == nil || result.GetDeniedResponse().GetStatus().GetCode() != 401 {
				t.Fatalf("identity must be denied before parsing body: result=%v err=%v", result, err)
			} else if !strings.HasPrefix(result.GetDeniedResponse().GetBody(), "Blocked by Kyverno policy agentrouter-model-governance: ") {
				t.Fatalf("identity denial must identify the policy: %v", result)
			}
		})
	}
}

func TestExecutionPostsSubjectAccessReview(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		t.Run(fmt.Sprint(allowed), func(t *testing.T) {
			policy := readPolicy(t, "mcp-operations")
			for i := range policy.Spec.Variables {
				if policy.Spec.Variables[i].Name == "token" {
					policy.Spec.Variables[i].Expression = `{"Valid": dyn(true), "Claims": dyn({"preferred_username": dyn("alice"), "iss": dyn("http://keycloak.agentrouter-demo.svc.cluster.local:8080/realms/demo"), "aud": dyn(["agentrouter-demo"])})}`
				}
			}
			client := fake.NewSimpleDynamicClient(runtime.NewScheme())
			calls := 0
			client.PrependReactor("create", "subjectaccessreviews", func(action clienttesting.Action) (bool, runtime.Object, error) {
				calls++
				expectedResource := schema.GroupVersionResource{Group: "authorization.k8s.io", Version: "v1", Resource: "subjectaccessreviews"}
				if action.GetResource() != expectedResource || action.GetNamespace() != "" {
					t.Fatalf("SAR must use cluster-scoped authorization API: %+v", action)
				}
				review := action.(clienttesting.CreateAction).GetObject().(*unstructured.Unstructured)
				expected := map[string]any{
					"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview",
					"spec": map[string]any{
						"user": "alice",
						"resourceAttributes": map[string]any{
							"namespace": "team-a-dev", "group": "apps", "resource": "deployments",
							"subresource": "scale", "name": "checkout", "verb": "update",
						},
					},
				}
				if !reflect.DeepEqual(review.Object, expected) {
					t.Fatalf("unexpected SAR body: %#v", review.Object)
				}
				response := review.DeepCopy()
				response.Object["status"] = map[string]any{"allowed": allowed}
				return true, response, nil
			})
			compiled, errs := compiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](client).Compile(policy, nil)
			if len(errs) != 0 {
				t.Fatal(errs.ToAggregate())
			}
			request := &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "POST", Path: "/mcp", Headers: map[string]string{"authorization": "Bearer sample"},
					Body: `{"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":2}}}`,
				},
			}}}
			result, err := compiled.Evaluate(context.Background(), client, request)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || result == nil || (allowed && result.GetOkResponse() == nil) || (!allowed && result.GetDeniedResponse() == nil) {
				t.Fatalf("SAR allowed=%t, posts=%d: %v", allowed, calls, result)
			}
		})
	}
}

func TestReportFormatOmitsRequest(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "manifests", "workloads.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var format string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, `- "--log-msg-format=`) {
			format = strings.TrimSuffix(strings.TrimPrefix(line, `- "--log-msg-format=`), `"`)
		}
	}
	if format == "" {
		t.Fatal("deployment must override the unsafe default report format")
	}
	output := fmt.Sprintf(format, "timestamp", `{"authorization":"Bearer secret","body":"sensitive"}`, "allowed")
	if output != "[timestamp] decision: allowed" || strings.Contains(output, "EXTRA") {
		t.Fatalf("request leaked or unused argument diagnostic added: %s", output)
	}
}
