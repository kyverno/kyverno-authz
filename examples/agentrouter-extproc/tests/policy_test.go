package agentrouter_test

import (
	"context"
	"encoding/json"
	"fmt"
	"google.golang.org/protobuf/types/known/timestamppb"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"testing/fstest"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	vpol "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/kyverno-authz/apis"
	celproc "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/extproc"
	"github.com/kyverno/kyverno-authz/pkg/engine/compiler"
	"github.com/kyverno/kyverno-authz/pkg/engine/sources"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

// The authorizer skips policies that fail to compile, which would allow
// requests that no other policy matches. Every file must therefore compile.
func TestPoliciesCompile(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "policies", "authz", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	processorFiles, err := filepath.Glob(filepath.Join("..", "policies", "processor", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || len(processorFiles) != 1 {
		t.Fatalf("expected two Envoy and one processor policies: %v %v", files, processorFiles)
	}
	files = append(files, processorFiles...)
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			var policy vpol.ValidatingPolicy
			if err := yaml.UnmarshalStrict(data, &policy); err != nil {
				t.Fatal(err)
			}
			if len(policy.Spec.MatchConditions) != 1 {
				t.Fatal("each policy must select its routes with one match condition")
			}
			if policy.Spec.EvaluationMode() == apis.EvaluationModeEnvoyProcessor {
				c := compiler.NewCompiler[dynamic.Interface, celproc.Input, *celproc.Result](nil)
				if _, errs := c.Compile(&policy, nil); len(errs) != 0 {
					t.Fatal(errs.ToAggregate())
				}
				return
			}
			c := compiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](nil)
			if _, errs := c.Compile(&policy, nil); len(errs) != 0 {
				t.Fatal(errs.ToAggregate())
			}
		})
	}
}

func discoveryPolicy(t *testing.T) vpol.ValidatingPolicy {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "policies", "processor", "mcp-tool-discovery.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var policy vpol.ValidatingPolicy
	if err := yaml.UnmarshalStrict(data, &policy); err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestDiscoveryIgnoresOtherTraffic(t *testing.T) {
	policy := discoveryPolicy(t)
	compiled, errs := compiler.NewCompiler[dynamic.Interface, celproc.Input, *celproc.Result](nil).Compile(&policy, nil)
	if len(errs) != 0 {
		t.Fatal(errs.ToAggregate())
	}
	for _, input := range []celproc.Input{
		{Phase: "request", Request: celproc.Request{Method: "POST", Path: "/mcp", Body: `{"method":"tools/list"}`}},
		{Phase: "response", Request: celproc.Request{Method: "GET", Path: "/mcp"}, Response: celproc.Response{Status: 200}},
		{Phase: "response", Request: celproc.Request{Method: "POST", Path: "/v1/chat/completions"}, Response: celproc.Response{Status: 200}},
		{Phase: "response", Request: celproc.Request{Method: "POST", Path: "/mcp", Body: `{"method":"initialize"}`}, Response: celproc.Response{Status: 200, Body: `{"result":{}}`}},
		{Phase: "response", Request: celproc.Request{Method: "POST", Path: "/mcp", Body: `{"method":"tools/call"}`}, Response: celproc.Response{Status: 200, Body: `{"result":{"content":[]}}`}},
		{Phase: "response", Request: celproc.Request{Method: "POST", Path: "/mcp", Body: `{"method":"notifications/initialized"}`}, Response: celproc.Response{Status: 202}},
		{Phase: "response", Request: celproc.Request{Method: "POST", Path: "/mcp", Body: `{"method":"tools/list"}`}, Response: celproc.Response{Status: 403}},
	} {
		t.Run(input.Phase+input.Request.Method+input.Request.Path+input.Request.Body, func(t *testing.T) {
			// No token, JWKS server, or Kubernetes client: any eager identity/SAR
			// evaluation would fail these pass-through cases.
			result, err := compiled.Evaluate(context.Background(), nil, input)
			if err != nil || result != nil {
				t.Fatalf("non-discovery traffic evaluated: result=%+v, err=%v", result, err)
			}
		})
	}
}

func TestDiscoveryFiltersAndPreservesFields(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		t.Run(fmt.Sprint(allowed), func(t *testing.T) {
			policy := discoveryPolicy(t)
			for i := range policy.Spec.Variables {
				switch policy.Spec.Variables[i].Name {
				case "token":
					policy.Spec.Variables[i].Expression = `{"Valid": dyn(true), "Claims": dyn({"preferred_username": dyn("alice"), "iss": dyn("http://keycloak.agentrouter-demo.svc.cluster.local:8080/realms/demo"), "aud": dyn(["agentrouter-demo"])})}`
				case "sar":
					policy.Spec.Variables[i].Expression = fmt.Sprintf(`{"status":{"allowed":%t}}`, allowed)
				}
			}
			compiled, errs := compiler.NewCompiler[dynamic.Interface, celproc.Input, *celproc.Result](nil).Compile(&policy, nil)
			if len(errs) != 0 {
				t.Fatal(errs.ToAggregate())
			}
			body := `{"jsonrpc":"2.0","id":9,"extra":{"kept":true},"result":{"ttlMs":0,"cacheScope":"public","future":[1,"two"],"tools":[{"name":"runbooks__get_runbook","description":"keep me"},{"name":"kube-tools__scale_deployment"}]}}`
			input := celproc.Input{Phase: "response", Request: celproc.Request{Method: "POST", Path: "/mcp", Body: `{"method":"tools/list"}`}, Response: celproc.Response{
				Status: 200, Body: body, Events: []celproc.SSEEvent{{Event: "message", ID: "9", Data: body}},
			}}
			for _, events := range [][]celproc.SSEEvent{
				nil,
				{{Event: "message", ID: "9"}, {Event: "message", ID: "10"}},
				{{Event: "message"}},
				{{Event: "ping", ID: "9"}},
			} {
				invalid := input
				invalid.Response.Events = events
				result, err := compiled.Evaluate(context.Background(), nil, invalid)
				if err != nil || result == nil || result.Action != "respond" || result.Status != 500 {
					t.Fatalf("unsupported SSE must fail closed for SAR allowed=%t: result=%+v, err=%v", allowed, result, err)
				}
			}
			result, err := compiled.Evaluate(context.Background(), nil, input)
			if err != nil || result == nil {
				t.Fatalf("result=%+v, err=%v", result, err)
			}
			if allowed {
				if result.Action != "continue" || result.ReplaceBody {
					t.Fatalf("authorized discovery changed: %+v", result)
				}
				return
			}
			var expected, actual map[string]any
			if err := json.Unmarshal([]byte(body), &expected); err != nil {
				t.Fatal(err)
			}
			originalResult := expected["result"].(map[string]any)
			originalResult["tools"] = originalResult["tools"].([]any)[:1]
			if err := json.Unmarshal([]byte(result.Body), &actual); err != nil {
				t.Fatal(err)
			}
			if !result.ReplaceBody || !reflect.DeepEqual(actual, expected) {
				t.Fatalf("replacement did not preserve fields: %+v", result)
			}
			input.Response.Body = "not-json"
			if _, err := compiled.Evaluate(context.Background(), nil, input); err == nil {
				t.Fatal("malformed discovery response must fail closed")
			}
		})
	}
}

func TestBreakGlassCompiles(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "policies", "authz", "mcp-operations.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var policy vpol.ValidatingPolicy
	if err := yaml.UnmarshalStrict(data, &policy); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join("..", "policies", "exceptions", "break-glass-inc-1234.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var exception vpol.PolicyException
	if err := yaml.UnmarshalStrict(data, &exception); err != nil {
		t.Fatal(err)
	}
	if len(exception.Spec.PolicyRefs) != 1 || exception.Spec.PolicyRefs[0].Name != policy.Name || exception.Spec.EvaluationMode != policy.Spec.EvaluationMode() {
		t.Fatal("exception must reference exactly its Envoy policy")
	}
	c := compiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](nil)
	if _, errs := c.Compile(&policy, []*vpol.PolicyException{&exception}); len(errs) != 0 {
		t.Fatal(errs.ToAggregate())
	}
}

func TestBreakGlassScope(t *testing.T) {
	policyData, err := os.ReadFile(filepath.Join("..", "policies", "authz", "mcp-operations.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var policy vpol.ValidatingPolicy
	if err := yaml.UnmarshalStrict(policyData, &policy); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("..", "policies", "exceptions", "break-glass-inc-1234.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var exception vpol.PolicyException
	if err := yaml.UnmarshalStrict(data, &exception); err != nil {
		t.Fatal(err)
	}
	exception.Spec.MatchConditions = append(exception.Spec.MatchConditions, admissionregistrationv1.MatchCondition{
		Name: "expires-at", Expression: `object.attributes.request.time < timestamp("2099-01-01T00:00:00Z")`,
	})
	for _, tc := range []struct {
		name, user, tool, namespace, incident string
		replicas                              any
		exempt                                bool
	}{
		{"incident", "bob", "kube-tools__scale_deployment", "team-a-dev", "INC-1234", 2, true},
		{"expired", "bob", "kube-tools__scale_deployment", "team-a-dev", "INC-1234", 2, false},
		{"no-header", "bob", "kube-tools__scale_deployment", "team-a-dev", "", 2, false},
		{"wrong-incident", "bob", "kube-tools__scale_deployment", "team-a-dev", "INC-9999", 2, false},
		{"alice", "alice", "kube-tools__scale_deployment", "team-a-dev", "INC-1234", 2, false},
		{"tool", "bob", "kube-tools__get_workload_status", "team-a-dev", "INC-1234", 2, false},
		{"namespace", "bob", "kube-tools__scale_deployment", "team-b-dev", "INC-1234", 2, false},
		{"over-limit", "bob", "kube-tools__scale_deployment", "team-a-dev", "INC-1234", 50, false},
		{"fraction", "bob", "kube-tools__scale_deployment", "team-a-dev", "INC-1234", 1.5, false},
		{"string", "bob", "kube-tools__scale_deployment", "team-a-dev", "INC-1234", "2", false},
		{"bool", "bob", "kube-tools__scale_deployment", "team-a-dev", "INC-1234", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := policy.DeepCopy()
			for i := range copy.Spec.Variables {
				switch copy.Spec.Variables[i].Name {
				case "token":
					copy.Spec.Variables[i].Expression = fmt.Sprintf(`{"Valid": dyn(true), "Claims": dyn({"preferred_username": dyn(%q), "iss": dyn("http://keycloak.agentrouter-demo.svc.cluster.local:8080/realms/demo"), "aud": dyn(["agentrouter-demo"])})}`, tc.user)
				case "sar", "podListSar":
					copy.Spec.Variables[i].Expression = `{"status":{"allowed":false}}`
				}
			}
			exceptionForCase := exception.DeepCopy()
			if tc.name == "expired" {
				exceptionForCase.Spec.MatchConditions[len(exceptionForCase.Spec.MatchConditions)-1].Expression = `object.attributes.request.time < timestamp("2000-01-01T00:00:00Z")`
			}
			compiled, errs := compiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](nil).Compile(copy, []*vpol.PolicyException{exceptionForCase})
			if len(errs) != 0 {
				t.Fatal(errs.ToAggregate())
			}
			args := map[string]any{"namespace": tc.namespace, "name": "checkout", "replicas": tc.replicas}
			if tc.tool != "kube-tools__scale_deployment" {
				delete(args, "replicas")
			}
			body, err := json.Marshal(map[string]any{"method": "tools/call", "params": map[string]any{"name": tc.tool, "arguments": args}})
			if err != nil {
				t.Fatal(err)
			}
			headers := map[string]string{"authorization": "Bearer test"}
			if tc.incident != "" {
				headers["x-incident-id"] = tc.incident
			}
			request := &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{Time: timestamppb.New(time.Now()), Http: &authv3.AttributeContext_HttpRequest{Method: "POST", Path: "/mcp", Headers: headers, Body: string(body)}}}}
			result, err := compiled.Evaluate(context.Background(), nil, request)
			if err != nil {
				t.Fatal(err)
			}
			if tc.exempt {
				if result != nil {
					t.Fatalf("exception did not skip whole policy: %v", result)
				}
			} else if result == nil || result.GetDeniedResponse() == nil {
				t.Fatalf("outside exception must remain denied: %v", result)
			}
		})
	}
}

func TestFileSourceLoadsPoliciesAndException(t *testing.T) {
	files := fstest.MapFS{}
	for _, path := range []string{
		"authz/mcp-operations.yaml", "authz/llm-models.yaml",
		"processor/mcp-tool-discovery.yaml", "exceptions/break-glass-inc-1234.yaml",
	} {
		data, err := os.ReadFile(filepath.Join("..", "policies", path))
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.Base(path)] = &fstest.MapFile{Data: data}
	}
	policies, exceptions, err := sources.LoadPolicies(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 3 || len(exceptions) != 1 {
		t.Fatalf("file loader skipped documents: %d policies, %d exceptions", len(policies), len(exceptions))
	}
}
