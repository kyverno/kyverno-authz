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
