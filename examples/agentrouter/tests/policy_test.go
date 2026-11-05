package agentrouter_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	vpol "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/kyverno-authz/pkg/engine/compiler"
	"github.com/kyverno/kyverno-authz/pkg/engine/sources"
	"k8s.io/client-go/dynamic"
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

func TestExecutionUsesLiveSAR(t *testing.T) {
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
