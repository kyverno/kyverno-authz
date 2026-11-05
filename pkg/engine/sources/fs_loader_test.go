package sources

import (
	"context"
	"fmt"
	"testing"
	"testing/fstest"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kyverno/kyverno-authz/pkg/engine/compiler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/dynamic"
)

func TestLoadPoliciesIncludesPolicyExceptions(t *testing.T) {
	for _, version := range []string{"v1", "v1beta1", "v1alpha1"} {
		t.Run(version, func(t *testing.T) {
			documents := fmt.Sprintf(`apiVersion: policies.kyverno.io/%s
kind: ValidatingPolicy
metadata:
  name: file-guardrails
spec:
  evaluation:
    mode: Envoy
  variables:
  - name: exempt
    expression: 'object.attributes.request.http.headers[?"x-exempt"].orValue("") == "yes"'
  validations:
  - expression: 'envoy.Denied(403).WithBody("Tool access denied").Response()'
---
apiVersion: policies.kyverno.io/%s
kind: PolicyException
metadata:
  name: file-exemption
  namespace: default
spec:
  evaluationMode: Envoy
  policyRefs:
  - kind: ValidatingPolicy
    name: file-guardrails
  matchConditions:
  - name: exempt-request
    expression: 'variables.exempt'
`, version, version)
			policies, exceptions, err := LoadPolicies(fstest.MapFS{"policies.yaml": &fstest.MapFile{Data: []byte(documents)}})
			require.NoError(t, err)
			require.Len(t, policies, 1)
			require.Len(t, exceptions, 1)
			assert.Equal(t, "file-guardrails", exceptions[0].Spec.PolicyRefs[0].Name)
			compiled, errs := compiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](nil).Compile(policies[0], exceptions)
			require.NoError(t, errs.ToAggregate())
			for _, exempt := range []string{"yes", "no"} {
				response, err := compiled.Evaluate(context.Background(), nil, &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{Headers: map[string]string{"x-exempt": exempt}}}}})
				require.NoError(t, err)
				if exempt == "yes" {
					assert.Nil(t, response)
				} else {
					require.NotNil(t, response)
					assert.NotNil(t, response.GetDeniedResponse())
				}
			}
		})
	}
}
