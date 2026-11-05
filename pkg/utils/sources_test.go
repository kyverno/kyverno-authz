package utils

import (
	"testing"

	vpol "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/kyverno-authz/apis"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStaticExceptionReferenceRequiresValidatingPolicyKind(t *testing.T) {
	policy := &vpol.ValidatingPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "guardrails"},
		Spec: vpol.ValidatingPolicySpec{
			EvaluationConfiguration: &vpol.EvaluationConfiguration{Mode: apis.EvaluationModeEnvoy},
		},
	}
	for _, kind := range []string{"MutatingPolicy", "", "ValidatingPolicy"} {
		t.Run(kind, func(t *testing.T) {
			exception := &vpol.PolicyException{Spec: vpol.PolicyExceptionSpec{
				EvaluationMode: apis.EvaluationModeEnvoy,
				PolicyRefs:     []vpol.PolicyRef{{Name: policy.Name, Kind: kind}},
			}}
			source := newStatic[any](nil, []*vpol.ValidatingPolicy{policy}, []*vpol.PolicyException{exception})
			matched := source.policyMap[policy]
			if (len(matched) == 1) != (kind == "ValidatingPolicy") {
				t.Fatalf("kind %q incorrectly matched same-named policy: %v", kind, matched)
			}
		})
	}
}

func TestFilterPoliciesByMode(t *testing.T) {
	envoyPolicy := &vpol.ValidatingPolicy{Spec: vpol.ValidatingPolicySpec{EvaluationConfiguration: &vpol.EvaluationConfiguration{Mode: apis.EvaluationModeEnvoy}}}
	processorPolicy := &vpol.ValidatingPolicy{Spec: vpol.ValidatingPolicySpec{EvaluationConfiguration: &vpol.EvaluationConfiguration{Mode: apis.EvaluationModeEnvoyProcessor}}}
	for _, test := range []struct {
		mode vpol.EvaluationMode
		want *vpol.ValidatingPolicy
	}{
		{mode: apis.EvaluationModeEnvoy, want: envoyPolicy},
		{mode: apis.EvaluationModeEnvoyProcessor, want: processorPolicy},
	} {
		got := filterPoliciesByMode([]*vpol.ValidatingPolicy{envoyPolicy, processorPolicy}, test.mode)
		if len(got) != 1 || got[0] != test.want {
			t.Fatalf("mode %s selected unexpected policies: %#v", test.mode, got)
		}
	}
}
