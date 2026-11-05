package utils

import (
	"testing"

	vpol "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/kyverno-authz/apis"
)

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
