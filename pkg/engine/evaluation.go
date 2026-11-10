package engine

import (
	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/core/resulters"
	"github.com/kyverno/sdk/extensions/policy"
)

// Evaluation retains the policy responsible for the selected engine outcome.
// The SDK's policy.Evaluation alone does not carry policy attribution.
type Evaluation[RESULT any] struct {
	policy.Evaluation[RESULT]
	PolicyName string
}

func NewPolicyResulter[POLICY, IN, RESULT any](selected func(policy.Evaluation[RESULT]) bool) core.Resulter[POLICY, IN, policy.Evaluation[RESULT], Evaluation[RESULT]] {
	return resulters.NewTransformer(
		func(p POLICY, _ IN, out policy.Evaluation[RESULT]) Evaluation[RESULT] {
			name := ""
			if named, ok := any(p).(Named); ok {
				name = named.Name()
			}
			return Evaluation[RESULT]{Evaluation: out, PolicyName: name}
		},
		func(out Evaluation[RESULT]) Evaluation[RESULT] { return out },
		resulters.NewFirst[POLICY, IN](func(out Evaluation[RESULT]) bool { return selected(out.Evaluation) }),
	)
}
