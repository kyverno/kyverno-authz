package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/kyverno/sdk/extensions/policy"
	"github.com/stretchr/testify/assert"
)

type namedPolicy string

func (p namedPolicy) Name() string { return string(p) }

func TestPolicyResulterRetainsSelectedPolicy(t *testing.T) {
	for _, failure := range []error{nil, errors.New("evaluation failed")} {
		result := NewPolicyResulter[namedPolicy, string](func(out policy.Evaluation[*string]) bool { return out.Result != nil || out.Error != nil })
		ctx := context.Background()
		result.Collect(ctx, namedPolicy("no-match"), "request", policy.Evaluation[*string]{})
		decision := "denied"
		result.Collect(ctx, namedPolicy("selected-policy"), "request", policy.Evaluation[*string]{Result: &decision, Error: failure})
		result.Collect(ctx, namedPolicy("later-policy"), "request", policy.Evaluation[*string]{Result: &decision})
		assert.Equal(t, "selected-policy", result.Result().PolicyName)
		assert.Equal(t, &decision, result.Result().Result)
		assert.Equal(t, failure, result.Result().Error)
	}
}
