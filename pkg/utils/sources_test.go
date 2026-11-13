package utils

import (
	"context"
	"testing"

	vpolv1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type nameCompiler struct{}

func (nameCompiler) Compile(p *vpolv1.ValidatingPolicy, _ []*vpolv1.PolicyException) (string, field.ErrorList) {
	if p.Name == "bad" {
		return "", field.ErrorList{field.Invalid(field.NewPath("spec"), nil, "syntax error")}
	}
	return p.Name, nil
}

func TestStaticSource_IsolatesCompileErrors(t *testing.T) {
	policy := func(name string) *vpolv1.ValidatingPolicy {
		return &vpolv1.ValidatingPolicy{ObjectMeta: metav1.ObjectMeta{Name: name}}
	}
	src := newStatic[string](nameCompiler{}, []*vpolv1.ValidatingPolicy{policy("a"), policy("bad"), policy("b")}, nil)
	data, err := src.Load(context.Background())
	assert.Equal(t, []string{"a", "b"}, data)
	compileErrs, otherErrs := engine.SplitErrors(err)
	assert.Empty(t, otherErrs)
	if assert.Len(t, compileErrs, 1) {
		assert.Equal(t, "bad", compileErrs[0].Policy)
	}
}
