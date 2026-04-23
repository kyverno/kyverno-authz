package engine

import (
	v1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type Compiler[POLICY any] interface {
	Compile(*v1.ValidatingPolicy, []*v1.PolicyException) (POLICY, field.ErrorList)
}
