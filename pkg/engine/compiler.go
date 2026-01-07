package engine

import (
	vpol "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

type Compiler[POLICY any] interface {
	Compile(*vpol.ValidatingPolicy) (POLICY, field.ErrorList)
}
