package v1alpha1

import (
	vpol "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
)

const (
	EvaluationModeEnvoy vpol.EvaluationMode = "Envoy"
	EvaluationModeHTTP  vpol.EvaluationMode = "HTTP"
)
