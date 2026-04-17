package metrics

import (
	"context"
	"time"

	kyengine "github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/sdk/core"
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	DecisionAllow   = "allow"
	DecisionDeny    = "deny"
	DecisionError   = "error"
	DecisionNoMatch = "no_match"
)

var (
	authzDecisionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authz_policy_evaluations_total",
			Help: "Total number of authz policy evaluations by policy name and decision outcome.",
		},
		[]string{"policy", "decision"},
	)
	authzPolicyDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "authz_policy_evaluation_duration_seconds",
			Help: "Duration in seconds of individual policy evaluations.",
		},
		[]string{"policy", "decision"},
	)
)

func init() {
	ctrlmetrics.Registry.MustRegister(authzDecisionsTotal, authzPolicyDurationSeconds)
}

// policyName extracts the name from a policy if it implements engine.Named,
// falling back to "unknown".
func policyName[POLICY any](p POLICY) string {
	if named, ok := any(p).(kyengine.Named); ok {
		return named.Name()
	}
	return "unknown"
}

// RecordPolicyDecision records a counter and duration observation for a single
// policy evaluation.
func RecordPolicyDecision(policyName, decision string, start time.Time) {
	authzDecisionsTotal.WithLabelValues(policyName, decision).Inc()
	authzPolicyDurationSeconds.WithLabelValues(policyName, decision).Observe(time.Since(start).Seconds())
}

// MetricsEvaluatorFactory wraps a core.EvaluatorFactory to record per-policy
// decision metrics. classifyFn maps the evaluation output (which for authz
// policies is policy.Evaluation[T] and already contains any error) to one of
// DecisionAllow / DecisionDeny / DecisionError / DecisionNoMatch.
func MetricsEvaluatorFactory[
	POLICY any,
	DATA any,
	IN any,
	OUT any,
](
	inner core.EvaluatorFactory[POLICY, DATA, IN, OUT],
	classifyFn func(OUT) string,
) core.EvaluatorFactory[POLICY, DATA, IN, OUT] {
	return func(ctx context.Context, fc core.FactoryContext[POLICY, DATA, IN]) core.Evaluator[POLICY, IN, OUT] {
		delegate := inner(ctx, fc)
		return core.MakeEvaluatorFunc(func(ctx context.Context, pol POLICY, in IN) OUT {
			start := time.Now()
			out := delegate.Evaluate(ctx, pol, in)
			RecordPolicyDecision(policyName(pol), classifyFn(out), start)
			return out
		})
	}
}
