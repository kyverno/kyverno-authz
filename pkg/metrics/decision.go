package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	ModeHTTP  = "http"
	ModeEnvoy = "envoy"

	SourcePolicy  = "policy"
	SourceEngine  = "engine"
	SourceDefault = "default"
	SourceServer  = "server"
)

var (
	authzRequestDecisionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authz_decisions_total",
			Help: "Total number of authz decisions by mode, outcome, and source.",
		},
		[]string{"mode", "decision", "source"},
	)
	authzDecisionDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "authz_decision_duration_seconds",
			Help: "Duration in seconds for authz decisions by mode and outcome.",
		},
		[]string{"mode", "decision"},
	)
)

func init() {
	ctrlmetrics.Registry.MustRegister(authzRequestDecisionsTotal, authzDecisionDurationSeconds)
}

// RecordAuthzDecision records request-level authz decision count and latency.
func RecordAuthzDecision(mode, decision, source string, start time.Time) {
	authzRequestDecisionsTotal.WithLabelValues(mode, decision, source).Inc()
	authzDecisionDurationSeconds.WithLabelValues(mode, decision).Observe(time.Since(start).Seconds())
}
