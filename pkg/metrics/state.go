package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	serverPhase = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "authz_server_phase",
			Help: "Current lifecycle phase of the authz server. The gauge is 1 for the current phase and 0 for all others.",
		},
		[]string{"phase"},
	)
	snapshotVersion = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "authz_policy_snapshot_version",
			Help: "Version of the policy snapshot that the server evaluates requests against.",
		},
	)
	snapshotPolicies = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "authz_policy_snapshot_policies",
			Help: "Number of policies in the current policy snapshot.",
		},
	)
	snapshotTimestamp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "authz_policy_snapshot_timestamp_seconds",
			Help: "Unix time at which the current policy snapshot was published.",
		},
	)
	snapshotRefreshErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "authz_policy_snapshot_refresh_errors_total",
			Help: "Total number of policy snapshot refreshes that failed and kept the last known good snapshot.",
		},
	)
	policyCompileErrors = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "authz_policy_compile_errors",
			Help: "Policies that failed to compile and are excluded from the current policy snapshot. The gauge is 1 for each excluded policy.",
		},
		[]string{"policy"},
	)
)

func init() {
	ctrlmetrics.Registry.MustRegister(
		serverPhase,
		snapshotVersion,
		snapshotPolicies,
		snapshotTimestamp,
		snapshotRefreshErrors,
		policyCompileErrors,
	)
}

// RecordServerPhase sets the phase gauge to 1 for the current phase and 0 for the others.
func RecordServerPhase(current string, all ...string) {
	for _, phase := range all {
		value := 0.0
		if phase == current {
			value = 1
		}
		serverPhase.WithLabelValues(phase).Set(value)
	}
}

// RecordSnapshot records the version, size, and publish time of a policy snapshot.
func RecordSnapshot(version uint64, policies int, createdAt time.Time) {
	snapshotVersion.Set(float64(version))
	snapshotPolicies.Set(float64(policies))
	snapshotTimestamp.Set(float64(createdAt.Unix()))
}

// RecordSnapshotRefreshError counts a failed snapshot refresh.
func RecordSnapshotRefreshError() {
	snapshotRefreshErrors.Inc()
}

// RecordPolicyCompileErrors replaces the set of policies that failed to compile.
func RecordPolicyCompileErrors(policies ...string) {
	policyCompileErrors.Reset()
	for _, policy := range policies {
		policyCompileErrors.WithLabelValues(policy).Set(1)
	}
}
