package metrics

import (
	"context"
	"fmt"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	envoyRequestsMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authz_envoy_server_validating_requests",
			Help: "can be used to track the number of envoy requests",
		},
		[]string{"method", "host", "path", "schema", "status"},
	)
	envoyRequestsErrorMetric = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authz_envoy_server_validating_request_errors",
			Help: "can be used to track the number of envoy request errors",
		},
		[]string{"method", "host", "path", "schema"},
	)
	envoyDurationMetric = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "authz_envoy_server_validating_requests_duration_seconds",
			Help: "can be used to track the latencies (in seconds) associated with the entire envoy request.",
		},
		[]string{"method", "host", "path", "schema", "status"},
	)
)

func init() {
	ctrlmetrics.Registry.MustRegister(envoyRequestsMetric, envoyDurationMetric, envoyRequestsErrorMetric)
}

func RecordEnvoyRequest(ctx context.Context, startTime time.Time, req *authv3.CheckRequest, res *authv3.CheckResponse) {
	method, host, path, scheme := envoyRequestAttributes(req)
	var status string
	if res != nil && res.Status != nil {
		status = fmt.Sprint(res.Status.Code)
	}

	envoyRequestsMetric.WithLabelValues(
		method,
		host,
		path,
		scheme,
		status,
	).Inc()

	defer func() {
		latency := time.Since(startTime).Seconds()

		envoyDurationMetric.WithLabelValues(
			method,
			host,
			path,
			scheme,
			status,
		).Observe(latency)
	}()
}

func RecordEnvoyRequestError(ctx context.Context, req *authv3.CheckRequest, err error) {
	method, host, path, scheme := envoyRequestAttributes(req)
	envoyRequestsErrorMetric.WithLabelValues(
		method,
		host,
		path,
		scheme,
	).Inc()
}

func envoyRequestAttributes(req *authv3.CheckRequest) (method, host, path, scheme string) {
	if req == nil || req.Attributes == nil || req.Attributes.Request == nil || req.Attributes.Request.Http == nil {
		return "", "", "", ""
	}
	http := req.Attributes.Request.Http
	return http.Method, http.Host, http.Path, http.Scheme
}
