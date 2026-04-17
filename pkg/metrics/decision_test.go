package metrics

import (
	"context"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	httpcel "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
)

func TestRecordAuthzDecision(t *testing.T) {
	authzRequestDecisionsTotal.Reset()
	authzDecisionDurationSeconds.Reset()

	start := time.Now().Add(-1500 * time.Millisecond)
	RecordAuthzDecision(ModeHTTP, DecisionAllow, SourcePolicy, start)

	counter := testutil.ToFloat64(authzRequestDecisionsTotal.WithLabelValues(ModeHTTP, DecisionAllow, SourcePolicy))
	assert.Equal(t, 1.0, counter)

	obs, err := authzDecisionDurationSeconds.GetMetricWithLabelValues(ModeHTTP, DecisionAllow)
	assert.NoError(t, err)
	sum, count := histogramSample(obs.(prometheus.Histogram))
	assert.Equal(t, uint64(1), count)
	assert.Greater(t, sum, 1.0)
	assert.Less(t, sum, 10.0)
}

func TestRecordHTTPRequest_UsesSecondsForDuration(t *testing.T) {
	httpRequestsMetric.Reset()
	httpDurationMetric.Reset()
	httpRequestsErrorMetric.Reset()

	req := httpcel.CheckRequest{
		Attributes: httpcel.CheckRequestAttributes{
			Method: "GET",
			Host:   "example.com",
			Path:   "/healthz",
			Scheme: "http",
		},
	}
	res := &httpcel.CheckResponse{Ok: &httpcel.CheckResponseOk{}}

	start := time.Now().Add(-2 * time.Second)
	RecordHTTPRequest(context.Background(), start, req, res)

	obs, err := httpDurationMetric.GetMetricWithLabelValues("GET", "example.com", "/healthz", "http", "ok")
	assert.NoError(t, err)
	sum, count := histogramSample(obs.(prometheus.Histogram))
	assert.Equal(t, uint64(1), count)
	assert.Greater(t, sum, 1.0)
	assert.Less(t, sum, 10.0)
}

func TestRecordEnvoyRequest_UsesSecondsAndHandlesNil(t *testing.T) {
	envoyRequestsMetric.Reset()
	envoyDurationMetric.Reset()
	envoyRequestsErrorMetric.Reset()

	assert.NotPanics(t, func() {
		RecordEnvoyRequest(context.Background(), time.Now().Add(-500*time.Millisecond), nil, nil)
		RecordEnvoyRequestError(context.Background(), nil, assert.AnError)
	})

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Host:   "example.com",
					Path:   "/allow",
					Scheme: "http",
				},
			},
		},
	}
	res := &authv3.CheckResponse{}
	start := time.Now().Add(-2200 * time.Millisecond)
	RecordEnvoyRequest(context.Background(), start, req, res)

	obs, err := envoyDurationMetric.GetMetricWithLabelValues("GET", "example.com", "/allow", "http", "")
	assert.NoError(t, err)
	sum, count := histogramSample(obs.(prometheus.Histogram))
	assert.Equal(t, uint64(1), count)
	assert.Greater(t, sum, 1.0)
	assert.Less(t, sum, 10.0)
}

func histogramSample(hist prometheus.Histogram) (sum float64, count uint64) {
	m := &dto.Metric{}
	if err := hist.Write(m); err != nil {
		return 0, 0
	}
	h := m.GetHistogram()
	if h == nil {
		return 0, 0
	}
	return h.GetSampleSum(), h.GetSampleCount()
}
