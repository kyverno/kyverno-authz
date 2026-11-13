package events

import (
	"context"
	"errors"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/go-logr/logr"
	"github.com/openreports/reports-api/pkg/client/clientset/versioned/fake"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Run with -race: the event loop writes the ring buffer while the flush worker reads it.
func TestOpenreportsConcurrentPushAndFlush(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := fake.NewSimpleClientset()
	interval := time.Microsecond
	handler := NewOpenreportsSubscriber[string](ctx, 8, client.OpenreportsV1alpha1(), &interval, logr.Discard(), "report", "default", "[%s] request %s: %s")
	const events = 200
	for i := 0; i < events; i++ {
		// retry when the event channel is full so every event is recorded
		require.Eventually(t, func() bool {
			sub := handler.(*openreportsEventSubscriber[string])
			if len(sub.eventChan) == cap(sub.eventChan) {
				return false
			}
			handler.Push(ctx, time.Now(), "request", NewResultAccessor(&authv3.CheckResponse{}, nil))
			return true
		}, time.Second, time.Microsecond)
	}
	require.Eventually(t, func() bool {
		report, err := client.OpenreportsV1alpha1().Reports("default").Get(ctx, "report", metav1.GetOptions{})
		return err == nil && report.Summary.Pass+report.Summary.Fail+report.Summary.Error == events && len(report.Results) == 8
	}, 5*time.Second, time.Millisecond)
}

func deniedResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{HttpResponse: &authv3.CheckResponse_DeniedResponse{
		DeniedResponse: &authv3.DeniedHttpResponse{Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden}},
	}}
}

func TestReportResultPolicyAttribution(t *testing.T) {
	subscriber := &openreportsEventSubscriber[string]{msgFormat: "[%s] request %s: %s"}
	report, err := subscriber.newReportResult(time.Now(), "request", NewResultAccessor(deniedResponse(), nil, "bounded"))
	require.NoError(t, err)
	require.Equal(t, "bounded", report.Policy)
	require.Equal(t, "kyverno-authz", report.Source)
	require.Equal(t, "fail", string(report.Result))
	report, err = subscriber.newReportResult(time.Now(), "request", NewResultAccessor(&authv3.CheckResponse{}, nil))
	require.NoError(t, err)
	require.Empty(t, report.Policy)
}

func TestReportsFilter(t *testing.T) {
	allowed := NewResultAccessor(&authv3.CheckResponse{}, nil, "allowed")
	denied := NewResultAccessor(deniedResponse(), nil, "bounded")
	errored := NewResultAccessor(nil, errors.New("evaluation failed"), "broken")
	for _, tc := range []struct {
		filter string
		want   []string
	}{
		{"fail,error", []string{RequestDenied, RequestErrored}},
		{"fail", []string{RequestDenied}},
		{" pass , fail,error,warn,skip", []string{RequestAllowed, RequestDenied, RequestErrored}},
	} {
		t.Run(tc.filter, func(t *testing.T) {
			filter, err := ParseReportsFilter(tc.filter)
			require.NoError(t, err)
			// Without a running event loop, the channel holds exactly the events that pass the filter.
			subscriber := &openreportsEventSubscriber[string]{filter: filter, eventChan: make(chan event[string], 3)}
			for _, result := range []*resultAccessorImpl{allowed, denied, errored} {
				subscriber.Push(context.Background(), time.Now(), "request", result)
			}
			var decisions []string
			for len(subscriber.eventChan) > 0 {
				ev := <-subscriber.eventChan
				decision, _ := ev.res.MustGet()
				decisions = append(decisions, decision)
			}
			require.Equal(t, tc.want, decisions)
		})
	}
	for _, value := range []string{"", "failure", "fail,", "pass;fail"} {
		_, err := ParseReportsFilter(value)
		require.Error(t, err, value)
	}
}

func TestFilteredReportsSkipExcludedResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := fake.NewSimpleClientset()
	filter, err := ParseReportsFilter("fail,error")
	require.NoError(t, err)
	interval := time.Millisecond
	handler := NewOpenreportsSubscriber[string](ctx, 2, client.OpenreportsV1alpha1(), &interval, logr.Discard(), "report", "default", "%[3]s", filter)
	for i := 0; i < 10; i++ {
		handler.Push(ctx, time.Now(), "request", NewResultAccessor(&authv3.CheckResponse{}, nil))
	}
	time.Sleep(20 * time.Millisecond)
	reports, err := client.OpenreportsV1alpha1().Reports("default").List(ctx, metav1.ListOptions{})
	require.NoError(t, err)
	require.Empty(t, reports.Items, "excluded results must not create a report")
	for i := 0; i < 3; i++ {
		handler.Push(ctx, time.Now(), "request", NewResultAccessor(deniedResponse(), nil, "bounded"))
	}
	handler.Push(ctx, time.Now(), "request", NewResultAccessor(nil, errors.New("evaluation failed"), "broken"))
	require.Eventually(t, func() bool {
		report, err := client.OpenreportsV1alpha1().Reports("default").Get(ctx, "report", metav1.GetOptions{})
		return err == nil && report.Summary.Fail == 3 && report.Summary.Error == 1 && report.Summary.Pass == 0 &&
			len(report.Results) == 2 && report.Results[1].Policy == "broken"
	}, time.Second, time.Millisecond)
}
