package events

import (
	"context"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
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
