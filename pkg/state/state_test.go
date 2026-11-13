package state

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTracker_Lifecycle(t *testing.T) {
	tracker := NewTracker()
	var seen []Phase
	tracker.OnChange(func(p Phase) { seen = append(seen, p) })

	assert.Equal(t, Starting, tracker.Phase())
	assert.False(t, tracker.Serving())

	tracker.Syncing()
	assert.Equal(t, Syncing, tracker.Phase())
	assert.False(t, tracker.Serving())

	// degraded has no effect before the server is ready
	tracker.Degraded("source failed")
	assert.Equal(t, Syncing, tracker.Phase())

	tracker.Ready()
	assert.Equal(t, Ready, tracker.Phase())
	assert.True(t, tracker.Serving())

	tracker.Degraded("source failed")
	assert.Equal(t, Degraded, tracker.Phase())
	assert.Equal(t, "source failed", tracker.Reason())
	assert.True(t, tracker.Serving(), "a degraded server keeps serving the last known good snapshot")

	tracker.Ready()
	assert.Equal(t, Ready, tracker.Phase())
	assert.Empty(t, tracker.Reason())

	tracker.Drain()
	assert.Equal(t, Draining, tracker.Phase())
	assert.False(t, tracker.Serving())

	// draining is terminal
	tracker.Ready()
	tracker.Syncing()
	assert.Equal(t, Draining, tracker.Phase())

	assert.Equal(t, []Phase{Starting, Syncing, Ready, Degraded, Ready, Draining}, seen)
}

func TestTracker_SyncingOnlyFromStarting(t *testing.T) {
	tracker := NewTracker()
	tracker.Ready()
	tracker.Syncing()
	assert.Equal(t, Ready, tracker.Phase())
}

func TestTracker_DrainOnSignal(t *testing.T) {
	tracker := NewTracker()
	tracker.Ready()
	signalCtx, signal := context.WithCancel(context.Background())
	serveCtx, stop := context.WithCancel(context.Background())
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		tracker.DrainOnSignal(signalCtx, serveCtx, 50*time.Millisecond, stop)
	}()
	signal()
	assert.Eventually(t, func() bool { return tracker.Phase() == Draining }, time.Second, time.Millisecond)
	// the serving context stays open during the drain delay
	assert.NoError(t, serveCtx.Err())
	<-done
	assert.Error(t, serveCtx.Err())
}

func TestTracker_DrainOnSignal_ServeContextDone(t *testing.T) {
	tracker := NewTracker()
	tracker.Ready()
	serveCtx, stop := context.WithCancel(context.Background())
	stop()
	tracker.DrainOnSignal(context.Background(), serveCtx, time.Hour, stop)
	assert.Equal(t, Ready, tracker.Phase())
}
