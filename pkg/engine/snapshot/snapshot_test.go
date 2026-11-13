package snapshot

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/kyverno-authz/pkg/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"
)

// fakeSource returns whatever the test sets.
type fakeSource struct {
	mu    sync.Mutex
	data  []string
	err   error
	loads int
}

func (f *fakeSource) set(data []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data, f.err = data, err
}

func (f *fakeSource) Load(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loads++
	return f.data, f.err
}

func (f *fakeSource) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loads
}

func newSyncing(inner *fakeSource, opts Options) (*Source[string], *state.Tracker) {
	tracker := state.NewTracker()
	tracker.Syncing()
	return New[string](inner, tracker, opts), tracker
}

func TestLoad_NotReadyBeforeFirstSnapshot(t *testing.T) {
	src, tracker := newSyncing(&fakeSource{}, Options{})
	data, err := src.Load(context.Background())
	assert.Nil(t, data)
	assert.ErrorIs(t, err, ErrNotReady)
	assert.Nil(t, src.Current())
	assert.Equal(t, state.Syncing, tracker.Phase())
}

func TestRefresh_PublishesSnapshot(t *testing.T) {
	inner := &fakeSource{data: []string{"a", "b"}}
	src, tracker := newSyncing(inner, Options{})
	require.NoError(t, src.Refresh(context.Background()))
	assert.Equal(t, state.Ready, tracker.Phase())
	data, err := src.Load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, data)
	assert.Equal(t, uint64(1), src.Current().Version)

	inner.set([]string{"a"}, nil)
	require.NoError(t, src.Refresh(context.Background()))
	assert.Equal(t, uint64(2), src.Current().Version)
	data, _ = src.Load(context.Background())
	assert.Equal(t, []string{"a"}, data)
}

func TestRefresh_SnapshotIsImmutable(t *testing.T) {
	backing := []string{"a", "b"}
	inner := &fakeSource{data: backing}
	src, _ := newSyncing(inner, Options{})
	require.NoError(t, src.Refresh(context.Background()))
	backing[0] = "mutated"
	data, _ := src.Load(context.Background())
	assert.Equal(t, []string{"a", "b"}, data)
}

func TestRefresh_ExcludesPoliciesThatFailToCompile(t *testing.T) {
	inner := &fakeSource{
		data: []string{"good"},
		err:  &engine.CompileError{Policy: "bad", Err: errors.New("syntax error")},
	}
	src, tracker := newSyncing(inner, Options{})
	require.NoError(t, src.Refresh(context.Background()))
	assert.Equal(t, state.Ready, tracker.Phase())
	assert.Equal(t, []string{"good"}, src.Current().Policies)
	assert.Equal(t, []string{"bad"}, src.Current().Excluded)
}

func TestRefresh_StrictRejectsCompileErrors(t *testing.T) {
	inner := &fakeSource{
		data: []string{"good"},
		err:  &engine.CompileError{Policy: "bad", Err: errors.New("syntax error")},
	}
	src, tracker := newSyncing(inner, Options{Strict: true})
	assert.Error(t, src.Refresh(context.Background()))
	assert.Equal(t, state.Syncing, tracker.Phase())
	assert.Nil(t, src.Current())

	inner.set([]string{"good"}, nil)
	require.NoError(t, src.Refresh(context.Background()))
	assert.Equal(t, state.Ready, tracker.Phase())

	// after the server is ready, strict mode keeps the last known good snapshot
	inner.set([]string{"good", "other"}, &engine.CompileError{Policy: "bad", Err: errors.New("syntax error")})
	assert.Error(t, src.Refresh(context.Background()))
	assert.Equal(t, state.Degraded, tracker.Phase())
	assert.Equal(t, []string{"good"}, src.Current().Policies)
}

func TestRefresh_MinPolicies(t *testing.T) {
	inner := &fakeSource{}
	src, tracker := newSyncing(inner, Options{MinPolicies: 1})
	assert.Error(t, src.Refresh(context.Background()))
	assert.Equal(t, state.Syncing, tracker.Phase())

	inner.set([]string{"a"}, nil)
	require.NoError(t, src.Refresh(context.Background()))
	assert.Equal(t, state.Ready, tracker.Phase())

	inner.set(nil, nil)
	assert.Error(t, src.Refresh(context.Background()))
	assert.Equal(t, state.Degraded, tracker.Phase())
	assert.Equal(t, []string{"a"}, src.Current().Policies)
}

func TestRefresh_KeepsLastKnownGoodOnSourceError(t *testing.T) {
	inner := &fakeSource{data: []string{"a"}}
	src, tracker := newSyncing(inner, Options{})
	require.NoError(t, src.Refresh(context.Background()))

	inner.set([]string{}, multierr.Combine(
		errors.New("registry unreachable"),
		&engine.CompileError{Policy: "bad", Err: errors.New("syntax error")},
	))
	assert.Error(t, src.Refresh(context.Background()))
	assert.Equal(t, state.Degraded, tracker.Phase())
	assert.True(t, tracker.Serving())
	data, err := src.Load(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, []string{"a"}, data)
	assert.Equal(t, uint64(1), src.Current().Version)

	// recovery
	inner.set([]string{"a", "b"}, nil)
	require.NoError(t, src.Refresh(context.Background()))
	assert.Equal(t, state.Ready, tracker.Phase())
	assert.Equal(t, uint64(2), src.Current().Version)
}

func TestRefresh_SourceErrorBeforeReadyStaysSyncing(t *testing.T) {
	inner := &fakeSource{err: errors.New("registry unreachable")}
	src, tracker := newSyncing(inner, Options{})
	assert.Error(t, src.Refresh(context.Background()))
	assert.Equal(t, state.Syncing, tracker.Phase())
	assert.False(t, tracker.Serving())
}

func TestRun_RetriesUntilReadyAndRefreshesOnTrigger(t *testing.T) {
	inner := &fakeSource{err: errors.New("not yet")}
	tracker := state.NewTracker()
	src := New[string](inner, tracker, Options{RetryPeriod: 10 * time.Millisecond, ResyncPeriod: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		src.Run(ctx)
	}()
	assert.Eventually(t, func() bool { return tracker.Phase() == state.Syncing }, time.Second, time.Millisecond)
	inner.set([]string{"a"}, nil)
	assert.Eventually(t, func() bool { return tracker.Phase() == state.Ready }, time.Second, time.Millisecond)

	// with a long resync period, only a trigger refreshes the snapshot
	inner.set([]string{"a", "b"}, nil)
	loads := inner.count()
	src.Trigger()
	assert.Eventually(t, func() bool {
		data, _ := src.Load(ctx)
		return len(data) == 2
	}, time.Second, time.Millisecond)
	assert.Greater(t, inner.count(), loads)

	cancel()
	<-done
}
