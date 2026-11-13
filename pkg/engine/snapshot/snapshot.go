// Package snapshot provides a policy source that serves immutable, versioned
// snapshots of an inner source.
//
// The inner source is loaded in the background, never on the request path.
// Each successful load is published as a new snapshot and swapped in
// atomically, so a request always evaluates against one consistent set of
// policies. When a later load fails, the last known good snapshot stays in
// place and the server moves to the Degraded phase.
package snapshot

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/kyverno-authz/pkg/metrics"
	"github.com/kyverno/kyverno-authz/pkg/state"
	"github.com/kyverno/sdk/core"
	"go.uber.org/multierr"
	ctrl "sigs.k8s.io/controller-runtime"
)

// ErrNotReady is returned by Load before the first snapshot is published.
var ErrNotReady = errors.New("policies are not loaded yet")

const (
	defaultRetryPeriod  = time.Second
	defaultResyncPeriod = 30 * time.Second
)

// Snapshot is an immutable set of compiled policies.
type Snapshot[POLICY any] struct {
	// Version increases by one for every published snapshot.
	Version uint64
	// Policies holds the compiled policies. Don't modify it.
	Policies []POLICY
	// Excluded lists the policies that failed to compile and are not part of the snapshot.
	Excluded []string
	// CreatedAt is the time the snapshot was published.
	CreatedAt time.Time
}

// Options configure when a load is published as a snapshot.
type Options struct {
	// MinPolicies is the minimum number of policies a load must contain to be published.
	MinPolicies int
	// Strict prevents publishing a load in which any policy failed to compile.
	Strict bool
	// RetryPeriod is how often to retry loading before the first snapshot is published.
	RetryPeriod time.Duration
	// ResyncPeriod is how often to reload after the first snapshot is published,
	// in addition to the reloads requested with Trigger.
	ResyncPeriod time.Duration
}

// Source serves the current snapshot of an inner source.
type Source[POLICY any] struct {
	inner   core.Source[POLICY]
	tracker *state.Tracker
	opts    Options
	current atomic.Pointer[Snapshot[POLICY]]
	trigger chan struct{}
	mu      sync.Mutex // serializes Refresh
	// excluded holds the policies that failed to compile in the previous refresh.
	excluded map[string]struct{}
}

// New returns a snapshot source for inner that reports its state to tracker.
func New[POLICY any](inner core.Source[POLICY], tracker *state.Tracker, opts Options) *Source[POLICY] {
	if opts.RetryPeriod <= 0 {
		opts.RetryPeriod = defaultRetryPeriod
	}
	if opts.ResyncPeriod <= 0 {
		opts.ResyncPeriod = defaultResyncPeriod
	}
	return &Source[POLICY]{
		inner:   inner,
		tracker: tracker,
		opts:    opts,
		trigger: make(chan struct{}, 1),
	}
}

// Load implements core.Source. It returns the policies of the current
// snapshot, or ErrNotReady if no snapshot is published yet.
func (s *Source[POLICY]) Load(_ context.Context) ([]POLICY, error) {
	snapshot := s.current.Load()
	if snapshot == nil {
		return nil, ErrNotReady
	}
	return snapshot.Policies, nil
}

// Current returns the current snapshot, or nil if none is published yet.
func (s *Source[POLICY]) Current() *Snapshot[POLICY] {
	return s.current.Load()
}

// Trigger requests a refresh. It never blocks.
func (s *Source[POLICY]) Trigger() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// Refresh loads the inner source and publishes a new snapshot if the load is
// acceptable. It returns an error when the load is rejected, in which case the
// previous snapshot, if any, stays in place.
func (s *Source[POLICY]) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	logger := ctrl.LoggerFrom(ctx)
	policies, err := s.inner.Load(ctx)
	compileErrs, otherErrs := engine.SplitErrors(err)
	excluded := make([]string, 0, len(compileErrs))
	excludedSet := make(map[string]struct{}, len(compileErrs))
	for _, compileErr := range compileErrs {
		excluded = append(excluded, compileErr.Policy)
		excludedSet[compileErr.Policy] = struct{}{}
		// log each failure once, not on every refresh
		if _, seen := s.excluded[compileErr.Policy]; !seen {
			logger.Error(compileErr.Err, "Policy failed to compile and is excluded", "policy", compileErr.Policy)
		}
	}
	s.excluded = excludedSet
	sort.Strings(excluded)
	metrics.RecordPolicyCompileErrors(excluded...)
	var reject error
	switch {
	case len(otherErrs) > 0:
		reject = fmt.Errorf("failed to load policies: %w", multierr.Combine(otherErrs...))
	case s.opts.Strict && len(compileErrs) > 0:
		reject = fmt.Errorf("%d policies failed to compile and strict mode is enabled", len(compileErrs))
	case len(policies) < s.opts.MinPolicies:
		reject = fmt.Errorf("loaded %d policies, fewer than the required minimum of %d", len(policies), s.opts.MinPolicies)
	}
	if reject != nil {
		metrics.RecordSnapshotRefreshError()
		s.tracker.Degraded(reject.Error())
		return reject
	}
	var version uint64 = 1
	if previous := s.current.Load(); previous != nil {
		version = previous.Version + 1
	}
	snapshot := &Snapshot[POLICY]{
		Version:   version,
		Policies:  append([]POLICY(nil), policies...),
		Excluded:  excluded,
		CreatedAt: time.Now(),
	}
	s.current.Store(snapshot)
	metrics.RecordSnapshot(snapshot.Version, len(snapshot.Policies), snapshot.CreatedAt)
	if s.tracker.Phase() != state.Ready {
		logger.Info("Policy snapshot published", "version", snapshot.Version, "policies", len(snapshot.Policies), "excluded", len(excluded))
	}
	s.tracker.Ready()
	return nil
}

// Run refreshes the snapshot until ctx is done. Before the first snapshot is
// published, it retries every RetryPeriod. After that, it refreshes on every
// Trigger and every ResyncPeriod.
func (s *Source[POLICY]) Run(ctx context.Context) {
	logger := ctrl.LoggerFrom(ctx)
	s.tracker.Syncing()
	refresh := func() {
		if err := s.Refresh(ctx); err != nil {
			if s.current.Load() == nil {
				logger.Info("Waiting for policies", "reason", err.Error())
			} else {
				logger.Error(err, "Policy refresh failed, serving the last known good snapshot", "version", s.current.Load().Version)
			}
		}
	}
	refresh()
	for {
		period := s.opts.ResyncPeriod
		if s.current.Load() == nil {
			period = s.opts.RetryPeriod
		}
		timer := time.NewTimer(period)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-s.trigger:
			timer.Stop()
		case <-timer.C:
		}
		refresh()
	}
}
