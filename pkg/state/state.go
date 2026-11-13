// Package state tracks the lifecycle of an authz server.
//
// The server moves through the following phases:
//
//	Starting ──► Syncing ──► Ready ──► Draining
//	                           │  ▲
//	                           ▼  │
//	                         Degraded
//
// The server only evaluates authorization requests in the Ready and Degraded
// phases. In every other phase, it rejects requests so that the gateway's
// failure mode applies.
package state

import (
	"context"
	"sync"
	"time"

	"github.com/kyverno/kyverno-authz/pkg/metrics"
	ctrl "sigs.k8s.io/controller-runtime"
)

type Phase string

const (
	// Starting means the server process is up but has not started loading policies.
	Starting Phase = "Starting"
	// Syncing means the server is loading policies from its sources for the first time.
	Syncing Phase = "Syncing"
	// Ready means every source has completed its first load and a policy snapshot is published.
	Ready Phase = "Ready"
	// Degraded means a source failed after the server was ready.
	// The server keeps serving the last known good policy snapshot.
	Degraded Phase = "Degraded"
	// Draining means the server received a termination signal and is shutting down.
	Draining Phase = "Draining"
)

var phases = []string{string(Starting), string(Syncing), string(Ready), string(Degraded), string(Draining)}

// Tracker holds the current lifecycle phase. It is safe for concurrent use.
type Tracker struct {
	mu        sync.RWMutex
	phase     Phase
	reason    string
	listeners []func(Phase)
}

// NewTracker returns a tracker in the Starting phase.
func NewTracker() *Tracker {
	t := &Tracker{phase: Starting}
	metrics.RecordServerPhase(string(Starting), phases...)
	return t
}

// Phase returns the current phase.
func (t *Tracker) Phase() Phase {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.phase
}

// Reason returns a human-readable reason for the current phase, if any.
func (t *Tracker) Reason() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.reason
}

// Serving reports whether the server evaluates authorization requests.
// It is true in the Ready and Degraded phases.
func (t *Tracker) Serving() bool {
	switch t.Phase() {
	case Ready, Degraded:
		return true
	default:
		return false
	}
}

// OnChange registers a callback that runs after every phase change, and once
// immediately with the current phase.
func (t *Tracker) OnChange(f func(Phase)) {
	t.mu.Lock()
	t.listeners = append(t.listeners, f)
	phase := t.phase
	t.mu.Unlock()
	f(phase)
}

// Syncing moves the server from Starting to Syncing.
func (t *Tracker) Syncing() {
	t.transition(Syncing, "", Starting)
}

// Ready moves the server to Ready from Syncing or Degraded.
func (t *Tracker) Ready() {
	t.transition(Ready, "", Starting, Syncing, Degraded)
}

// Degraded moves the server from Ready to Degraded. It has no effect before
// the server is ready, because there is no snapshot to fall back on.
func (t *Tracker) Degraded(reason string) {
	t.transition(Degraded, reason, Ready, Degraded)
}

// Drain moves the server to Draining. Draining is terminal.
func (t *Tracker) Drain() {
	t.transition(Draining, "", Starting, Syncing, Ready, Degraded)
}

func (t *Tracker) transition(to Phase, reason string, from ...Phase) {
	t.mu.Lock()
	allowed := false
	for _, f := range from {
		if t.phase == f {
			allowed = true
			break
		}
	}
	if !allowed || (t.phase == to && t.reason == reason) {
		t.mu.Unlock()
		return
	}
	t.phase = to
	t.reason = reason
	listeners := append([]func(Phase){}, t.listeners...)
	t.mu.Unlock()
	metrics.RecordServerPhase(string(to), phases...)
	for _, f := range listeners {
		f(to)
	}
}

// DrainOnSignal waits until signalCtx is done, moves the server to Draining,
// waits for delay so that load balancers observe the failing readiness probe,
// and then calls stop. It returns early without draining if serveCtx is done
// first.
func (t *Tracker) DrainOnSignal(signalCtx, serveCtx context.Context, delay time.Duration, stop context.CancelFunc) {
	select {
	case <-serveCtx.Done():
		return
	case <-signalCtx.Done():
	}
	logger := ctrl.LoggerFrom(serveCtx)
	t.Drain()
	logger.Info("Termination signal received, draining", "delay", delay)
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-serveCtx.Done():
		}
	}
	stop()
}
