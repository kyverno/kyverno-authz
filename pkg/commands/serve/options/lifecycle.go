// Package options holds flags shared by the authz server commands.
package options

import (
	"fmt"
	"time"

	"github.com/kyverno/kyverno-authz/pkg/authz"
	"github.com/spf13/pflag"
)

// Lifecycle holds the flags that control readiness, the default decision, and shutdown.
type Lifecycle struct {
	DefaultDecision string
	MinPolicies     int
	Strict          bool
	DrainDelay      time.Duration
	ShutdownTimeout time.Duration
}

// AddFlags registers the lifecycle flags.
func (o *Lifecycle) AddFlags(flags *pflag.FlagSet) {
	flags.StringVar(&o.DefaultDecision, "default-decision", string(authz.DefaultDecisionAllow), "Decision for requests that match no policy (allow or deny)")
	flags.IntVar(&o.MinPolicies, "min-policies", 0, "Minimum number of policies that must load before the server becomes ready")
	flags.BoolVar(&o.Strict, "strict", false, "Stay not ready, or keep the last known good policies, when any policy fails to compile, instead of excluding the failing policies")
	flags.DurationVar(&o.DrainDelay, "drain-delay", 0, "Time to keep serving after a termination signal while readiness fails, so that load balancers stop sending traffic")
	flags.DurationVar(&o.ShutdownTimeout, "shutdown-timeout", 10*time.Second, "Maximum time to wait for in-flight requests during a graceful shutdown")
}

// Validate checks the flag values and returns the parsed default decision.
func (o *Lifecycle) Validate() (authz.DefaultDecision, error) {
	decision, err := authz.ParseDefaultDecision(o.DefaultDecision)
	if err != nil {
		return "", err
	}
	if o.MinPolicies < 0 {
		return "", fmt.Errorf("invalid --min-policies %d, must be zero or greater", o.MinPolicies)
	}
	if o.DrainDelay < 0 {
		return "", fmt.Errorf("invalid --drain-delay %s, must be zero or greater", o.DrainDelay)
	}
	if o.ShutdownTimeout < 0 {
		return "", fmt.Errorf("invalid --shutdown-timeout %s, must be zero or greater", o.ShutdownTimeout)
	}
	return decision, nil
}
