package http

import (
	"time"

	"github.com/kyverno/kyverno-authz/pkg/authz"
)

type Config struct {
	// DefaultDecision applies to requests that match no policy.
	DefaultDecision authz.DefaultDecision
	// Ready reports whether policies are loaded. A nil function means always ready.
	Ready func() bool
	// ShutdownTimeout bounds how long a graceful shutdown waits for in-flight requests.
	ShutdownTimeout  time.Duration
	Address          string
	NestedRequest    bool
	InputExpression  string
	OutputExpression string
	CertFile         string
	KeyFile          string
}
