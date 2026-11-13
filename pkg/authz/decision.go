package authz

import (
	"fmt"
	"strings"
)

// DefaultDecision is the decision for a request that matches no policy.
type DefaultDecision string

const (
	DefaultDecisionAllow DefaultDecision = "allow"
	DefaultDecisionDeny  DefaultDecision = "deny"
)

// NoMatchReason is the reason returned when a request is denied because it matches no policy.
const NoMatchReason = "request denied: no authorization policy matched the request"

// NotReadyReason is the reason returned when a request arrives before policies are loaded.
const NotReadyReason = "authz server is not ready: policies are not loaded"

// ParseDefaultDecision parses an allow or deny value.
func ParseDefaultDecision(value string) (DefaultDecision, error) {
	switch d := DefaultDecision(strings.ToLower(value)); d {
	case DefaultDecisionAllow, DefaultDecisionDeny:
		return d, nil
	default:
		return "", fmt.Errorf("invalid default decision %q, must be %q or %q", value, DefaultDecisionAllow, DefaultDecisionDeny)
	}
}
