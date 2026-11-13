package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDefaultDecision(t *testing.T) {
	for in, want := range map[string]DefaultDecision{"allow": DefaultDecisionAllow, "Deny": DefaultDecisionDeny} {
		got, err := ParseDefaultDecision(in)
		assert.NoError(t, err)
		assert.Equal(t, want, got)
	}
	_, err := ParseDefaultDecision("maybe")
	assert.Error(t, err)
}
