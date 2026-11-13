package sources

import (
	"context"
	"errors"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
)

func TestNewComposite_KeepsPartialResults(t *testing.T) {
	partialErr := errors.New("one policy failed")
	src := NewComposite(
		core.MakeSource(1, 2),
		core.MakeSourceFunc(func(context.Context) ([]int, error) { return []int{3}, partialErr }),
		core.MakeSource(4),
	)
	data, err := src.Load(context.Background())
	assert.Equal(t, []int{1, 2, 3, 4}, data)
	assert.ErrorIs(t, err, partialErr)
}
