package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/kyverno/sdk/core"
	sdksources "github.com/kyverno/sdk/core/sources"
	"github.com/stretchr/testify/assert"
	"go.uber.org/multierr"
)

func TestSplitErrors(t *testing.T) {
	ioErr := errors.New("io failure")
	// errors wrapped and aggregated by the SDK cache and composite sources keep their identity
	cache := sdksources.NewCache(
		core.MakeSource("good", "bad"),
		func(_ context.Context, in string) (string, error) { return in, nil },
		func(_ context.Context, key string, _ string) (string, error) {
			if key == "bad" {
				return "", &CompileError{Policy: "bad", Err: errors.New("syntax error")}
			}
			return key, nil
		},
	)
	data, cacheErr := cache.Load(context.Background())
	assert.Equal(t, []string{"good"}, data)
	err := multierr.Append(cacheErr, ioErr)

	compileErrs, otherErrs := SplitErrors(err)
	if assert.Len(t, compileErrs, 1) {
		assert.Equal(t, "bad", compileErrs[0].Policy)
		assert.Contains(t, compileErrs[0].Error(), "syntax error")
	}
	assert.Equal(t, []error{ioErr}, otherErrs)

	compileErrs, otherErrs = SplitErrors(nil)
	assert.Empty(t, compileErrs)
	assert.Empty(t, otherErrs)
}
