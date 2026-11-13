package sources

import (
	"context"

	"github.com/kyverno/sdk/core"
	"go.uber.org/multierr"
)

// NewComposite merges several sources into one.
//
// Unlike the SDK composite source, it keeps the items that a source returns
// together with an error. Sources return partial results with per-policy
// compile errors, and dropping those results would let one bad policy unload
// every other policy from the same source.
func NewComposite[DATA any](sources ...core.Source[DATA]) core.Source[DATA] {
	return core.MakeSourceFunc(func(ctx context.Context) ([]DATA, error) {
		var out []DATA
		var errs error
		for _, source := range sources {
			items, err := source.Load(ctx)
			errs = multierr.Append(errs, err)
			out = append(out, items...)
		}
		return out, errs
	})
}
