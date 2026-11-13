package engine

import (
	"errors"
	"fmt"

	"go.uber.org/multierr"
)

// CompileError reports that a single policy failed to compile.
// Sources return it, aggregated with multierr, for each policy they exclude,
// so that one bad policy doesn't prevent the others from loading.
type CompileError struct {
	Policy string
	Err    error
}

func (e *CompileError) Error() string {
	return fmt.Sprintf("failed to compile policy %s: %v", e.Policy, e.Err)
}

func (e *CompileError) Unwrap() error {
	return e.Err
}

// SplitErrors separates per-policy compile errors from other source errors.
func SplitErrors(err error) ([]*CompileError, []error) {
	var compileErrs []*CompileError
	var otherErrs []error
	for _, err := range multierr.Errors(err) {
		var compileErr *CompileError
		if errors.As(err, &compileErr) {
			compileErrs = append(compileErrs, compileErr)
		} else {
			otherErrs = append(otherErrs, err)
		}
	}
	return compileErrs, otherErrs
}
