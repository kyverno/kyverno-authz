package utils

import (
	"context"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hairyhenderson/go-fsimpl"
	"github.com/hairyhenderson/go-fsimpl/filefs"
	"github.com/hairyhenderson/go-fsimpl/gitfs"
	vpolv1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/kyverno-authz/pkg/engine/sources"
	"github.com/kyverno/kyverno-authz/pkg/utils/ocifs"
	"github.com/kyverno/sdk/core"
	sdksources "github.com/kyverno/sdk/core/sources"
	"go.uber.org/multierr"
)

type staticEntry struct {
	policy     *vpolv1.ValidatingPolicy
	exceptions []*vpolv1.PolicyException
}

type staticSource[POLICY any] struct {
	compiler engine.Compiler[POLICY]
	entries  []staticEntry
}

// we do exception matching during initialization to avoid latency in the http evaluation path
func newStatic[POLICY any](compiler engine.Compiler[POLICY], policies []*vpolv1.ValidatingPolicy, policyExceptions []*vpolv1.PolicyException) *staticSource[POLICY] {
	entries := make([]staticEntry, 0, len(policies))
	for _, p := range policies {
		matchedExceptions := []*vpolv1.PolicyException{}
		for _, ex := range policyExceptions {
			if ex.Spec.EvaluationMode != p.Spec.EvaluationMode() {
				continue
			}
			exceptionMatched := false
			for _, pol := range ex.Spec.PolicyRefs {
				// no need to check for kind here because its already been checked in the filesystem load
				if pol.Name == p.Name {
					exceptionMatched = true
					break
				}
			}
			if exceptionMatched {
				matchedExceptions = append(matchedExceptions, ex)
			}
		}
		entries = append(entries, staticEntry{policy: p, exceptions: matchedExceptions})
	}

	return &staticSource[POLICY]{
		compiler: compiler,
		entries:  entries,
	}
}

// Load compiles every policy, in the order they were loaded. A policy that
// fails to compile is excluded and reported as an engine.CompileError; the
// other policies are still returned.
func (s *staticSource[POLICY]) Load(_ context.Context) ([]POLICY, error) {
	policies := []POLICY{}
	var errs error
	for _, entry := range s.entries {
		policy, err := s.compiler.Compile(entry.policy, entry.exceptions)
		if len(err) > 0 {
			errs = multierr.Append(errs, &engine.CompileError{Policy: entry.policy.Name, Err: err.ToAggregate()})
			continue
		}
		policies = append(policies, policy)
	}
	return policies, errs
}

func GetExternalSources[POLICY any](vpolCompiler engine.Compiler[POLICY], nOpts []name.Option, rOpts []remote.Option, urls ...string) ([]core.Source[POLICY], error) {
	mux := fsimpl.NewMux()
	mux.Add(filefs.FS)
	// mux.Add(httpfs.FS)
	// mux.Add(blobfs.FS)
	mux.Add(gitfs.FS)

	// Create a configured ocifs.FS with registry options
	configuredOCIFS := ocifs.ConfigureOCIFS(nOpts, rOpts)
	mux.Add(configuredOCIFS)

	var providers []core.Source[POLICY]
	for _, url := range urls {
		fsys, err := mux.Lookup(url)
		if err != nil {
			return nil, err
		}
		policies, policyExceptions, err := sources.LoadPolicies(fsys)
		if err != nil {
			return nil, err
		}

		providers = append(
			providers,
			sdksources.NewOnce(newStatic(vpolCompiler, policies, policyExceptions)),
		)
	}
	return providers, nil
}
