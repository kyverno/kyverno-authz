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
)

type staticSource[POLICY any] struct {
	compiler  engine.Compiler[POLICY]
	policyMap map[*vpolv1.ValidatingPolicy][]*vpolv1.PolicyException
}

// we do exception matching during initialization to avoid latency in the http evaluation path
func newStatic[POLICY any](compiler engine.Compiler[POLICY], policies []*vpolv1.ValidatingPolicy, policyExceptions []*vpolv1.PolicyException) *staticSource[POLICY] {
	policyMap := make(map[*vpolv1.ValidatingPolicy][]*vpolv1.PolicyException, len(policies))
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
		policyMap[p] = matchedExceptions
	}

	return &staticSource[POLICY]{
		compiler:  compiler,
		policyMap: policyMap,
	}
}

func (s *staticSource[POLICY]) Load(_ context.Context) ([]POLICY, error) {
	policies := []POLICY{}
	for p, polexs := range s.policyMap {
		policy, err := s.compiler.Compile(p, polexs)
		if err != nil {
			return nil, err.ToAggregate()
		}
		policies = append(policies, policy)
	}

	return policies, nil
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
