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
	compiler         engine.Compiler[POLICY]
	policies         []*vpolv1.ValidatingPolicy
	policyExceptions []*vpolv1.PolicyException
}

func (s *staticSource[POLICY]) Load(_ context.Context) ([]POLICY, error) {
	policies := []POLICY{}
	for _, p := range s.policies {
		matchedExceptions := []*vpolv1.PolicyException{}
		for _, ex := range s.policyExceptions {
			if ex.Spec.EvaluationMode != p.Spec.EvaluationMode() {
				continue
			}
			for _, pol := range ex.Spec.PolicyRefs {
				// any api other than validating policy
				if pol.Kind != "ValidatingPolicy" {
					continue
				}
				if pol.Name != p.Name {
					continue
				}
			}
			matchedExceptions = append(matchedExceptions, ex)
		}

		policy, err := s.compiler.Compile(p, matchedExceptions)
		if err != nil {
			return nil, err.ToAggregate()
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

func GetExternalSources[POLICY any](vpolCompiler engine.Compiler[POLICY], nOpts []name.Option, rOpts []remote.Option, urls ...string) ([]core.Source[POLICY], error) {
	// how about we strip away all this sdk bullshit and make it just open the location it get policies and exceptions
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
			sdksources.NewOnce(&staticSource[POLICY]{
				policies:         policies,
				policyExceptions: policyExceptions,
			}),
		)
	}
	return providers, nil
}
