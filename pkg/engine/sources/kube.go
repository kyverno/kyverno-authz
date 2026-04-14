package sources

import (
	"context"

	v1 "github.com/kyverno/api/api/policies.kyverno.io/v1"

	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/core/sources"
	controllerruntime "github.com/kyverno/sdk/extensions/controller-runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

func NewKube[POLICY any](name string, mgr ctrl.Manager, compiler engine.Compiler[POLICY]) (core.Source[POLICY], error) {
	options := controller.Options{
		NeedLeaderElection: ptr.To(false),
	}
	policyApiSource, err := controllerruntime.NewApiSource[v1.ValidatingPolicy](name, mgr, options)
	if err != nil {
		return nil, err
	}

	// will an api source just store instances of that api or no ?
	polexApiSource, err := controllerruntime.NewApiSource[v1.PolicyException](name, mgr, options)
	if err != nil {
		return nil, err
	}

	cache := sources.NewCache(
		policyApiSource,
		func(_ context.Context, in *v1.ValidatingPolicy) (string, error) {
			return in.Name + in.ResourceVersion, nil
		},

		func(ctx context.Context, _ string, in *v1.ValidatingPolicy) (POLICY, error) {
			var zero POLICY
			exceptions, excErr := polexApiSource.Load(ctx)
			if err != nil {
				return zero, excErr
			}

			matchedExceptions := []*v1.PolicyException{}
			for _, ex := range exceptions {
				if ex.Spec.EvaluationMode != in.Spec.EvaluationMode() {
					continue
				}
				for _, pol := range ex.Spec.PolicyRefs {
					// any api other than validating policy
					if pol.Kind != "ValidatingPolicy" {
						continue
					}
					if pol.Name != in.Name {
						continue
					}
				}
				matchedExceptions = append(matchedExceptions, ex)
			}

			policy, err := compiler.Compile(in, exceptions)
			return policy, err.ToAggregate()
		},
	)
	return cache, nil
}
