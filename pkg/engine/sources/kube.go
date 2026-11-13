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

	compositeStore := newCompositeStore()

	// we don't the instances of the api source. we only want to register them with the manager so they
	// would start reconciling and calling the predicate
	_, err := controllerruntime.NewApiWithPredicate[v1.ValidatingPolicy](name+"-vpol", mgr, options, compositeStore.handlePolicy)
	if err != nil {
		return nil, err
	}

	_, err = controllerruntime.NewApiWithPredicate[v1.PolicyException](name+"-polex", mgr, options, compositeStore.handlePolex)
	if err != nil {
		return nil, err
	}

	return newPolicyCache(compositeStore, compiler), nil
}

func newPolicyCache[POLICY any](compositeStore *compositeStore, compiler engine.Compiler[POLICY]) core.Source[POLICY] {
	return sources.NewCache(
		compositeStore,
		compositeStore.keyFunc,
		func(ctx context.Context, _ string, in *v1.ValidatingPolicy) (POLICY, error) {
			var zero POLICY
			exceptions, err := compositeStore.policyExceptions(in)
			if err != nil {
				return zero, err
			}
			policy, errs := compiler.Compile(in, exceptions)
			return policy, errs.ToAggregate()
		},
	)
}
