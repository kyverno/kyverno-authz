package sources

import (
	"context"
	"fmt"

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

	// we still need a way to load from the datastore when theres a need to recompute a cache key
	cache := sources.NewCache(
		compositeStore,
		compositeStore.keyFunc,
		func(ctx context.Context, _ string, in *v1.ValidatingPolicy) (POLICY, error) {
			var zero POLICY
			exceptions := []*v1.PolicyException{}
			// we need to pass the name and the namespace in the key lookup because the predicate
			// gets called with the reconcile key which is namespace/name. this would also allow us
			// to more easily integrate namespaced policies later
			polState, ok := compositeStore.policies[in.Name]
			if !ok {
				return zero, fmt.Errorf("attempting to fetch and compile a policy that doesn't exist")
			}
			for _, exc := range polState.exceptions {
				if exc.exception.Spec.EvaluationMode != in.Spec.EvaluationMode() {
					continue
				}
				exceptions = append(exceptions, &exc.exception)
			}
			policy, err := compiler.Compile(in, exceptions)
			return policy, err.ToAggregate()
		},
	)
	return cache, nil
}
