package sources

import (
	"context"
	"fmt"

	v1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/core/sources"
	controllerruntime "github.com/kyverno/sdk/extensions/controller-runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

// Kube is a policy source backed by ValidatingPolicy and PolicyException
// resources in the cluster.
type Kube[POLICY any] struct {
	core.Source[POLICY]
	store  *compositeStore
	reader client.Reader
}

// NewKube registers controllers for policies and exceptions with mgr and
// returns a source that compiles them. Each onChange callback runs after
// every policy or exception event.
func NewKube[POLICY any](name string, mgr ctrl.Manager, compiler engine.Compiler[POLICY], onChange ...func()) (*Kube[POLICY], error) {
	options := controller.Options{
		NeedLeaderElection: ptr.To(false),
	}

	compositeStore := newCompositeStore()
	notify := func() {
		for _, f := range onChange {
			f()
		}
	}

	// we don't the instances of the api source. we only want to register them with the manager so they
	// would start reconciling and calling the predicate
	_, err := controllerruntime.NewApiWithPredicate(name+"-vpol", mgr, options, func(key string, policy *v1.ValidatingPolicy, isDelete bool) {
		compositeStore.handlePolicy(key, policy, isDelete)
		notify()
	})
	if err != nil {
		return nil, err
	}

	_, err = controllerruntime.NewApiWithPredicate(name+"-polex", mgr, options, func(key string, exception *v1.PolicyException, isDelete bool) {
		compositeStore.handlePolex(key, exception, isDelete)
		notify()
	})
	if err != nil {
		return nil, err
	}

	return &Kube[POLICY]{
		Source: newPolicyCache(compositeStore, compiler),
		store:  compositeStore,
		reader: mgr.GetClient(),
	}, nil
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
			if len(errs) > 0 {
				// report the failure for this policy only, so that the other policies still load
				return zero, &engine.CompileError{Policy: in.Name, Err: errs.ToAggregate()}
			}
			return policy, nil
		},
	)
}

// Sync seeds the source with every policy and exception in the informer cache.
//
// The informer cache can be synced before the controllers have reconciled
// every object, so a source that only relies on reconciles can be empty right
// after startup. Call Sync after the cache has synced and before you mark the
// server ready. Objects that a reconcile already stored are left untouched.
func (k *Kube[POLICY]) Sync(ctx context.Context) error {
	var policies v1.ValidatingPolicyList
	if err := k.reader.List(ctx, &policies); err != nil {
		return fmt.Errorf("failed to list policies: %w", err)
	}
	var exceptions v1.PolicyExceptionList
	if err := k.reader.List(ctx, &exceptions); err != nil {
		return fmt.Errorf("failed to list policy exceptions: %w", err)
	}
	// seed policies first, so that exceptions can link to them
	for i := range policies.Items {
		policy := &policies.Items[i]
		k.store.seedPolicy(types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}.String(), policy)
	}
	for i := range exceptions.Items {
		exception := &exceptions.Items[i]
		k.store.seedPolex(types.NamespacedName{Namespace: exception.Namespace, Name: exception.Name}.String(), exception)
	}
	return nil
}
