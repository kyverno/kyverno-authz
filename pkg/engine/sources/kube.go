package sources

import (
	"context"
	"strconv"
	"strings"

	v1 "github.com/kyverno/api/api/policies.kyverno.io/v1"

	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/core/sources"
	controllerruntime "github.com/kyverno/sdk/extensions/controller-runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

/*
 * this is a leetcode problem lol

 - i need two arrays basically. and to be able to find the index of the policy changed when one policy changes
 - so maybe store a map of policyname to index ?
- and an array of policy execption tracker. and make it also follow the same indexing as the other one
- the length of the exception array and the policy array will be always equal to the size of the map <<<<

- policy creation workflow:

- we don't have a cache entry in the map. create one. append to the array of policies the new policy. create a new empty array of policy exceptions.
- now this policy key is tracked. we store policyname: arrayidx in the map

- policy update workflow:

- check the map of indexes, its there. fetch the policy from the policyb array at that index, replace it

- policy delete workflow:
- this is the tricky bit because the index will not be at the start. but we need to void it. we can keep a map of index to empty struct
voided indices. and when a new creation
happens we can fill one of those indices instead of appending

polex creation workflow:
- find out if its a new polex. (it is in this scenario)
- append the polex arr and get the index. store it in the polex name map
- we check what policies it references. for each policy that it references. read the index of it from the policy name map
- its a policy name that exists. get the polex tracker entry. append the policy exception index to the polexs field
- increment maxrv

there is the corner case of a policy created that is refernced by an exception that previously existed
how to find out if the exception referenced this policy previously ?
what if we had a map of polex name to array of policy name ?


*/

type polexTracker struct {
	maxRV  int
	polexs []int //array of indices into the polexarr
}

type myfunkydatastore struct {
	policyNameMap map[string]int
	policyArray   []v1.ValidatingPolicy
	voidedIndices map[int]struct{} // keep track of indices i had to clear from the policyarray on policy delete

	polexnametopolicies map[string][]string // map of polex name to policy names. the purpose is when a new policy gets created
	// we will look up if there was any exception that referenced it.

	policyToExceptionsArray []polexTracker // an array that should have the same indices as the policy array. it keeps track of the max resource version
	// across all policy exceptions that reference that policy and the indices of those exceptions in the polexarr
	polexNameMap map[string]int
	polexArr     []v1.PolicyException
}

type PolicyState struct {
	Policy     v1.ValidatingPolicy
	Exceptions map[string]*ExceptionState // keyed by polex namespace/name
	MaxRV      int64
}

type ExceptionState struct {
	Exception v1.PolicyException
	// what policies point does this exception point to ?
	References map[string]*PolicyState // keyed by policy namespace/name
}

type Store struct {
	Policies   map[string]*PolicyState    // keyed by policy namespace/name
	Exceptions map[string]*ExceptionState // keyed by polex namespace/name
}

func NewKube[POLICY any](name string, mgr ctrl.Manager, compiler engine.Compiler[POLICY]) (core.Source[POLICY], error) {
	options := controller.Options{
		NeedLeaderElection: ptr.To(false),
	}
	store := &Store{}
	// create a function when the policy exception gets created
	// a function when the policy gets created
	// p1 is a function for policy crud
	p1 := func(requestKey string, policy *v1.ValidatingPolicy, isDelete bool) {
		if isDelete {
			delete(store.Policies, requestKey)
			for _, exc := range store.Exceptions {
				for policyKey, _ := range exc.References {
					if policyKey == requestKey {
						delete(exc.References, requestKey)
					}
				}
			}
		}

		// for an update, we just need to replace the policy in the policystate with the new one
		policyState, ok := store.Policies[requestKey]
		if ok {
			policyState.Policy = *policy
			return
		}

		store.Policies[requestKey] = &PolicyState{
			Policy:     *policy,
			Exceptions: make(map[string]*ExceptionState),
		}
		// check if any existing exception references this policy
		for _, exc := range store.Exceptions {
			for _, ref := range exc.Exception.Spec.PolicyRefs {
				// if the exeception references that policy
				if ref.Name == strings.Split(requestKey, "/")[1] {
					// create the mapping from the exception to the policystate
					exc.References[requestKey] = store.Policies[requestKey]
					// store the mapping from the policy to the exception state pointer
					store.Policies[requestKey].Exceptions[exc.Exception.Namespace+"/"+exc.Exception.Name] = exc
				}
			}
		}
	}

	p2 := func(requestKey string, polex *v1.PolicyException, isDelete bool) {
		if isDelete {
			delete(store.Exceptions, requestKey)
			for _, polState := range store.Policies {
				if _, ok := polState.Exceptions[requestKey]; ok {
					delete(polState.Exceptions, requestKey)
				}
			}
		}

		excState := &ExceptionState{
			Exception:  *polex,
			References: map[string]*PolicyState{},
		}
		for _, polName := range polex.Spec.PolicyRefs {
			// the exception references this policy. make the exceptions field in the policy state store a reference to it
			if polState, ok := store.Policies[polName.Name]; ok {
				polState.Exceptions[requestKey] = excState
				excState.References[polName.Name] = polState
			}
		}
		store.Exceptions[requestKey] = excState
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
	// how does this all tie back to the cache ?

	// we should we recompile ? if the policy changes. or if any of its associated exceptiong change or new ones get added
	// should we just start a watch for exceptions and avoid all of this ?
	// the watch would track all exceptions in a map of policyname to exception.
	// whats a data structure that displays the relation of
	cache := sources.NewCache(
		policyApiSource,
		func(_ context.Context, in *v1.ValidatingPolicy) (string, error) {
			state, ok := store.Policies[in.Namespace+"/"+in.Name]
			if !ok {
				// error
			}
			return in.Name + in.ResourceVersion + strconv.Itoa(int(state.MaxRV)), nil
		},

		func(ctx context.Context, _ string, in *v1.ValidatingPolicy) (POLICY, error) {
			var zero POLICY
			exceptions, excErr := polexApiSource.Load(ctx)
			if err != nil {
				return zero, excErr
			}
			// we need to store policies with their exceptions in a map same as we are doing for the file system
			// and we should update this map when a new exception comes in
			// we also wanna know this fucking cache source when would it do processing and when it would fallback on its "cache"
			// since resource version is part of the cache key then if the resource gets updated and computing its key would result in something new
			// this also means that exceptions getting deleted or updated has no effect here since the policy will stay the same. so we wont call the cache func
			// hence not get any exceptions
			// this also applies to a policy that was evaluated once before the exception was created

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
