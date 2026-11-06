package sources

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/exp/maps"

	v1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
)

type policyState struct {
	policy                v1.ValidatingPolicy
	exceptions            map[string]*exceptionState // keyed by polex namespace/name
	exceptionEventCounter int                        // deletes don't trigger a change in rv. so we rely on our own counter to keep track of polex events
}

type exceptionState struct {
	exception v1.PolicyException
	// what policies does this exception point to ?
	references map[string]*policyState // keyed by policy namespace/name
}

type compositeStore struct {
	sync.Mutex
	policies   map[string]*policyState    // keyed by policy namespace/name
	exceptions map[string]*exceptionState // keyed by polex namespace/name
}

func newCompositeStore() *compositeStore {
	return &compositeStore{
		Mutex:      sync.Mutex{},
		policies:   make(map[string]*policyState),
		exceptions: make(map[string]*exceptionState),
	}
}

func (s *compositeStore) Load(_ context.Context) ([]*v1.ValidatingPolicy, error) {
	s.Lock()
	defer s.Unlock()

	// Collect and sort keys for deterministic iteration
	keys := maps.Keys(s.policies)
	slices.Sort(keys)

	policies := []*v1.ValidatingPolicy{}
	for _, key := range keys {
		policies = append(policies, s.policies[key].policy.DeepCopy())
	}
	return policies, nil
}

func (s *compositeStore) handlePolicy(policyKey string, policy *v1.ValidatingPolicy, isDelete bool) {
	// this store is explicitly for cluster scoped policies for now. we would need to handle this differently
	// if we wanna add support for namespaced policies in authz. but for now the authz project as a whole
	// works with cluster scoped policies anyway
	s.Lock()
	defer s.Unlock()

	policyKey = strings.TrimPrefix(policyKey, "/")
	if isDelete {
		delete(s.policies, policyKey)
		for _, exc := range s.exceptions {
			delete(exc.references, policyKey)
		}
		return
	}

	// update: replace the policy in place
	if policyState, ok := s.policies[policyKey]; ok {
		policyState.policy = *policy.DeepCopy()
		return
	}

	// create: build the policy state and link any exceptions that already reference it
	polState := &policyState{
		policy:     *policy.DeepCopy(),
		exceptions: make(map[string]*exceptionState),
	}

	s.policies[policyKey] = polState
	for excKey, exc := range s.exceptions {
		for _, ref := range exc.exception.Spec.PolicyRefs {
			if ref.Kind == "ValidatingPolicy" && ref.Name == policyKey {
				exc.references[policyKey] = s.policies[policyKey]
				polState.exceptions[excKey] = exc
			}
		}
	}
}

func (s *compositeStore) handlePolex(excKey string, exc *v1.PolicyException, isDelete bool) {
	s.Lock()
	defer s.Unlock()

	// Unlink the previous references first, including references removed by an update.
	if previous, ok := s.exceptions[excKey]; ok {
		for _, polState := range previous.references {
			delete(polState.exceptions, excKey)
			polState.exceptionEventCounter++
		}
		delete(s.exceptions, excKey)
	}
	if isDelete {
		return
	}
	excState := &exceptionState{
		exception:  *exc.DeepCopy(),
		references: map[string]*policyState{},
	}
	// Retain exceptions even when their referenced policies do not exist yet.
	s.exceptions[excKey] = excState
	for _, polRef := range exc.Spec.PolicyRefs {
		if polRef.Kind != "ValidatingPolicy" {
			continue
		}
		polState, ok := s.policies[polRef.Name]
		if ok {
			polState.exceptions[excKey] = excState
			polState.exceptionEventCounter++
			excState.references[polRef.Name] = polState
		}
	}
}

func (s *compositeStore) keyFunc(_ context.Context, policy *v1.ValidatingPolicy) (string, error) {
	s.Lock()
	defer s.Unlock()

	polState, ok := s.policies[policy.Name]
	if !ok {
		return "", fmt.Errorf("attempting to get the cache key for a non existing policy")
	}
	return policy.Name + ":" + policy.ResourceVersion + ":" + strconv.Itoa(polState.exceptionEventCounter), nil
}

// policyExceptions snapshots exceptions under the lock; compilation must not hold it.
func (s *compositeStore) policyExceptions(policy *v1.ValidatingPolicy) ([]*v1.PolicyException, error) {
	s.Lock()
	defer s.Unlock()
	state, ok := s.policies[policy.Name]
	if !ok {
		return nil, fmt.Errorf("attempting to fetch and compile a policy that doesn't exist")
	}
	exceptions := make([]*v1.PolicyException, 0, len(state.exceptions))
	for _, exc := range state.exceptions {
		if exc.exception.Spec.EvaluationMode == policy.Spec.EvaluationMode() {
			exceptions = append(exceptions, exc.exception.DeepCopy())
		}
	}
	return exceptions, nil
}
