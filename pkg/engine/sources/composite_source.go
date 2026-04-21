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
		policies = append(policies, &s.policies[key].policy)
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
		policyState.policy = *policy
		return
	}

	// create: build the policy state and link any exceptions that already reference it
	s.policies[policyKey] = &policyState{
		policy:     *policy,
		exceptions: make(map[string]*exceptionState),
	}
	for excKey, exc := range s.exceptions {
		for _, ref := range exc.exception.Spec.PolicyRefs {
			if ref.Name == policyKey {
				exc.references[policyKey] = s.policies[policyKey]
				s.policies[policyKey].exceptions[excKey] = exc
			}
		}
	}
}

func (s *compositeStore) handlePolex(excKey string, exc *v1.PolicyException, isDelete bool) {
	s.Lock()
	defer s.Unlock()

	if isDelete {
		delete(s.exceptions, excKey)
		for _, polState := range s.policies {
			// increment the polex event counter to that during recomputing the cache
			// we get a different value and recompile the policy with its exceptions
			polState.exceptionEventCounter++
			delete(polState.exceptions, excKey)
		}
		return
	}
	excState := &exceptionState{
		exception:  *exc,
		references: map[string]*policyState{},
	}
	for _, polRef := range exc.Spec.PolicyRefs {
		if polState, ok := s.policies[polRef.Name]; ok {
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
	return policy.Name + policy.ResourceVersion + strconv.Itoa(polState.exceptionEventCounter), nil
}
