package sources

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	v1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
)

type policyState struct {
	policy     v1.ValidatingPolicy
	exceptions map[string]*exceptionState // keyed by polex namespace/name
	maxRV      int64
}

type exceptionState struct {
	exception v1.PolicyException
	// what policies does this exception point to ?
	references map[string]*policyState // keyed by policy namespace/name
}

type compositeStore struct {
	policies   map[string]*policyState    // keyed by policy namespace/name
	exceptions map[string]*exceptionState // keyed by polex namespace/name
}

func newCompositeStore() *compositeStore {
	return &compositeStore{
		policies:   make(map[string]*policyState),
		exceptions: make(map[string]*exceptionState),
	}
}

func (c *compositeStore) Load(_ context.Context) ([]*v1.ValidatingPolicy, error) {
	policies := []*v1.ValidatingPolicy{}
	for _, polState := range c.policies {
		policies = append(policies, &polState.policy)
	}
	return policies, nil
}

func (s *compositeStore) handlePolicy(policyKey string, policy *v1.ValidatingPolicy, isDelete bool) {
	// this store is explicitly for cluster scoped policies for now. we would need to handle this
	// differently if we wanna add support for them in authz. but for now the authz project as a
	// whole works with cluster scoped policies anyway
	policyKey = strings.TrimPrefix("/", policyKey)
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
	if isDelete {
		delete(s.exceptions, excKey)
		for _, polState := range s.policies {
			// deletion should trigger an rv increment as well
			delete(polState.exceptions, excKey)
		}
		return
	}
	excState := &exceptionState{
		exception:  *exc,
		references: map[string]*policyState{},
	}
	rv, _ := strconv.ParseInt(exc.ResourceVersion, 10, 64)
	for _, polRef := range exc.Spec.PolicyRefs {
		if polState, ok := s.policies[polRef.Name]; ok {
			polState.exceptions[excKey] = excState
			excState.references[polRef.Name] = polState
			if rv > polState.maxRV {
				polState.maxRV = rv
			}
		}
	}
}

func (c *compositeStore) keyFunc(_ context.Context, policy *v1.ValidatingPolicy) (string, error) {
	polState, ok := c.policies[policy.Name]
	if !ok {
		return "", fmt.Errorf("attempting to get the cache key for a non existing policy")
	}
	// if resource version is a string why can't we just store it as string not an int
	return policy.Name + policy.ResourceVersion + strconv.Itoa(int(polState.maxRV)), nil
}
