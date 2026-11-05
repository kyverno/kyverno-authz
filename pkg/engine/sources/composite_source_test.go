package sources

import (
	"context"
	"fmt"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	v1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/kyverno-authz/apis"
	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/kyverno-authz/pkg/engine/compiler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/dynamic"
)

type countingCompiler struct{ calls int }

func (c *countingCompiler) Compile(p *v1.ValidatingPolicy, exceptions []*v1.PolicyException) (engine.EnvoyPolicy, field.ErrorList) {
	c.calls++
	return compiler.NewCompiler[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse](nil).Compile(p, exceptions)
}

func testPolicy(name string) *v1.ValidatingPolicy {
	return &v1.ValidatingPolicy{ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "1"}, Spec: v1.ValidatingPolicySpec{
		EvaluationConfiguration: &v1.EvaluationConfiguration{Mode: apis.EvaluationModeEnvoy},
		Variables:               []admissionregistrationv1.Variable{{Name: "exempt", Expression: `true`}},
		Validations:             []admissionregistrationv1.Validation{{Expression: `envoy.Denied(403).WithBody("Denied").Response()`}},
	}}
}
func testException(name string) *v1.PolicyException {
	return &v1.PolicyException{ObjectMeta: metav1.ObjectMeta{Name: "exemption", ResourceVersion: "1"}, Spec: v1.PolicyExceptionSpec{
		EvaluationMode: apis.EvaluationModeEnvoy, PolicyRefs: []v1.PolicyRef{{Kind: "ValidatingPolicy", Name: name}},
		MatchConditions: []admissionregistrationv1.MatchCondition{{Name: "exempt", Expression: `variables.exempt`}},
	}}
}

func TestExceptionKindCannotExemptSameNamedPolicy(t *testing.T) {
	for _, exceptionFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(exceptionFirst), func(t *testing.T) {
			ctx := context.Background()
			store := newCompositeStore()
			p := testPolicy("guardrails")
			exc := testException(p.Name)
			exc.Spec.PolicyRefs[0].Kind = "MutatingPolicy"
			if exceptionFirst {
				store.handlePolex("/exemption", exc, false)
			}
			store.handlePolicy("/guardrails", p, false)
			if !exceptionFirst {
				store.handlePolex("/exemption", exc, false)
			}
			cache := newPolicyCache[engine.EnvoyPolicy](store, &countingCompiler{})
			check := func(exempt bool) {
				t.Helper()
				policies, err := cache.Load(ctx)
				require.NoError(t, err)
				require.Len(t, policies, 1)
				result, err := policies[0].Evaluate(ctx, nil, &authv3.CheckRequest{})
				require.NoError(t, err)
				if exempt {
					require.Nil(t, result)
				} else {
					require.NotNil(t, result)
					require.NotNil(t, result.GetDeniedResponse())
				}
			}
			check(false)
			exc.Spec.PolicyRefs[0].Kind = "ValidatingPolicy"
			store.handlePolex("/exemption", exc, false)
			check(true)
			exc.Spec.PolicyRefs[0].Kind = "MutatingPolicy"
			store.handlePolex("/exemption", exc, false)
			check(false)
		})
	}
}

func TestExceptionLifecycleRecompilesPolicy(t *testing.T) {
	ctx := context.Background()
	store := newCompositeStore()
	compiler := &countingCompiler{}
	cache := newPolicyCache[engine.EnvoyPolicy](store, compiler)
	p := testPolicy("guardrails")
	store.handlePolicy("/guardrails", p, false)
	check := func(exempt bool, calls int) {
		t.Helper()
		policies, err := cache.Load(ctx)
		require.NoError(t, err)
		require.Len(t, policies, 1)
		result, err := policies[0].Evaluate(ctx, nil, &authv3.CheckRequest{})
		require.NoError(t, err)
		if exempt {
			assert.Nil(t, result)
		} else {
			require.NotNil(t, result)
			assert.NotNil(t, result.GetDeniedResponse())
		}
		assert.Equal(t, calls, compiler.calls)
	}
	check(false, 1)
	check(false, 1)
	exc := testException("guardrails")
	store.handlePolex("/exemption", exc, false)
	check(true, 2)
	// No resourceVersion change is required: the local counter invalidates the cache.
	exc.Spec.MatchConditions[0].Expression = "false"
	store.handlePolex("/exemption", exc, false)
	check(false, 3)
	exc.Spec.MatchConditions[0].Expression = "variables.exempt"
	store.handlePolex("/exemption", exc, false)
	check(true, 4)
	store.handlePolex("/exemption", nil, true)
	check(false, 5)
}

func TestExceptionReferencesBeforePolicyAndRetargeting(t *testing.T) {
	store := newCompositeStore()
	exc := testException("first")
	store.handlePolex("/exemption", exc, false)
	first, second := testPolicy("first"), testPolicy("second")
	store.handlePolicy("/first", first, false)
	store.handlePolicy("/second", second, false)
	exceptions, err := store.policyExceptions(first)
	require.NoError(t, err)
	require.Len(t, exceptions, 1)
	// Returned exceptions and policies must not expose shared store state.
	exceptions[0].Spec.MatchConditions[0].Expression = "false"
	snapshot, err := store.Load(context.Background())
	require.NoError(t, err)
	snapshot[0].Spec.Validations[0].Expression = "null"
	assert.NotEqual(t, "null", store.policies["first"].policy.Spec.Validations[0].Expression)
	beforeFirst, err := store.keyFunc(context.Background(), first)
	require.NoError(t, err)
	beforeSecond, err := store.keyFunc(context.Background(), second)
	require.NoError(t, err)
	exc.Spec.PolicyRefs[0].Name = "second"
	store.handlePolex("/exemption", exc, false)
	exceptions, err = store.policyExceptions(first)
	require.NoError(t, err)
	assert.Empty(t, exceptions)
	exceptions, err = store.policyExceptions(second)
	require.NoError(t, err)
	require.Len(t, exceptions, 1)
	assert.Equal(t, "variables.exempt", exceptions[0].Spec.MatchConditions[0].Expression)
	afterFirst, err := store.keyFunc(context.Background(), first)
	require.NoError(t, err)
	afterSecond, err := store.keyFunc(context.Background(), second)
	require.NoError(t, err)
	assert.NotEqual(t, beforeFirst, afterFirst)
	assert.NotEqual(t, beforeSecond, afterSecond)
	// Deleting/recreating the policy reconnects its existing exceptions.
	store.handlePolicy("/second", nil, true)
	store.handlePolicy("/second", second, false)
	exceptions, err = store.policyExceptions(second)
	require.NoError(t, err)
	assert.Len(t, exceptions, 1)
	store.handlePolex("/exemption", nil, true)
	exceptions, err = store.policyExceptions(second)
	require.NoError(t, err)
	assert.Empty(t, exceptions)
}

func TestMissingPolicyDoesNotRetainStoreLock(t *testing.T) {
	store := newCompositeStore()
	_, err := store.policyExceptions(testPolicy("missing"))
	require.Error(t, err)
	done := make(chan struct{})
	go func() {
		store.handlePolicy("/guardrails", testPolicy("guardrails"), false)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("store remained locked after missing policy")
	}
}
