package sources

import (
	"testing"

	v1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestCompositeStore_Seed(t *testing.T) {
	store := newCompositeStore()
	newer := &v1.ValidatingPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", ResourceVersion: "2"}}
	older := &v1.ValidatingPolicy{ObjectMeta: metav1.ObjectMeta{Name: "policy", ResourceVersion: "1"}}
	// a reconcile stored a newer version before the seed ran
	store.handlePolicy("/policy", newer, false)
	store.seedPolicy("/policy", older)
	assert.Equal(t, "2", store.policies["policy"].policy.ResourceVersion)

	// seeding links exceptions to seeded policies
	store.seedPolicy("/other", &v1.ValidatingPolicy{ObjectMeta: metav1.ObjectMeta{Name: "other"}})
	exception := &v1.PolicyException{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "exc"},
		Spec:       v1.PolicyExceptionSpec{PolicyRefs: []v1.PolicyRef{{Name: "other", Kind: "ValidatingPolicy"}}},
	}
	store.seedPolex("ns/exc", exception)
	assert.Contains(t, store.policies["other"].exceptions, "ns/exc")
}
