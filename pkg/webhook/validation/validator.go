package validation

import (
	"context"

	vpolv1beta1 "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func NewValidator(compileVpol func(*vpolv1beta1.ValidatingPolicy) field.ErrorList) *validator {
	return &validator{
		compileVpol: compileVpol,
	}
}

type validator struct {
	compileVpol func(*vpolv1beta1.ValidatingPolicy) field.ErrorList
}

func (v *validator) ValidateCreate(ctx context.Context, obj *vpolv1beta1.ValidatingPolicy) (admission.Warnings, error) {
	return nil, v.validateVpol(obj)
}

func (v *validator) ValidateUpdate(ctx context.Context, oldObj, newObj *vpolv1beta1.ValidatingPolicy) (admission.Warnings, error) {
	return nil, v.validateVpol(newObj)
}

func (*validator) ValidateDelete(ctx context.Context, obj *vpolv1beta1.ValidatingPolicy) (admission.Warnings, error) {
	return nil, nil
}

func (v *validator) validateVpol(policy *vpolv1beta1.ValidatingPolicy) error {
	if allErrs := v.compileVpol(policy); len(allErrs) > 0 {
		return apierrors.NewInvalid(
			vpolv1beta1.SchemeGroupVersion.WithKind("ValidatingPolicy").GroupKind(),
			policy.Name,
			allErrs,
		)
	}
	return nil
}
