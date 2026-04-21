package compiler

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	v1 "github.com/kyverno/api/api/policies.kyverno.io/v1"
	"github.com/kyverno/kyverno-authz/apis"
	authzcel "github.com/kyverno/kyverno-authz/pkg/cel"
	envoy "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/envoy"
	httpauth "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
	"github.com/kyverno/sdk/cel/libs/http"
	"github.com/kyverno/sdk/cel/libs/imagedata"
	"github.com/kyverno/sdk/cel/libs/resource"
	"github.com/kyverno/sdk/extensions/policy"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/dynamic"
	"k8s.io/klog/v2"
)

const (
	HttpKey      = "http"
	ImageDataKey = "image"
	ObjectKey    = "object"
	VariablesKey = "variables"
	ResourceKey  = "resource"
)

func NewCompiler[DATA dynamic.Interface, IN, OUT any](client DATA) *compiler[DATA, IN, OUT] {
	return &compiler[DATA, IN, OUT]{
		client: client,
	}
}

type compiler[DATA dynamic.Interface, IN, OUT any] struct {
	client DATA
}

// exceptions that are passed here are guaranteed to be matching the policy. they are filtered in the kube policy source
func (c *compiler[DATA, IN, OUT]) Compile(policy *v1.ValidatingPolicy, exceptions []*v1.PolicyException) (policy.Policy[DATA, IN, OUT], field.ErrorList) {
	cp, err := c.compile(policy, exceptions)
	if err != nil {
		// the behavior of the sdk is to ignore compile errors and continue
		// trying to evaluate the payload against any of the valid policies
		// which makes compile errors not appear in any meaningful way unless
		// they get caught by the webhook
		klog.Error("error compiling policy:", err.ToAggregate().Error())
		return compiledPolicy[DATA, IN, OUT]{}, err
	}

	if policy.Spec.FailurePolicy == nil {
		cp.failurePolicy = admissionregistrationv1.Fail
	} else {
		cp.failurePolicy = *policy.Spec.FailurePolicy
	}
	return *cp, err
}

func (c *compiler[DATA, IN, OUT]) compile(policy *v1.ValidatingPolicy, exceptions []*v1.PolicyException) (
	*compiledPolicy[DATA, IN, OUT], field.ErrorList) {
	var allErrs field.ErrorList
	base, err := authzcel.NewEnv(policy.Spec.EvaluationMode(), c.client)
	if err != nil {
		return nil, append(allErrs, field.InternalError(nil, err))
	}
	var objectKey cel.EnvOption
	switch policy.Spec.EvaluationMode() {
	case apis.EvaluationModeEnvoy:
		objectKey = cel.Variable(ObjectKey, envoy.CheckRequest)
	case apis.EvaluationModeHTTP:
		objectKey = cel.Variable(ObjectKey, httpauth.RequestType)
	default:
		return nil, append(allErrs, field.InternalError(nil, fmt.Errorf("invalid policy evaluation mode: %s", policy.Spec.EvaluationMode())))
	}
	provider := authzcel.NewVariablesProvider(base.CELTypeProvider())
	env, err := base.Extend(
		cel.Variable(HttpKey, http.ContextType),
		cel.Variable(ImageDataKey, imagedata.ContextType),
		objectKey,
		cel.Variable(VariablesKey, authzcel.VariablesType),
		cel.Variable(ResourceKey, resource.ContextType),
		cel.CustomTypeProvider(provider),
	)
	if err != nil {
		return nil, append(allErrs, field.InternalError(nil, err))
	}
	path := field.NewPath("spec")
	matchConditions := make([]cel.Program, 0, len(policy.Spec.MatchConditions))
	{
		path := path.Child("matchConditions")
		for i, matchCondition := range policy.Spec.MatchConditions {
			path := path.Index(i).Child("expression")
			ast, issues := env.Compile(matchCondition.Expression)
			if err := issues.Err(); err != nil {
				return nil, append(allErrs, field.Invalid(path, matchCondition.Expression, err.Error()))
			}
			if !ast.OutputType().IsExactType(types.BoolType) {
				return nil, append(allErrs, field.Invalid(path, matchCondition.Expression, "matchCondition output is expected to be of type bool"))
			}
			prog, err := env.Program(ast)
			if err != nil {
				return nil, append(allErrs, field.Invalid(path, matchCondition.Expression, err.Error()))
			}
			matchConditions = append(matchConditions, prog)
		}
	}
	variables := map[string]cel.Program{}
	{
		path := path.Child("variables")
		for i, variable := range policy.Spec.Variables {
			path := path.Index(i).Child("expression")
			ast, issues := env.Compile(variable.Expression)
			if err := issues.Err(); err != nil {
				return nil, append(allErrs, field.Invalid(path, variable.Expression, err.Error()))
			}
			provider.RegisterField(variable.Name, ast.OutputType())
			prog, err := env.Program(ast)
			if err != nil {
				return nil, append(allErrs, field.Invalid(path, variable.Expression, err.Error()))
			}
			variables[variable.Name] = prog
		}
	}
	var rules []cel.Program
	{
		path := path.Child("validations")
		for i, rule := range policy.Spec.Validations {
			path := path.Index(i)
			program, errs := c.compileAuthorization(path, policy.Spec.EvaluationMode(), rule, env)
			if errs != nil {
				return nil, append(allErrs, errs...)
			}
			rules = append(rules, program)
		}
	}
	var compiledPolexs []compiledException
	{
		for _, ex := range exceptions {
			cex, errs := c.compileException(*ex, env)
			if errs != nil {
				return nil, append(allErrs, errs...)
			}
			compiledPolexs = append(compiledPolexs, *cex)
		}
	}

	return &compiledPolicy[DATA, IN, OUT]{
		matchConditions: matchConditions,
		name:            policy.Name,
		variables:       variables,
		rules:           rules,
		exceptions:      compiledPolexs,
	}, nil
}

func (c *compiler[DATA, IN, OUT]) compileAuthorization(path *field.Path, evalMode v1.EvaluationMode, rule admissionregistrationv1.Validation, env *cel.Env) (cel.Program, field.ErrorList) {
	var allErrs field.ErrorList
	{
		path := path.Child("expression")
		ast, issues := env.Compile(rule.Expression)
		if err := issues.Err(); err != nil {
			return nil, append(allErrs, field.Invalid(path, rule.Expression, err.Error()))
		}
		switch evalMode {
		case apis.EvaluationModeEnvoy:
			if !ast.OutputType().IsExactType(envoy.CheckResponse) && !ast.OutputType().IsExactType(types.NullType) {
				msg := fmt.Sprintf("rule response output is expected to be of type %s", envoy.CheckResponse.TypeName())
				return nil, append(allErrs, field.Invalid(path, rule.Expression, msg))
			}
		case apis.EvaluationModeHTTP:
			if !ast.OutputType().IsExactType(httpauth.ResponseType) && !ast.OutputType().IsExactType(types.NullType) {
				msg := fmt.Sprintf("rule response output is expected to be of type %s", httpauth.ResponseType.TypeName())
				return nil, append(allErrs, field.Invalid(path, rule.Expression, msg))
			}
		}
		prog, err := env.Program(ast)
		if err != nil {
			return nil, append(allErrs, field.Invalid(path, rule.Expression, err.Error()))
		}
		return prog, nil
	}
}

func (c *compiler[DATA, IN, OUT]) compileException(ex v1.PolicyException, env *cel.Env) (*compiledException, field.ErrorList) {
	compiledMatchConditions := []cel.Program{}
	var allErrs field.ErrorList
	for _, mc := range ex.Spec.MatchConditions {
		path := field.NewPath("spec").Child("matchConditions")
		ast, issues := env.Compile(mc.Expression)
		if err := issues.Err(); err != nil {
			return nil, append(allErrs, field.Invalid(path, mc.Expression, err.Error()))
		}
		if !ast.OutputType().IsExactType(types.BoolType) {
			msg := fmt.Sprintf("output is expected to be of type %s", types.BoolType.TypeName())
			return nil, append(allErrs, field.Invalid(path, mc.Expression, msg))
		}
		prog, err := env.Program(ast)
		if err != nil {
			return nil, append(allErrs, field.Invalid(path, mc.Expression, err.Error()))
		}
		compiledMatchConditions = append(compiledMatchConditions, prog)
	}
	return &compiledException{
		matchConditions: compiledMatchConditions,
	}, nil
}
