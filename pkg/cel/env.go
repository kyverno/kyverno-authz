package cel

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	vpol "github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	"github.com/kyverno/kyverno-authz/apis"
	impl "github.com/kyverno/kyverno-authz/pkg/cel/impl"
	"github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/envoy"
	httpauth "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
	jsoncel "github.com/kyverno/kyverno-authz/pkg/cel/libs/json"
	"github.com/kyverno/kyverno-authz/pkg/cel/libs/jwt"
	"github.com/kyverno/kyverno-authz/pkg/cel/libs/mcp"
	"github.com/kyverno/kyverno-authz/pkg/engine/variables"
	"github.com/kyverno/sdk/cel/libs/http"
	"github.com/kyverno/sdk/cel/libs/image"
	"github.com/kyverno/sdk/cel/libs/imagedata"
	"github.com/kyverno/sdk/cel/libs/resource"
	"k8s.io/apiserver/pkg/cel/library"
	"k8s.io/client-go/dynamic"
)

func NewBaseEnv() (*cel.Env, error) {
	// create new cel env
	return cel.NewEnv(
		// configure env
		cel.HomogeneousAggregateLiterals(),
		cel.EagerlyValidateDeclarations(true),
		cel.DefaultUTCTimeZone(true),
		cel.CrossTypeNumericComparisons(true),
		// register common libs
		cel.OptionalTypes(),
		ext.Bindings(),
		ext.Encoders(),
		ext.Lists(),
		ext.Math(),
		ext.Protos(),
		ext.Sets(),
		ext.Strings(),
		// register kubernetes libs
		library.CIDR(),
		library.Format(),
		library.IP(),
		library.Lists(),
		library.Regex(),
		library.URLs(),
		library.Quantity(),
		library.SemverLib(),
	)
}

func NewEnv(evalMode vpol.EvaluationMode, d dynamic.Interface) (*cel.Env, error) {
	base, err := NewBaseEnv()
	if err != nil {
		return nil, err
	}
	// register our libs
	switch evalMode {
	case apis.EvaluationModeEnvoy:
		base, err = base.Extend(
			envoy.Lib(),
		)
	case apis.EvaluationModeHTTP:
		base, err = base.Extend(
			httpauth.Lib(),
		)
	default:
		err = fmt.Errorf("invalid evaluation mode passed for env builder")
	}
	if err != nil {
		return nil, err
	}
	loader, err := variables.ImageData(nil)
	if err != nil {
		return nil, err
	}
	// create new cel env
	return base.Extend(
		http.Lib(http.Context{ContextInterface: http.NewHTTP()}, http.Latest()),
		jwt.Lib(),
		jsoncel.Lib(&impl.JsonImpl{}),
		mcp.Lib(&impl.MCPImpl{}),
		resource.Lib(resource.Context{ContextInterface: variables.NewResourceProvider(d)}, "", resource.Latest()),
		image.Lib(image.Latest()),
		imagedata.Lib(imagedata.Context{ContextInterface: loader}, image.Latest()),
	)
}
