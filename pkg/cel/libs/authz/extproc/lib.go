package extproc

import (
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
)

type lib struct{}

func Lib() cel.EnvOption         { return cel.Lib(&lib{}) }
func (*lib) LibraryName() string { return "kyverno.authz.extproc" }
func (c *lib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		ext.NativeTypes(
			reflect.TypeFor[Input](), reflect.TypeFor[Request](), reflect.TypeFor[Response](),
			reflect.TypeFor[Result](), reflect.TypeFor[HeaderMutation](), reflect.TypeFor[SSEEvent](), ext.ParseStructTags(true),
		),
		c.extendEnv,
	}
}
func (*lib) ProgramOptions() []cel.ProgramOption { return nil }
func (*lib) extendEnv(env *cel.Env) (*cel.Env, error) {
	i := impl{adapter: env.CELTypeAdapter()}
	return env.Extend(
		cel.Function("extproc.Continue", cel.Overload("extproc_continue", []*cel.Type{}, ResultType, cel.FunctionBinding(func(...ref.Val) ref.Val { return i.result("continue") }))),
		cel.Function("extproc.ReplaceBody", cel.Overload("extproc_replace_body", []*cel.Type{types.StringType}, ResultType, cel.UnaryBinding(i.replaceBody))),
		cel.Function("extproc.Respond", cel.Overload("extproc_respond", []*cel.Type{types.IntType}, ResultType, cel.UnaryBinding(i.respond))),
		cel.Function("WithBody", cel.MemberOverload("extproc_with_body", []*cel.Type{ResultType, types.StringType}, ResultType, cel.BinaryBinding(i.withBody))),
		cel.Function("WithHeader", cel.MemberOverload("extproc_with_header", []*cel.Type{ResultType, types.StringType, types.StringType}, ResultType, cel.FunctionBinding(i.withHeader))),
		cel.Function("WithoutHeader", cel.MemberOverload("extproc_without_header", []*cel.Type{ResultType, types.StringType}, ResultType, cel.BinaryBinding(i.withoutHeader))),
		cel.Function("extproc.Marshal", cel.Overload("extproc_json_marshal", []*cel.Type{types.DynType}, types.StringType, cel.UnaryBinding(marshalJSON))),
	)
}
