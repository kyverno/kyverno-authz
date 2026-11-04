package extproc_test

import (
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	celproc "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/extproc"
)

func TestLibraryOutputsAndJSONEncoding(t *testing.T) {
	env, err := cel.NewEnv(celproc.Lib())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		expression string
		check      func(any) bool
	}{
		{
			name:       "respond",
			expression: `extproc.Respond(403).WithBody("blocked").WithHeader("x-policy", "deny").WithoutHeader("server")`,
			check: func(value any) bool {
				result, ok := value.(*celproc.Result)
				return ok && result.Action == "respond" && result.Status == 403 && result.Body == "blocked" && len(result.Headers) == 2 && result.Headers[1].Remove
			},
		},
		{
			name:       "continue with header mutations",
			expression: `extproc.Continue().WithHeader("x-policy", "allow").WithoutHeader("x-secret")`,
			check: func(value any) bool {
				result, ok := value.(*celproc.Result)
				return ok && result.Action == "continue" && len(result.Headers) == 2 && result.Headers[1].Remove
			},
		},
		{
			name:       "replace body",
			expression: `extproc.ReplaceBody("updated")`,
			check: func(value any) bool {
				result, ok := value.(*celproc.Result)
				return ok && result.Action == "continue" && result.ReplaceBody && result.Body == "updated"
			},
		},
		{
			name:       "marshal dynamic map",
			expression: `extproc.Marshal(dyn({"name": dyn("visible"), "count": dyn(2)}))`,
			check:      func(value any) bool { return reflect.DeepEqual(value, `{"count":2,"name":"visible"}`) },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ast, issues := env.Compile(test.expression)
			if err := issues.Err(); err != nil {
				t.Fatal(err)
			}
			program, err := env.Program(ast)
			if err != nil {
				t.Fatal(err)
			}
			value, _, err := program.Eval(map[string]any{})
			if err != nil {
				t.Fatal(err)
			}
			if got := value.Value(); !test.check(got) {
				t.Fatalf("unexpected result: %#v", got)
			}
		})
	}
}
