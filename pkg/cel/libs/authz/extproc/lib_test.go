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
		{
			name:       "nested heterogeneous dynamic collections",
			expression: `extproc.Marshal(dyn({"outer": dyn([dyn({"number": dyn(2), "flag": dyn(true), "empty": dyn(null), "text": dyn("visible")}), dyn(3), dyn("tail")]), "empty": dyn({})}))`,
			check: func(value any) bool {
				return value == `{"empty":{},"outer":[{"empty":null,"flag":true,"number":2,"text":"visible"},3,"tail"]}`
			},
		},
		{
			name:       "preserve integer precision",
			expression: `extproc.Marshal(dyn([9223372036854775807, 18446744073709551615u]))`,
			check:      func(value any) bool { return value == `[9223372036854775807,18446744073709551615]` },
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

func TestJSONEncodingRejectsNonStringObjectKeys(t *testing.T) {
	env, err := cel.NewEnv(celproc.Lib())
	if err != nil {
		t.Fatal(err)
	}
	ast, issues := env.Compile(`extproc.Marshal(dyn({"nested": dyn({1: "not a JSON key"})}))`)
	if err := issues.Err(); err != nil {
		t.Fatal(err)
	}
	program, err := env.Program(ast)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := program.Eval(map[string]any{}); err == nil {
		t.Fatal("non-string map keys must fail rather than silently changing JSON semantics")
	}
}
