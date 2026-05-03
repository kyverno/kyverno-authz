package mcp

import (
	"testing"

	"github.com/google/cel-go/cel"
)

func TestLib_GetTypedArgumentOverloadsAcceptStringKeys(t *testing.T) {
	env, err := cel.NewEnv(Lib(&mockMCPImpl{}))
	if err != nil {
		t.Fatalf("failed creating CEL env: %v", err)
	}

	tests := []struct {
		name string
		expr string
	}{
		{
			name: "GetIntArgument",
			expr: `mcp.Parse("{}").GetIntArgument("max_tokens", 0)`,
		},
		{
			name: "GetFloatArgument",
			expr: `mcp.Parse("{}").GetFloatArgument("temperature", 0.0)`,
		},
		{
			name: "GetBoolArgument",
			expr: `mcp.Parse("{}").GetBoolArgument("stream", false)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, issues := env.Compile(tt.expr)
			if issues != nil && issues.Err() != nil {
				t.Fatalf("expected expression to compile, got error: %v", issues.Err())
			}
		})
	}
}

func TestLib_GetTypedArgumentOverloadsRejectNonStringKeys(t *testing.T) {
	env, err := cel.NewEnv(Lib(&mockMCPImpl{}))
	if err != nil {
		t.Fatalf("failed creating CEL env: %v", err)
	}

	tests := []struct {
		name string
		expr string
	}{
		{
			name: "GetIntArgument",
			expr: `mcp.Parse("{}").GetIntArgument(0, 0)`,
		},
		{
			name: "GetFloatArgument",
			expr: `mcp.Parse("{}").GetFloatArgument(0.0, 0.0)`,
		},
		{
			name: "GetBoolArgument",
			expr: `mcp.Parse("{}").GetBoolArgument(false, false)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, issues := env.Compile(tt.expr)
			if issues == nil || issues.Err() == nil {
				t.Fatalf("expected expression to fail compile for non-string key")
			}
		})
	}
}

func TestLib_GetSliceArgumentOverloadsAcceptListDefaults(t *testing.T) {
	env, err := cel.NewEnv(Lib(&mockMCPImpl{}))
	if err != nil {
		t.Fatalf("failed creating CEL env: %v", err)
	}

	tests := []struct {
		name string
		expr string
	}{
		{
			name: "GetStringSliceArgument list default",
			expr: `mcp.Parse("{}").GetStringSliceArgument("tags", [""])`,
		},
		{
			name: "GetIntSliceArgument list default",
			expr: `mcp.Parse("{}").GetIntSliceArgument("ids", [0])`,
		},
		{
			name: "GetFloatSliceArgument list default",
			expr: `mcp.Parse("{}").GetFloatSliceArgument("scores", [0.0])`,
		},
		{
			name: "GetBoolSliceArgument list default",
			expr: `mcp.Parse("{}").GetBoolSliceArgument("flags", [false])`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, issues := env.Compile(tt.expr)
			if issues != nil && issues.Err() != nil {
				t.Fatalf("expected expression to compile, got error: %v", issues.Err())
			}
		})
	}
}

func TestLib_GetSliceArgumentOverloadsRejectScalarDefaults(t *testing.T) {
	env, err := cel.NewEnv(Lib(&mockMCPImpl{}))
	if err != nil {
		t.Fatalf("failed creating CEL env: %v", err)
	}

	tests := []struct {
		name string
		expr string
	}{
		{
			name: "GetStringSliceArgument scalar default",
			expr: `mcp.Parse("{}").GetStringSliceArgument("tags", "")`,
		},
		{
			name: "GetIntSliceArgument scalar default",
			expr: `mcp.Parse("{}").GetIntSliceArgument("ids", 0)`,
		},
		{
			name: "GetFloatSliceArgument scalar default",
			expr: `mcp.Parse("{}").GetFloatSliceArgument("scores", 0.0)`,
		},
		{
			name: "GetBoolSliceArgument scalar default",
			expr: `mcp.Parse("{}").GetBoolSliceArgument("flags", false)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, issues := env.Compile(tt.expr)
			if issues == nil || issues.Err() == nil {
				t.Fatalf("expected expression to fail compile for scalar default")
			}
		})
	}
}
