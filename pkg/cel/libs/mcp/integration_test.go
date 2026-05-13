package mcp

import (
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/mark3labs/mcp-go/mcp"
)

// TestMCPRequestInPolicyWithVariables demonstrates how MCPRequest is used in a real policy scenario:
// 1. An MCPRequest is created (typically from mcp.Parse() in a variable)
// 2. Validation rules use the MCPRequest directly without needing Parse() again
func TestMCPRequestInPolicyWithVariables(t *testing.T) {
	// Setup: Create CEL environment similar to what a policy would have
	env, err := cel.NewEnv(
		ext.NativeTypes(
			reflect.TypeFor[MCPRequest](),
		),
		cel.Variable("mcpReq", MCPRequestType),
	)
	if err != nil {
		t.Fatalf("failed creating CEL env: %v", err)
	}

	tests := []struct {
		name           string
		mcpRequest     *MCPRequest
		validationExpr string
		wantResult     bool
	}{
		{
			name: "policy validates tool call method",
			mcpRequest: &MCPRequest{
				Method: "tools/call",
				ToolCall: &mcp.CallToolParams{
					Name: "shell",
				},
			},
			validationExpr: `mcpReq.Method == "tools/call" && mcpReq.ToolCall.Name == "shell"`,
			wantResult:     true,
		},
		{
			name: "policy validates resource read URI",
			mcpRequest: &MCPRequest{
				Method: "resources/read",
				ResourceRead: &mcp.ReadResourceParams{
					URI: "file:///etc/passwd",
				},
			},
			validationExpr: `mcpReq.Method == "resources/read" && mcpReq.ResourceRead.URI == "file:///etc/passwd"`,
			wantResult:     true,
		},
		{
			name: "policy checks for unset ToolCall",
			mcpRequest: &MCPRequest{
				Method: "initialize",
			},
			validationExpr: `mcpReq.Method == "initialize"`,
			wantResult:     true,
		},
		{
			name: "policy validates Paginated cursor",
			mcpRequest: &MCPRequest{
				Method: "resources/list",
				Paginated: &mcp.PaginatedParams{
					Cursor: "page-2",
				},
			},
			validationExpr: `mcpReq.Paginated.Cursor == "page-2"`,
			wantResult:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, issues := env.Compile(tt.validationExpr)
			if issues != nil && issues.Err() != nil {
				t.Fatalf("compilation error: %v", issues.Err())
			}

			prog, err := env.Program(ast)
			if err != nil {
				t.Fatalf("program error: %v", err)
			}

			result, _, err := prog.Eval(map[string]any{
				"mcpReq": tt.mcpRequest,
			})
			if err != nil {
				t.Fatalf("evaluation error: %v", err)
			}

			native, convErr := result.ConvertToNative(reflect.TypeOf(true))
			if convErr != nil {
				t.Fatalf("failed to convert result: %v", convErr)
			}
			got, ok := native.(bool)
			if !ok {
				t.Fatalf("result is not a bool: %T", native)
			}

			if got != tt.wantResult {
				t.Errorf("got %v, want %v", got, tt.wantResult)
			}
		})
	}
}

// TestMCPRequestDirectAccessWithoutReParsing demonstrates that once MCPRequest is available
// (from parsing in a variable), it can be used directly in validation rules without Parse()
func TestMCPRequestDirectAccessWithoutReParsing(t *testing.T) {
	env, err := cel.NewEnv(
		ext.NativeTypes(
			reflect.TypeFor[MCPRequest](),
		),
		cel.Variable("mcpReq", MCPRequestType),
	)
	if err != nil {
		t.Fatalf("failed creating CEL env: %v", err)
	}

	tests := []struct {
		name           string
		mcpRequest     *MCPRequest
		validationExpr string
		wantResult     bool
	}{
		{
			name: "direct field access without Parse() - Method",
			mcpRequest: &MCPRequest{
				Method: "tools/call",
				ToolCall: &mcp.CallToolParams{
					Name: "shell",
				},
			},
			validationExpr: `mcpReq.Method == "tools/call" && mcpReq.ToolCall.Name == "shell"`,
			wantResult:     true,
		},
		{
			name: "direct nested field access without Parse() - ResourceRead",
			mcpRequest: &MCPRequest{
				ResourceRead: &mcp.ReadResourceParams{
					URI: "file:///data",
				},
			},
			validationExpr: `mcpReq.ResourceRead.URI == "file:///data"`,
			wantResult:     true,
		},
		{
			name: "null check without Parse()",
			mcpRequest: &MCPRequest{
				Method: "initialize",
			},
			validationExpr: `mcpReq.Method == "initialize"`,
			wantResult:     true,
		},
		{
			name: "complex expression without Parse()",
			mcpRequest: &MCPRequest{
				Method: "resources/list",
				Paginated: &mcp.PaginatedParams{
					Cursor: "page-2",
				},
			},
			validationExpr: `mcpReq.Method == "resources/list" && mcpReq.Paginated.Cursor == "page-2"`,
			wantResult:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, issues := env.Compile(tt.validationExpr)
			if issues != nil && issues.Err() != nil {
				t.Fatalf("compilation error: %v", issues.Err())
			}

			prog, err := env.Program(ast)
			if err != nil {
				t.Fatalf("program error: %v", err)
			}

			result, _, err := prog.Eval(map[string]any{
				"mcpReq": tt.mcpRequest,
			})
			if err != nil {
				t.Fatalf("evaluation error: %v", err)
			}

			native, convErr := result.ConvertToNative(reflect.TypeOf(true))
			if convErr != nil {
				t.Fatalf("failed to convert result: %v", convErr)
			}
			got, ok := native.(bool)
			if !ok {
				t.Fatalf("result is not a bool: %T", native)
			}

			if got != tt.wantResult {
				t.Errorf("got %v, want %v", got, tt.wantResult)
			}
		})
	}
}

// TestMCPRequestGetterMethodsInValidation demonstrates that helper methods work
// without requiring Parse() on the result - the methods are called directly on MCPRequest instances
func TestMCPRequestGetterMethodsInValidation(t *testing.T) {

	tests := []struct {
		name           string
		mcpRequest     *MCPRequest
		testFunc       func(*MCPRequest) bool
		wantResult     bool
	}{
		{
			name: "GetStringArgument called directly",
			mcpRequest: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Arguments: map[string]any{
						"command": "ls",
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				return r.GetStringArgument("command", "") == "ls"
			},
			wantResult: true,
		},
		{
			name: "GetIntArgument with default",
			mcpRequest: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Arguments: map[string]any{
						"retries": 3,
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				return r.GetIntArgument("retries", 0) == 3
			},
			wantResult: true,
		},
		{
			name: "GetBoolArgument",
			mcpRequest: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Arguments: map[string]any{
						"force": true,
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				return r.GetBoolArgument("force", false) == true
			},
			wantResult: true,
		},
		{
			name: "GetFloatArgument",
			mcpRequest: &MCPRequest{
				ResourceRead: &mcp.ReadResourceParams{
					Arguments: map[string]any{
						"timeout": 5.5,
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				return r.GetFloatArgument("timeout", 0.0) == 5.5
			},
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.testFunc(tt.mcpRequest)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}
