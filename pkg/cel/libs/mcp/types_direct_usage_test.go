package mcp

import (
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"
	"github.com/mark3labs/mcp-go/mcp"
)

// TestMCPRequestDirectUsageInPolicy verifies that MCPRequest can be used directly
// in a CEL policy without requiring mcp.Parse()
func TestMCPRequestDirectUsageInPolicy(t *testing.T) {
	// Create a CEL environment with MCPRequest type registered
	env, err := cel.NewEnv(
		ext.NativeTypes(
			reflect.TypeFor[MCPRequest](),
		),
		cel.Variable("mcpReq", types.NewObjectType("mcp.MCPRequest")),
	)
	if err != nil {
		t.Fatalf("failed creating CEL env: %v", err)
	}

	tests := []struct {
		name       string
		policy     string
		request    *MCPRequest
		wantResult any
		wantError  bool
	}{
		{
			name:   "access Method field directly",
			policy: `mcpReq.Method == "tools/call"`,
			request: &MCPRequest{
				Method: "tools/call",
			},
			wantResult: true,
			wantError:  false,
		},
		{
			name:   "access nested ToolCall field",
			policy: `mcpReq.ToolCall.Name == "shell"`,
			request: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Name: "shell",
				},
			},
			wantResult: true,
			wantError:  false,
		},
		{
			name:   "check ToolCall is not null",
			policy: `mcpReq.ToolCall != null`,
			request: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Name: "shell",
				},
			},
			wantResult: true,
			wantError:  false,
		},
		{
			name:   "check ResourceRead fields without null check",
			policy: `mcpReq.ResourceRead.URI == "file:///etc/passwd"`,
			request: &MCPRequest{
				ResourceRead: &mcp.ReadResourceParams{
					URI: "file:///etc/passwd",
				},
			},
			wantResult: true,
			wantError:  false,
		},
		{
			name:   "check multiple conditions with direct fields",
			policy: `mcpReq.Method == "tools/call" && mcpReq.ToolCall.Name == "shell"`,
			request: &MCPRequest{
				Method: "tools/call",
				ToolCall: &mcp.CallToolParams{
					Name: "shell",
				},
			},
			wantResult: true,
			wantError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, issues := env.Compile(tt.policy)
			if issues != nil && issues.Err() != nil {
				if !tt.wantError {
					t.Fatalf("compilation error: %v", issues.Err())
				}
				return
			}

			program, err := env.Program(ast)
			if err != nil {
				if !tt.wantError {
					t.Fatalf("program creation error: %v", err)
				}
				return
			}

			result, _, err := program.Eval(map[string]any{
				"mcpReq": tt.request,
			})
			if err != nil {
				if !tt.wantError {
					t.Fatalf("evaluation error: %v", err)
				}
				return
			}

			// Convert CEL result to native type for comparison
			native, convErr := result.ConvertToNative(reflect.TypeOf(true))
			if convErr != nil {
				t.Fatalf("failed to convert result to native: %v", convErr)
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

// TestMCPRequestFieldAccess verifies direct field access on MCPRequest instances
func TestMCPRequestFieldAccess(t *testing.T) {
	tests := []struct {
		name      string
		mcpReq    *MCPRequest
		fieldTest func(*MCPRequest) bool
		expected  bool
	}{
		{
			name: "Method field is accessible",
			mcpReq: &MCPRequest{
				Method: "tools/call",
			},
			fieldTest: func(r *MCPRequest) bool {
				return r.Method == "tools/call"
			},
			expected: true,
		},
		{
			name: "ToolCall field is accessible",
			mcpReq: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Name: "kubectl",
				},
			},
			fieldTest: func(r *MCPRequest) bool {
				return r.ToolCall != nil && r.ToolCall.Name == "kubectl"
			},
			expected: true,
		},
		{
			name: "ResourceRead field is accessible",
			mcpReq: &MCPRequest{
				ResourceRead: &mcp.ReadResourceParams{
					URI: "file:///etc/passwd",
				},
			},
			fieldTest: func(r *MCPRequest) bool {
				return r.ResourceRead != nil && r.ResourceRead.URI == "file:///etc/passwd"
			},
			expected: true,
		},
		{
			name: "Paginated field is accessible",
			mcpReq: &MCPRequest{
				Paginated: &mcp.PaginatedParams{
					Cursor: "page-2",
				},
			},
			fieldTest: func(r *MCPRequest) bool {
				return r.Paginated != nil && r.Paginated.Cursor == "page-2"
			},
			expected: true,
		},
		{
			name: "PromptGet field is accessible",
			mcpReq: &MCPRequest{
				PromptGet: &mcp.GetPromptParams{
					Name: "my-prompt",
				},
			},
			fieldTest: func(r *MCPRequest) bool {
				return r.PromptGet != nil && r.PromptGet.Name == "my-prompt"
			},
			expected: true,
		},
		{
			name: "Null field checks work",
			mcpReq: &MCPRequest{
				Method: "initialize",
			},
			fieldTest: func(r *MCPRequest) bool {
				return r.ToolCall == nil && r.ResourceRead == nil
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fieldTest(tt.mcpReq)
			if got != tt.expected {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMCPRequestGetterMethodsWithoutParse verifies helper methods work on directly-constructed instances
func TestMCPRequestGetterMethodsWithoutParse(t *testing.T) {
	tests := []struct {
		name       string
		mcpReq     *MCPRequest
		testFunc   func(*MCPRequest) bool
		expected   bool
		description string
	}{
		{
			name: "GetStringArgument without parse",
			mcpReq: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Arguments: map[string]any{
						"command": "ls",
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				return r.GetStringArgument("command", "") == "ls"
			},
			expected:    true,
			description: "Should retrieve string argument from directly-constructed MCPRequest",
		},
		{
			name: "GetStringArgument with default",
			mcpReq: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Arguments: map[string]any{},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				return r.GetStringArgument("missing", "default") == "default"
			},
			expected:    true,
			description: "Should return default when key is missing",
		},
		{
			name: "GetIntArgument without parse",
			mcpReq: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Arguments: map[string]any{
						"count": 42,
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				return r.GetIntArgument("count", 0) == 42
			},
			expected:    true,
			description: "Should retrieve int argument from directly-constructed MCPRequest",
		},
		{
			name: "GetFloatArgument without parse",
			mcpReq: &MCPRequest{
				ResourceRead: &mcp.ReadResourceParams{
					Arguments: map[string]any{
						"ratio": 3.14,
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				return r.GetFloatArgument("ratio", 0.0) == 3.14
			},
			expected:    true,
			description: "Should retrieve float argument from directly-constructed MCPRequest",
		},
		{
			name: "GetBoolArgument without parse",
			mcpReq: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Arguments: map[string]any{
						"recursive": true,
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				return r.GetBoolArgument("recursive", false) == true
			},
			expected:    true,
			description: "Should retrieve bool argument from directly-constructed MCPRequest",
		},
		{
			name: "GetStringSliceArgument without parse",
			mcpReq: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Arguments: map[string]any{
						"tags": []string{"prod", "api"},
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				tags := r.GetStringSliceArgument("tags", nil)
				return len(tags) == 2 && tags[0] == "prod" && tags[1] == "api"
			},
			expected:    true,
			description: "Should retrieve string slice from directly-constructed MCPRequest",
		},
		{
			name: "GetIntSliceArgument without parse",
			mcpReq: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Arguments: map[string]any{
						"ports": []int{8080, 8081},
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				ports := r.GetIntSliceArgument("ports", nil)
				return len(ports) == 2 && ports[0] == 8080 && ports[1] == 8081
			},
			expected:    true,
			description: "Should retrieve int slice from directly-constructed MCPRequest",
		},
		{
			name: "GetFloatSliceArgument without parse",
			mcpReq: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Arguments: map[string]any{
						"values": []float64{1.5, 2.5},
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				values := r.GetFloatSliceArgument("values", nil)
				return len(values) == 2 && values[0] == 1.5 && values[1] == 2.5
			},
			expected:    true,
			description: "Should retrieve float slice from directly-constructed MCPRequest",
		},
		{
			name: "GetBoolSliceArgument without parse",
			mcpReq: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Arguments: map[string]any{
						"flags": []bool{true, false},
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				flags := r.GetBoolSliceArgument("flags", nil)
				return len(flags) == 2 && flags[0] == true && flags[1] == false
			},
			expected:    true,
			description: "Should retrieve bool slice from directly-constructed MCPRequest",
		},
		{
			name: "GetArguments returns correct map",
			mcpReq: &MCPRequest{
				ToolCall: &mcp.CallToolParams{
					Arguments: map[string]any{
						"key1": "value1",
						"key2": 123,
					},
				},
			},
			testFunc: func(r *MCPRequest) bool {
				args := r.GetArguments()
				return args["key1"] == "value1" && args["key2"] == 123
			},
			expected:    true,
			description: "Should return arguments map from directly-constructed MCPRequest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.testFunc(tt.mcpReq)
			if got != tt.expected {
				t.Errorf("%s: got %v, want %v", tt.description, got, tt.expected)
			}
		})
	}
}

// TestMCPRequestAsVariableInput simulates using MCPRequest passed as an input variable
// to a policy without needing to parse it first
func TestMCPRequestAsVariableInput(t *testing.T) {
	// Setup: Create a CEL environment with MCPRequest type
	env, err := cel.NewEnv(
		ext.NativeTypes(
			reflect.TypeFor[MCPRequest](),
		),
		cel.Variable("request", types.NewObjectType("mcp.MCPRequest")),
	)
	if err != nil {
		t.Fatalf("failed creating CEL env: %v", err)
	}

	tests := []struct {
		name       string
		policy     string
		request    *MCPRequest
		wantResult any
	}{
		{
			name:   "evaluate method field without parse",
			policy: `request.Method == "tools/call"`,
			request: &MCPRequest{
				Method: "tools/call",
			},
			wantResult: true,
		},
		{
			name:   "evaluate tool name without parse",
			policy: `request.ToolCall.Name == "kubectl"`,
			request: &MCPRequest{
				Method: "tools/call",
				ToolCall: &mcp.CallToolParams{
					Name: "kubectl",
				},
			},
			wantResult: true,
		},
		{
			name:   "evaluate resource URI without parse",
			policy: `request.ResourceRead.URI == "file:///data"`,
			request: &MCPRequest{
				ResourceRead: &mcp.ReadResourceParams{
					URI: "file:///data",
				},
			},
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, issues := env.Compile(tt.policy)
			if issues != nil && issues.Err() != nil {
				t.Fatalf("compilation error: %v", issues.Err())
			}

			program, err := env.Program(ast)
			if err != nil {
				t.Fatalf("program error: %v", err)
			}

			result, _, err := program.Eval(map[string]any{
				"request": tt.request,
			})
			if err != nil {
				t.Fatalf("evaluation error: %v", err)
			}

			// Convert CEL result to native bool for comparison
			native, convErr := result.ConvertToNative(reflect.TypeOf(true))
			if convErr != nil {
				t.Fatalf("failed to convert result to native: %v", convErr)
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
