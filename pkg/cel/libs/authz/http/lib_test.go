package http

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	mcplibs "github.com/kyverno/kyverno-authz/pkg/cel/libs/mcp"
)

func newTestEnv(t *testing.T) *cel.Env {
	t.Helper()
	env, err := cel.NewEnv(
		Lib(),
		cel.Variable("object", RequestType),
	)
	if err != nil {
		t.Fatalf("failed to create CEL env: %v", err)
	}
	return env
}

func evalBool(t *testing.T, env *cel.Env, expr string, vars map[string]any) bool {
	t.Helper()
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("compile error for %q: %v", expr, issues.Err())
	}
	prog, err := env.Program(ast)
	if err != nil {
		t.Fatalf("program error: %v", err)
	}
	out, _, err := prog.Eval(vars)
	if err != nil {
		t.Fatalf("eval error for %q: %v", expr, err)
	}
	result, ok := out.Value().(bool)
	if !ok {
		t.Fatalf("expected bool result, got %T", out.Value())
	}
	return result
}

func newMCPToolCallRequest(t *testing.T, body string) *CheckRequest {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "/", io.NopCloser(strings.NewReader(body)))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req, err := NewRequest(r)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	return &req
}

func TestNewRequest_PopulatesMCPRequest(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}`
	req := newMCPToolCallRequest(t, body)

	if req.Mcp == nil {
		t.Fatal("expected Mcp to be non-nil")
	}
	if req.Mcp.Request == nil {
		t.Fatal("expected Mcp.Request to be non-nil")
	}
	if req.Mcp.Request.Method != "tools/call" {
		t.Errorf("got Method=%q, want tools/call", req.Mcp.Request.Method)
	}
}

func TestNewRequest_NonMCPBody_EmptyRequest(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req, err := NewRequest(r)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	if req.Mcp == nil || req.Mcp.Request == nil {
		t.Fatal("expected Mcp.Request to be a non-nil empty MCPRequest for non-MCP traffic")
	}
	if req.Mcp.Request.Method != "" {
		t.Errorf("expected empty Method for non-MCP body, got %q", req.Mcp.Request.Method)
	}
}

// TestObjectMCPRequest_MethodGating verifies Layer 1: object.mcp.request.Method
// can be used in matchConditions without calling mcp.Parse().
func TestObjectMCPRequest_MethodGating(t *testing.T) {
	env := newTestEnv(t)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}`
	req := newMCPToolCallRequest(t, body)

	vars := map[string]any{"object": req}

	if !evalBool(t, env, `object.mcp.request.Method == "tools/call"`, vars) {
		t.Error("expected Method == tools/call")
	}
	if evalBool(t, env, `object.mcp.request.Method == "resources/read"`, vars) {
		t.Error("expected Method != resources/read")
	}
}

// TestObjectMCPRequest_GetStringArgument verifies Layer 2: Get*Argument helpers
// work on object.mcp.request without mcp.Parse().
func TestObjectMCPRequest_GetStringArgument(t *testing.T) {
	env, err := cel.NewEnv(Lib(), mcplibs.Lib(&mockMCPImpl{}), cel.Variable("object", RequestType))
	if err != nil {
		t.Fatalf("failed to create CEL env: %v", err)
	}

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"BLOCK_ME"}}}`
	req := newMCPToolCallRequest(t, body)

	vars := map[string]any{"object": req}

	blocked := evalBool(t, env,
		`object.mcp.request.Method == "tools/call" && object.mcp.request.GetStringArgument("message", "") == "BLOCK_ME"`,
		vars,
	)
	if !blocked {
		t.Error("expected expression to be true for BLOCK_ME message")
	}

	allowed := evalBool(t, env,
		`object.mcp.request.GetStringArgument("message", "") != "BLOCK_ME"`,
		vars,
	)
	if allowed {
		t.Error("expected expression to be false when message is BLOCK_ME")
	}
}

type mockMCPImpl struct{}

func (m *mockMCPImpl) Parse(b []byte) (*mcplibs.MCPRequest, error) {
	return &mcplibs.MCPRequest{}, nil
}
