package http

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/kyverno/kyverno-authz/apis"
	authzcel "github.com/kyverno/kyverno-authz/pkg/cel"
	httpcel "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
	"github.com/kyverno/kyverno-authz/pkg/cel/libs/httpserver"
	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/kyverno-authz/pkg/events"
	"github.com/kyverno/sdk/extensions/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/dynamic"
)

type staticEngine struct{}

func (staticEngine) Handle(context.Context, dynamic.Interface, *httpcel.CheckRequest) engine.Evaluation[*httpcel.CheckResponse] {
	return engine.Evaluation[*httpcel.CheckResponse]{PolicyName: "admin-only", Evaluation: policy.Evaluation[*httpcel.CheckResponse]{Result: &httpcel.CheckResponse{Denied: &httpcel.CheckResponseDenied{Reason: "Admin access required"}}}}
}

type capturedEvent struct{ result events.ResultAccessor }

func (e *capturedEvent) Push(_ context.Context, _ time.Time, _ httpcel.CheckRequest, result events.ResultAccessor) {
	e.result = result
}

func TestAuthorizerReportsPolicyAndTransformedHTTPStatus(t *testing.T) {
	env, err := authzcel.NewEnv(apis.EvaluationModeHTTP, nil)
	require.NoError(t, err)
	env, err = env.Extend(cel.Variable("object", httpcel.ResponseType), httpserver.Lib())
	require.NoError(t, err)
	ast, issues := env.Compile(`httpserver.HttpResponse{status:401,body:bytes(object.denied.reason)}`)
	require.NoError(t, issues.Err())
	program, err := env.Program(ast)
	require.NoError(t, err)
	event := &capturedEvent{}
	authorizer := NewAuthorizer(staticEngine{}, nil, nil, program, false, event)
	response := httptest.NewRecorder()
	authorizer.ServeHTTP(response, httptest.NewRequest("POST", "http://authz/", strings.NewReader("request body")))
	assert.Equal(t, 401, response.Code)
	assert.Equal(t, "Admin access required", response.Body.String())
	require.NotNil(t, event.result)
	metadata, ok := event.result.(interface {
		ReportMetadata() (string, map[string]string)
	})
	require.True(t, ok)
	name, properties := metadata.ReportMetadata()
	assert.Equal(t, "admin-only", name)
	assert.Equal(t, "401", properties["status"])
	assert.Equal(t, "Admin access required", properties["reason"])
}
