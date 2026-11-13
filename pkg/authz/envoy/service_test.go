package envoy

import (
	"context"
	"errors"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/kyverno/kyverno-authz/pkg/authz"
	"github.com/kyverno/kyverno-authz/pkg/events"
	"github.com/kyverno/sdk/extensions/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/dynamic"
)

type engineFunc func(context.Context, dynamic.Interface, *authv3.CheckRequest) policy.Evaluation[*authv3.CheckResponse]

func (f engineFunc) Handle(ctx context.Context, d dynamic.Interface, r *authv3.CheckRequest) policy.Evaluation[*authv3.CheckResponse] {
	return f(ctx, d, r)
}

func returning(result *authv3.CheckResponse, err error) engineFunc {
	return func(context.Context, dynamic.Interface, *authv3.CheckRequest) policy.Evaluation[*authv3.CheckResponse] {
		return policy.MakeEvaluation(result, err)
	}
}

func newService(e engineFunc, decision authz.DefaultDecision, ready bool) *service {
	return &service{
		engine:          e,
		eventHandler:    events.NewComposite[*authv3.CheckRequest](),
		defaultDecision: decision,
		ready:           func() bool { return ready },
	}
}

func TestCheck_NotReadyReturnsUnavailable(t *testing.T) {
	called := false
	svc := newService(func(context.Context, dynamic.Interface, *authv3.CheckRequest) policy.Evaluation[*authv3.CheckResponse] {
		called = true
		return policy.Evaluation[*authv3.CheckResponse]{}
	}, authz.DefaultDecisionAllow, false)
	resp, err := svc.Check(context.Background(), &authv3.CheckRequest{})
	assert.Nil(t, resp)
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.False(t, called, "the engine must not run before policies are loaded")
}

func TestCheck_DefaultDecision(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		svc := newService(returning(nil, nil), authz.DefaultDecisionAllow, true)
		resp, err := svc.Check(context.Background(), &authv3.CheckRequest{})
		require.NoError(t, err)
		assert.Equal(t, int32(codes.OK), resp.GetStatus().GetCode())
		assert.Nil(t, resp.GetDeniedResponse())
	})
	t.Run("deny", func(t *testing.T) {
		svc := newService(returning(nil, nil), authz.DefaultDecisionDeny, true)
		resp, err := svc.Check(context.Background(), &authv3.CheckRequest{})
		require.NoError(t, err)
		assert.Equal(t, int32(codes.PermissionDenied), resp.GetStatus().GetCode())
		assert.Equal(t, typev3.StatusCode_Forbidden, resp.GetDeniedResponse().GetStatus().GetCode())
		assert.Equal(t, authz.NoMatchReason, resp.GetDeniedResponse().GetBody())
	})
}

func TestCheck_PolicyResultWins(t *testing.T) {
	allowed := &authv3.CheckResponse{HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{}}}
	svc := newService(returning(allowed, nil), authz.DefaultDecisionDeny, true)
	resp, err := svc.Check(context.Background(), &authv3.CheckRequest{})
	require.NoError(t, err)
	assert.Same(t, allowed, resp)
}

func TestCheck_EngineErrorIsReturned(t *testing.T) {
	svc := newService(returning(nil, errors.New("boom")), authz.DefaultDecisionAllow, true)
	_, err := svc.Check(context.Background(), &authv3.CheckRequest{})
	assert.EqualError(t, err, "boom")
}
