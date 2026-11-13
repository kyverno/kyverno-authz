package envoy

import (
	"context"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/kyverno/kyverno-authz/pkg/authz"
	"github.com/kyverno/kyverno-authz/pkg/events"
	"github.com/kyverno/kyverno-authz/pkg/metrics"
	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/extensions/policy"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/dynamic"
	ctrl "sigs.k8s.io/controller-runtime"
)

type service struct {
	engine          core.Engine[dynamic.Interface, *authv3.CheckRequest, policy.Evaluation[*authv3.CheckResponse]]
	dynclient       dynamic.Interface
	eventHandler    events.EventIface[*authv3.CheckRequest]
	defaultDecision authz.DefaultDecision
	ready           func() bool
}

func (s *service) Check(ctx context.Context, r *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	start := time.Now()
	decision := metrics.DecisionError
	source := metrics.SourceServer
	defer func() {
		metrics.RecordAuthzDecision(metrics.ModeEnvoy, decision, source, start)
	}()
	// reject requests until policies are loaded, so that the gateway's failure mode applies
	if !s.ready() {
		decision = metrics.DecisionUnavailable
		return nil, status.Error(codes.Unavailable, authz.NotReadyReason)
	}
	// execute check
	response, matched, err := s.check(ctx, r)
	// log error if any
	if err != nil {
		source = metrics.SourceEngine
		metrics.RecordEnvoyRequestError(ctx, r, err)
		s.eventHandler.Push(ctx, time.Now(), r, events.NewResultAccessor(nil, err))
		ctrl.LoggerFrom(ctx).Error(err, "Check failed")
	} else {
		source = metrics.SourcePolicy
		if !matched {
			source = metrics.SourceDefault
		}
		if response.GetDeniedResponse() != nil {
			decision = metrics.DecisionDeny
		} else {
			decision = metrics.DecisionAllow
		}
		defer func() {
			s.eventHandler.Push(ctx, time.Now(), r, events.NewResultAccessor(response, nil))
			metrics.RecordEnvoyRequest(ctx, start, r, response)
		}()
	}
	// return response and error
	return response, err
}

// check evaluates the request. matched is false when no policy returned a result
// and the default decision applies.
func (s *service) check(ctx context.Context, r *authv3.CheckRequest) (_ *authv3.CheckResponse, matched bool, _ error) {
	// invoke engine
	response := s.engine.Handle(ctx, s.dynclient, r)
	if response.Result != nil {
		return response.Result, true, nil
	}
	if response.Error != nil {
		return &authv3.CheckResponse{}, false, response.Error
	}
	return defaultResponse(s.defaultDecision), false, nil
}

func defaultResponse(decision authz.DefaultDecision) *authv3.CheckResponse {
	if decision == authz.DefaultDecisionDeny {
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{
				Code:    int32(codes.PermissionDenied),
				Message: authz.NoMatchReason,
			},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{
				DeniedResponse: &authv3.DeniedHttpResponse{
					Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
					Body:   authz.NoMatchReason,
				},
			},
		}
	}
	return &authv3.CheckResponse{}
}
