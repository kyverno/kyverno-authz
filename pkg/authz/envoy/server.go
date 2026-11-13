package envoy

import (
	"context"
	"net"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kyverno/kyverno-authz/pkg/authz"
	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/kyverno-authz/pkg/events"
	"github.com/kyverno/kyverno-authz/pkg/metrics"
	"github.com/kyverno/kyverno-authz/pkg/server"
	"github.com/kyverno/kyverno-authz/pkg/state"
	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/core/dispatchers"
	"github.com/kyverno/sdk/core/handlers"
	"github.com/kyverno/sdk/core/resulters"
	"github.com/kyverno/sdk/extensions/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"k8s.io/client-go/dynamic"
)

// Options configure the Envoy authorization server.
type Options struct {
	// DefaultDecision applies to requests that match no policy.
	DefaultDecision authz.DefaultDecision
	// Tracker gates request processing and the gRPC health service on the server lifecycle.
	// A nil tracker means the server is always ready.
	Tracker *state.Tracker
	// ShutdownTimeout bounds how long a graceful stop waits for in-flight requests.
	ShutdownTimeout time.Duration
}

func NewServer(network, addr string, source engine.EnvoySource, dynclient dynamic.Interface, eventHandler events.EventIface[*authv3.CheckRequest], opts Options) server.ServerFunc {
	return func(ctx context.Context) error {
		// create a server
		s := grpc.NewServer()
		// build the engine
		engine := core.NewEngine(
			source,
			handlers.Handler(
				dispatchers.Sequential(
					metrics.MetricsEvaluatorFactory(
						policy.EvaluatorFactory[engine.EnvoyPolicy](),
						func(out policy.Evaluation[*authv3.CheckResponse]) string {
							if out.Error != nil {
								return metrics.DecisionError
							}
							if out.Result == nil {
								return metrics.DecisionNoMatch
							}
							if out.Result.GetDeniedResponse() != nil {
								return metrics.DecisionDeny
							}
							return metrics.DecisionAllow
						},
					),
					func(ctx context.Context, fc core.FactoryContext[engine.EnvoyPolicy, dynamic.Interface, *authv3.CheckRequest]) core.Breaker[engine.EnvoyPolicy, *authv3.CheckRequest, policy.Evaluation[*authv3.CheckResponse]] {
						return core.MakeBreakerFunc(func(_ context.Context, _ engine.EnvoyPolicy, _ *authv3.CheckRequest, out policy.Evaluation[*authv3.CheckResponse]) bool {
							return out.Result != nil
						})
					},
				),
				func(ctx context.Context, fc core.FactoryContext[engine.EnvoyPolicy, dynamic.Interface, *authv3.CheckRequest]) core.Resulter[engine.EnvoyPolicy, *authv3.CheckRequest, policy.Evaluation[*authv3.CheckResponse], policy.Evaluation[*authv3.CheckResponse]] {
					return resulters.NewFirst[engine.EnvoyPolicy, *authv3.CheckRequest](func(out policy.Evaluation[*authv3.CheckResponse]) bool {
						return out.Result != nil || out.Error != nil
					})
				},
			),
		)
		// setup our authorization service
		svc := &service{
			engine:          engine,
			dynclient:       dynclient,
			eventHandler:    eventHandler,
			defaultDecision: opts.DefaultDecision,
			ready:           func() bool { return true },
		}
		// register our authorization service
		authv3.RegisterAuthorizationServer(s, svc)
		// register the health service, NOT_SERVING until policies are loaded
		healthServer := health.NewServer()
		healthpb.RegisterHealthServer(s, healthServer)
		if opts.Tracker != nil {
			svc.ready = opts.Tracker.Serving
			opts.Tracker.OnChange(func(phase state.Phase) {
				setHealth(healthServer, phase)
			})
		} else {
			setHealth(healthServer, state.Ready)
		}
		// register reflection service
		reflection.Register(s)
		// create a listener
		l, err := net.Listen(network, addr)
		if err != nil {
			return err
		}
		// run server
		return server.RunGrpc(ctx, s, l, opts.ShutdownTimeout)
	}
}

func setHealth(healthServer *health.Server, phase state.Phase) {
	status := healthpb.HealthCheckResponse_NOT_SERVING
	switch phase {
	case state.Ready, state.Degraded:
		status = healthpb.HealthCheckResponse_SERVING
	case state.Draining:
		// Shutdown sets every service to NOT_SERVING and ignores later updates
		healthServer.Shutdown()
		return
	}
	healthServer.SetServingStatus("", status)
	healthServer.SetServingStatus(authv3.Authorization_ServiceDesc.ServiceName, status)
}
