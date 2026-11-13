package envoy

import (
	"context"
	"net"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kyverno/kyverno-authz/pkg/authz"
	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/kyverno-authz/pkg/events"
	"github.com/kyverno/kyverno-authz/pkg/state"
	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func TestServer_HealthAndCheckFollowLifecycle(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	tracker := state.NewTracker()
	run := NewServer("tcp", addr, core.MakeSource[engine.EnvoyPolicy](), nil, events.NewComposite[*authv3.CheckRequest](), Options{
		DefaultDecision: authz.DefaultDecisionDeny,
		Tracker:         tracker,
		ShutdownTimeout: time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- run(ctx) }()
	defer func() {
		cancel()
		assert.NoError(t, <-done)
	}()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close() //nolint:errcheck
	healthClient := healthpb.NewHealthClient(conn)
	authClient := authv3.NewAuthorizationClient(conn)

	healthStatus := func() healthpb.HealthCheckResponse_ServingStatus {
		resp, err := healthClient.Check(ctx, &healthpb.HealthCheckRequest{Service: authv3.Authorization_ServiceDesc.ServiceName})
		if err != nil {
			return healthpb.HealthCheckResponse_UNKNOWN
		}
		return resp.GetStatus()
	}

	// not ready: health is NOT_SERVING and Check is UNAVAILABLE
	assert.Eventually(t, func() bool { return healthStatus() == healthpb.HealthCheckResponse_NOT_SERVING }, 5*time.Second, 10*time.Millisecond)
	_, err = authClient.Check(ctx, &authv3.CheckRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))

	// ready: health is SERVING and Check applies the default decision
	tracker.Ready()
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, healthStatus())
	resp, err := authClient.Check(ctx, &authv3.CheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(codes.PermissionDenied), resp.GetStatus().GetCode())

	// draining: health is NOT_SERVING
	tracker.Drain()
	assert.Equal(t, healthpb.HealthCheckResponse_NOT_SERVING, healthStatus())
}
