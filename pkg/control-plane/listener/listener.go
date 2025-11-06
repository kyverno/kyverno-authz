package listener

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	protov1alpha1 "github.com/kyverno/kyverno-authz/pkg/control-plane/proto/v1alpha1"
	"google.golang.org/grpc"
	grpcbackoff "google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
	ctrl "sigs.k8s.io/controller-runtime"
)

type Processor interface {
	Process(policies []*protov1alpha1.ValidatingPolicy)
}

type policyListener struct {
	controlPlaneAddr          string
	clientAddr                string
	currentVersion            int64
	client                    protov1alpha1.ValidatingPolicyServiceClient
	conn                      *grpc.ClientConn
	processor                 Processor
	connEstablished           bool
	controlPlaneReconnectWait time.Duration
	healthCheckInterval       time.Duration
	stream                    grpc.BidiStreamingClient[protov1alpha1.ValidatingPolicyStreamRequest, protov1alpha1.ValidatingPolicyStreamResponse]
}

func NewPolicyListener(
	controlPlaneAddr string,
	clientAddr string,
	processor Processor,
	controlPlaneReconnectWait,
	healthCheckInterval time.Duration) *policyListener {
	return &policyListener{
		controlPlaneAddr:          controlPlaneAddr,
		processor:                 processor,
		clientAddr:                clientAddr,
		controlPlaneReconnectWait: controlPlaneReconnectWait,
		healthCheckInterval:       healthCheckInterval,
	}
}

func (l *policyListener) Start(ctx context.Context) error {
loop:
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			if err := l.dial(ctx); err != nil {
				time.Sleep(l.controlPlaneReconnectWait)
				ctrl.LoggerFrom(nil).Error(err, "")
				continue
			}
			break loop
		}
	}
	go l.sendHealthChecks(ctx) // start sending health checks
	if err := l.listen(ctx); err != nil {
		return err
	}
	return nil
}

func (l *policyListener) dial(ctx context.Context) error {
	ctrl.LoggerFrom(ctx).Info(fmt.Sprintf("Connecting to control plane at %s", l.controlPlaneAddr))
	l.connEstablished = false // mark new connection

	// Block until either connected or context cancelled
	conn, err := grpc.NewClient(
		l.controlPlaneAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),

		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: grpcbackoff.Config{
				BaseDelay:  0,
				Multiplier: 1.0,
				MaxDelay:   0,
			},
		}),
	)

	l.conn = conn
	l.client = protov1alpha1.NewValidatingPolicyServiceClient(conn)

	stream, err := l.client.ValidatingPoliciesStream(ctx)
	if err != nil {
		conn.Close() // close connection if stream creation fails
		return fmt.Errorf("failed to open policy stream: %w", err)
	}

	l.stream = stream
	l.connEstablished = true
	return nil
}

func (l *policyListener) InitialSync(ctx context.Context) error {
	ctrl.LoggerFrom(nil).Info("Running initial policy sync...")
	// Establish connection
	if err := l.dial(ctx); err != nil {
		return nil
	}

	if err := l.stream.Send(&protov1alpha1.ValidatingPolicyStreamRequest{ClientAddress: l.clientAddr}); err != nil {
		ctrl.LoggerFrom(nil).Error(err, "Error sending initial sync request")
		return err
	}
	req, err := l.stream.Recv()
	if err == io.EOF {
		ctrl.LoggerFrom(nil).Error(err, "Policy sender closed the stream")
		return nil
	}
	if err != nil {
		ctrl.LoggerFrom(nil).Error(err, "Error receiving initial policy request")
		return err
	}

	ctrl.LoggerFrom(nil).Info(fmt.Sprintf("Received validating policy request with version: %d", req.CurrentVersion))
	if req.CurrentVersion != l.currentVersion {
		l.currentVersion = req.CurrentVersion
	}
	// wait for processing to be over in the initial sync, its fine if it errors
	var wg sync.WaitGroup
	wg.Go(func() { l.processor.Process(req.Policies) })
	wg.Wait()
	ctrl.LoggerFrom(nil).Info("Policy listener has synced")
	return nil
}

func (l *policyListener) listen(ctx context.Context) error {
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-ctx.Done():
				ctrl.LoggerFrom(nil).Info("Stopping policy listener due to context cancellation")
				if err := l.stream.CloseSend(); err != nil {
					ctrl.LoggerFrom(nil).Error(err, "Error closing stream")
				}

				if l.conn != nil {
					if err := l.conn.Close(); err != nil {
						ctrl.LoggerFrom(nil).Error(err, "Error closing connection")
					}
				}
				return
			default:
				// guard against sending unnecessary messages to the control plane
				if !l.connEstablished {
					if err := l.stream.Send(&protov1alpha1.ValidatingPolicyStreamRequest{ClientAddress: l.clientAddr}); err != nil {
						ctrl.LoggerFrom(nil).Error(err, "Error sending to stream")
						return
					}
					l.connEstablished = true
				}
				req, err := l.stream.Recv()
				if err == io.EOF {
					ctrl.LoggerFrom(nil).Error(err, "Policy sender closed the stream")
					return
				}
				if err != nil {
					ctrl.LoggerFrom(nil).Error(err, "Error receiving policy request")
					return
				}
				// request with no new data, do nothing
				if req.CurrentVersion == l.currentVersion {
					continue
				}

				ctrl.LoggerFrom(nil).Info(fmt.Sprintf("Received validating policy request with version: %d", req.CurrentVersion))
				go func() { l.processor.Process(req.Policies) }()
			}
		}
	})
	ctrl.LoggerFrom(nil).Info("Policy listener running...")
	wg.Wait()
	return nil
}

func (l *policyListener) sendHealthChecks(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(l.healthCheckInterval):
			if _, err := l.client.HealthCheck(ctx, &protov1alpha1.HealthCheckRequest{
				ClientAddress: l.clientAddr,
				Time:          timestamppb.Now()}); err != nil {
				ctrl.LoggerFrom(ctx).Error(err, "Health check failed")
			}
			continue
		}
	}
}
