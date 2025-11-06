package sender

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	protov1alpha1 "github.com/kyverno/kyverno-authz/pkg/control-plane/proto/v1alpha1"

	"github.com/kyverno/kyverno-authz/pkg/utils"
	"go.uber.org/multierr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	ctrl "sigs.k8s.io/controller-runtime"
)

type PolicySender struct {
	protov1alpha1.UnimplementedValidatingPolicyServiceServer
	polMu                     *sync.Mutex
	policies                  map[string]*protov1alpha1.ValidatingPolicy
	currentVersion            int64
	healthCheckMap            map[string]time.Time
	cxnMu                     *sync.Mutex
	cxnsMap                   map[string]*clientConn
	ctx                       context.Context
	initialSendPolicyWait     time.Duration // how long to wait before the second attempt of a failed policy send
	maxSendPolicyInterval     time.Duration // the maximum duration to wait before stopping attempts of a policy send
	clientFlushInterval       time.Duration // how often we remove unhealthy clients from the map
	maxClientInactiveDuration time.Duration // how long should we wait before deciding this client is unhealthy
}

func NewPolicySender(
	ctx context.Context,
	initialSendPolicyWait time.Duration,
	maxSendPolicyInterval time.Duration,
	clientFlushInterval time.Duration,
	maxClientInactiveDuration time.Duration,
) *PolicySender {
	return &PolicySender{
		polMu:                     &sync.Mutex{},
		cxnMu:                     &sync.Mutex{},
		ctx:                       ctx,
		currentVersion:            1,
		policies:                  make(map[string]*protov1alpha1.ValidatingPolicy),
		healthCheckMap:            make(map[string]time.Time),
		cxnsMap:                   make(map[string]*clientConn),
		initialSendPolicyWait:     initialSendPolicyWait,
		maxSendPolicyInterval:     maxSendPolicyInterval,
		clientFlushInterval:       clientFlushInterval,
		maxClientInactiveDuration: maxClientInactiveDuration,
	}
}

/*
 * when a new policy comes, we spawn a sender per client,
 * when the client sends a message with current version equal to the current version of the
 */

type clientConn struct {
	cancelFunc context.CancelFunc
	stream     grpc.BidiStreamingServer[protov1alpha1.ValidatingPolicyStreamRequest, protov1alpha1.ValidatingPolicyStreamResponse]
}

func (s *PolicySender) StartHealthCheckMonitor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.clientFlushInterval):
			s.deleteInactive()
		}
	}
}

func (s *PolicySender) SendPolicy(pol *protov1alpha1.ValidatingPolicy) {
	errCh := make(chan error)
	var wg sync.WaitGroup
	wg.Add(len(s.cxnsMap))
	s.currentVersion++
	// send to clients, but don't wait on any of them
	for _, state := range s.cxnsMap {
		if state.cancelFunc != nil {
			state.cancelFunc() // stop all ongoing sync attempts
		}
	}
	for _, conn := range s.cxnsMap {
		ctx, cancel := context.WithCancel(context.Background())
		conn.cancelFunc = cancel
		go func() {
			defer wg.Done()
			polResp := protov1alpha1.ValidatingPolicyStreamResponse{
				CurrentVersion: s.currentVersion,
				Policies:       utils.ToSortedSlice(s.policies),
			}
			errCh <- s.sendWithBackoff(ctx, conn.stream, &polResp)
		}()
	}

	wg.Wait()
	close(errCh)

	errs := make([]error, len(errCh))
	for e := range errCh {
		errs = append(errs, e)
	}
	if len(errs) > 0 {
		ctrl.LoggerFrom(nil).Error(multierr.Combine(errs...), "failed to send policy")
	}
}

func (s *PolicySender) StorePolicy(pol *protov1alpha1.ValidatingPolicy) {
	s.polMu.Lock()
	defer s.polMu.Unlock()
	s.policies[pol.Name] = pol
}

func (s *PolicySender) DeletePolicy(polName string) {
	s.polMu.Lock()
	defer s.polMu.Unlock()
	delete(s.policies, polName)
}

func (s *PolicySender) HealthCheck(ctx context.Context, r *protov1alpha1.HealthCheckRequest) (*protov1alpha1.HealthCheckResponse, error) {
	if r.ClientAddress == "" || r.Time == nil {
		return nil, nil // invalid request, do nothing
	}
	// s.logger.Debugf("got health check message from %s, time: %s", r.ClientAddress, r.Time.AsTime().Format(time.RFC3339))
	t, ok := s.healthCheckMap[r.ClientAddress]
	if !ok || r.Time.AsTime().After(t) {
		s.healthCheckMap[r.ClientAddress] = r.Time.AsTime()
	}
	return &protov1alpha1.HealthCheckResponse{}, nil
}

func (s *PolicySender) ValidatingPoliciesStream(stream grpc.BidiStreamingServer[protov1alpha1.ValidatingPolicyStreamRequest, protov1alpha1.ValidatingPolicyStreamResponse]) error {
	for {
		select {
		case <-s.ctx.Done():
			return nil
		default:
			req, err := stream.Recv()
			if err == io.EOF {
				if p, ok := peer.FromContext(stream.Context()); ok {
					ctrl.LoggerFrom(nil).Info(fmt.Sprintf("Receiver at %s closed the stream", p.Addr))
				} else {
					ctrl.LoggerFrom(nil).Info("Receiver closed the stream")
				}
				return nil
			}
			if err != nil {
				if p, ok := peer.FromContext(stream.Context()); ok {
					ctrl.LoggerFrom(nil).Info(fmt.Sprintf("Receiver at %s errored", p.Addr))
				} else {
					ctrl.LoggerFrom(nil).Info("Receiver errored")
				}
				return err
			}
			ctrl.LoggerFrom(nil).Info(fmt.Sprintf("Received validating policy stream request from: %s", req.ClientAddress))

			if conn, ok := s.cxnsMap[req.ClientAddress]; ok {
				if conn.cancelFunc != nil {
					conn.cancelFunc()
					conn.cancelFunc = nil
				}
			}

			ctx, cancel := context.WithCancel(context.Background())
			conn := &clientConn{stream: stream, cancelFunc: cancel}
			s.cxnMu.Lock()
			s.cxnsMap[req.ClientAddress] = conn
			s.cxnMu.Unlock()

			go func(conn *clientConn) {
				polResp := protov1alpha1.ValidatingPolicyStreamResponse{
					CurrentVersion: s.currentVersion,
					Policies:       utils.ToSortedSlice(s.policies),
				}

				if err := s.sendWithBackoff(ctx, conn.stream, &polResp); err != nil {
					ctrl.LoggerFrom(nil).Error(err, "Error sending policy with backoff")
				}
			}(conn)
		}
	}
}
func (s *PolicySender) sendWithBackoff(
	ctx context.Context,
	stream grpc.BidiStreamingServer[
		protov1alpha1.ValidatingPolicyStreamRequest,
		protov1alpha1.ValidatingPolicyStreamResponse,
	],
	pol *protov1alpha1.ValidatingPolicyStreamResponse,
) error {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = s.initialSendPolicyWait
	b.MaxInterval = s.maxSendPolicyInterval
	b.MaxElapsedTime = 0

	backoffCtx := backoff.WithContext(b, ctx)

	return backoff.RetryNotify(
		func() error { return stream.Send(pol) },
		backoffCtx,
		func(err error, d time.Duration) {
			fmt.Printf("failed to send policy: %v, retrying in %v", err, d)
		},
	)
}

func (s *PolicySender) deleteInactive() {
	defer s.cxnMu.Unlock()
	inactiveClients := s.getInactiveClients()
	s.cxnMu.Lock()
	for _, c := range inactiveClients {
		ctrl.LoggerFrom(nil).Info(fmt.Sprintf("deleting %s from active clients", c))
		delete(s.cxnsMap, c)
		delete(s.healthCheckMap, c)
	}
}

func (s *PolicySender) getInactiveClients() []string {
	clientsToDelete := []string{}
	for c, t := range s.healthCheckMap {
		if elapsed := time.Since(t); elapsed > s.maxClientInactiveDuration {
			clientsToDelete = append(clientsToDelete, c)
		}
	}
	return clientsToDelete
}
