package server

import (
	"context"
	"net"
	"time"

	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/util/wait"
	ctrl "sigs.k8s.io/controller-runtime"
)

// RunGrpc serves until ctx is done, then stops gracefully. If shutdownTimeout
// is positive and in-flight requests don't finish in time, it stops the server
// forcibly.
func RunGrpc(ctx context.Context, server *grpc.Server, listener net.Listener, shutdownTimeout time.Duration) error {
	logger := ctrl.LoggerFrom(ctx).
		WithValues("address", listener.Addr()).
		WithValues("network", listener.Addr().Network())
	defer logger.Info("GRPC Server stopped")
	// create a wait group
	var group wait.Group
	// wait all tasks in the group are over
	defer group.Wait()
	// create a cancellable context
	ctx, cancel := context.WithCancel(ctx)
	// cancel context at the end
	defer cancel()
	// shutdown server when context is cancelled
	group.StartWithContext(ctx, func(ctx context.Context) {
		// wait context cancelled
		<-ctx.Done()
		logger.Info("GRPC Server shutting down...")
		// gracefully shutdown server
		stopped := make(chan struct{})
		go func() {
			server.GracefulStop()
			close(stopped)
		}()
		if shutdownTimeout <= 0 {
			<-stopped
			return
		}
		timer := time.NewTimer(shutdownTimeout)
		defer timer.Stop()
		select {
		case <-stopped:
		case <-timer.C:
			logger.Info("GRPC Server graceful shutdown timed out, stopping", "timeout", shutdownTimeout)
			server.Stop()
		}
	})
	logger.Info("GRPC Server starting...")
	// serve
	return server.Serve(listener)
}
