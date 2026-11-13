package probes

import (
	"context"
	"net/http"

	"github.com/kyverno/kyverno-authz/pkg/server"
	"github.com/kyverno/kyverno-authz/pkg/server/handlers"
)

// NewServer serves /livez, which always passes, and /readyz, which passes
// while ready returns true.
func NewServer(addr string, ready func() bool) server.ServerFunc {
	return func(ctx context.Context) error {
		// create mux
		mux := http.NewServeMux()
		// register health check
		mux.Handle("GET /livez", handlers.Healthy(True))
		// register ready check
		mux.Handle("GET /readyz", handlers.Ready(ready))
		// create server
		s := &http.Server{
			Addr:    addr,
			Handler: mux,
		}
		// run server
		return server.RunHttp(ctx, s, "", "")
	}
}
