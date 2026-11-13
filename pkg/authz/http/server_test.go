package http

import (
	"context"
	"io"
	"net"
	nethttp "net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kyverno/kyverno-authz/pkg/authz"
	httpcel "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/kyverno-authz/pkg/events"
	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startServer(t *testing.T, decision authz.DefaultDecision, ready func() bool) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	run := NewServer(Config{
		Address:         addr,
		DefaultDecision: decision,
		Ready:           ready,
		ShutdownTimeout: time.Second,
	}, core.MakeSource[engine.HTTPPolicy](), nil, events.NewComposite[httpcel.CheckRequest]())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- run(ctx) }()
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, <-done)
	})
	url := "http://" + addr + "/"
	require.Eventually(t, func() bool {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond)
	return url
}

func post(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := nethttp.Post(url, "text/plain", strings.NewReader(""))
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

func TestServer_NotReadyReturnsServiceUnavailable(t *testing.T) {
	var ready atomic.Bool
	url := startServer(t, authz.DefaultDecisionAllow, ready.Load)
	code, body := post(t, url)
	assert.Equal(t, nethttp.StatusServiceUnavailable, code)
	assert.Contains(t, body, authz.NotReadyReason)

	ready.Store(true)
	code, _ = post(t, url)
	assert.Equal(t, nethttp.StatusOK, code)
}

func TestServer_DefaultDecision(t *testing.T) {
	always := func() bool { return true }
	t.Run("allow", func(t *testing.T) {
		code, _ := post(t, startServer(t, authz.DefaultDecisionAllow, always))
		assert.Equal(t, nethttp.StatusOK, code)
	})
	t.Run("deny", func(t *testing.T) {
		code, body := post(t, startServer(t, authz.DefaultDecisionDeny, always))
		assert.Equal(t, nethttp.StatusForbidden, code)
		assert.Equal(t, authz.NoMatchReason, body)
	})
}
