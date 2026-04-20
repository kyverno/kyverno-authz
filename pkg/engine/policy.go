package engine

import (
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
	"github.com/kyverno/sdk/extensions/policy"
	"k8s.io/client-go/dynamic"
)

type EnvoyPolicy = policy.Policy[dynamic.Interface, *authv3.CheckRequest, *authv3.CheckResponse]
type HTTPPolicy = policy.Policy[dynamic.Interface, *http.CheckRequest, *http.CheckResponse]

// Named is an optional interface that a Policy may implement to expose its name.
// This is used for per-policy observability (metrics, logging).
type Named interface {
	Name() string
}
