package engine

import (
	"github.com/kyverno/kyverno-authz/sdk/core"
)

type EnvoySource = core.Source[EnvoyPolicy]
type HTTPSource = core.Source[HTTPPolicy]
