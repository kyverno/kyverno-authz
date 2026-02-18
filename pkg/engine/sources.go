package engine

import (
	"github.com/kyverno/sdk/core"
)

type EnvoySource = core.Source[EnvoyPolicy]
type HTTPSource = core.Source[HTTPPolicy]
