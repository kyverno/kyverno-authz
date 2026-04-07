package events

import (
	"context"
	"fmt"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/http"
)

var (
	RequestAllowed string = "Allowed"
	RequestDenied  string = "Denied"
	RequestErrored string = "Errored"
)

type EventIface[Req any] interface {
	Push(context.Context, time.Time, Req, ResultAccessor)
}

type CompositeEventSubscriber[Req any] struct {
	inner []EventIface[Req]
}

// its must because if there's an invalid type in the accessor the function panics
type ResultAccessor interface {
	MustGet() (string, error)
}

type resultAccessorImpl struct {
	result any
	err    error
}

func NewResultAccessor(res any, err error) *resultAccessorImpl {
	return &resultAccessorImpl{
		result: res,
		err:    err,
	}
}

func (r *resultAccessorImpl) MustGet() (string, error) {
	if r.err != nil {
		return RequestErrored, r.err
	}

	switch res := r.result.(type) {
	case *authv3.CheckResponse:
		if res.GetDeniedResponse() != nil {
			return RequestDenied, nil
		}
		return RequestAllowed, nil
	case http.CheckResponse:
		if res.Denied != nil {
			return RequestDenied, nil
		}
		return RequestAllowed, nil
	default:
		// should never happen, if it does then that's a coding error
		panic(fmt.Sprintf("got an unknown type of result in the accessor %T", res))
	}
}

func NewComposite[Req any](subsribers ...EventIface[Req]) EventIface[Req] {
	return &CompositeEventSubscriber[Req]{
		inner: subsribers,
	}
}

func (c *CompositeEventSubscriber[Req]) Push(ctx context.Context, t time.Time, req Req, res ResultAccessor) {
	for _, sub := range c.inner {
		// TODO: sync wait group and error returns if we want the process to be synchronous
		go sub.Push(ctx, t, req, res)
	}
}
