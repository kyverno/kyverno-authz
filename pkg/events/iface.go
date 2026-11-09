package events

import (
	"context"
	"fmt"
	"strconv"
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
	result     any
	err        error
	policyName string
}

func NewResultAccessor(res any, err error, policyName ...string) *resultAccessorImpl {
	name := ""
	if len(policyName) != 0 {
		name = policyName[0]
	}
	return &resultAccessorImpl{
		result:     res,
		err:        err,
		policyName: name,
	}
}

// ReportMetadata is optional so existing ResultAccessor implementations remain compatible.
func (r *resultAccessorImpl) ReportMetadata() (string, map[string]string) {
	properties := map[string]string{}
	if r.policyName != "" {
		properties["policy-kind"] = "ValidatingPolicy"
	}
	switch res := r.result.(type) {
	case *authv3.CheckResponse:
		if denied := res.GetDeniedResponse(); denied != nil {
			properties["status"] = strconv.Itoa(int(denied.GetStatus().GetCode()))
			properties["reason"] = denied.GetBody()
		} else if res.GetOkResponse() != nil {
			properties["status"] = "200"
		}
	case http.CheckResponse:
		if res.Denied != nil {
			properties["reason"] = res.Denied.Reason
		}
	}
	return r.policyName, properties
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

type event[Req any] struct {
	t   time.Time
	req Req
	res ResultAccessor
}

func NewComposite[Req any](subsribers ...EventIface[Req]) EventIface[Req] {
	return &CompositeEventSubscriber[Req]{
		inner: subsribers,
	}
}

func (c *CompositeEventSubscriber[Req]) Push(ctx context.Context, t time.Time, req Req, res ResultAccessor) {
	for _, sub := range c.inner {
		sub.Push(ctx, t, req, res)
	}
}
