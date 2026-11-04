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
	httpStatus int
}

func NewResultAccessor(res any, err error, policyName ...string) *resultAccessorImpl {
	name := ""
	if len(policyName) != 0 {
		name = policyName[0]
	}
	return &resultAccessorImpl{
		result:     res,
		policyName: name,
		err:        err,
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
	case *http.CheckResponse:
		if res != nil && res.Denied != nil {
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

// ReportMetadata is optional so existing ResultAccessor implementations remain compatible.
func (r *resultAccessorImpl) ReportMetadata() (string, map[string]string) {
	properties := map[string]string{}
	switch res := r.result.(type) {
	case *authv3.CheckResponse:
		if denied := res.GetDeniedResponse(); denied != nil {
			properties["status"] = strconv.Itoa(int(denied.GetStatus().GetCode()))
			properties["reason"] = denied.GetBody()
		}
	case http.CheckResponse:
		if res.Denied != nil {
			properties["reason"] = res.Denied.Reason
		}
	case *http.CheckResponse:
		if res != nil && res.Denied != nil {
			properties["reason"] = res.Denied.Reason
		}
	}
	if r.httpStatus != 0 {
		properties["status"] = strconv.Itoa(r.httpStatus)
	}
	return r.policyName, properties
}

// WithHTTPStatus records the status after the HTTP output expression is evaluated.
func (r *resultAccessorImpl) WithHTTPStatus(status int) *resultAccessorImpl {
	r.httpStatus = status
	return r
}
