package extproc

import (
	"context"
	"fmt"
	"net"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	celproc "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/extproc"
	"github.com/kyverno/kyverno-authz/pkg/engine"
	"github.com/kyverno/kyverno-authz/pkg/server"
	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/core/dispatchers"
	"github.com/kyverno/sdk/core/handlers"
	"github.com/kyverno/sdk/core/resulters"
	"github.com/kyverno/sdk/extensions/policy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"k8s.io/client-go/dynamic"
	ctrl "sigs.k8s.io/controller-runtime"
)

func newService(source engine.ProcessorSource, dynclient dynamic.Interface, failOpen bool) *service {
	return &service{
		engine: core.NewEngine(source, handlers.Handler(
			dispatchers.Sequential(
				policy.EvaluatorFactory[engine.ProcessorPolicy](),
				func(_ context.Context, _ core.FactoryContext[engine.ProcessorPolicy, dynamic.Interface, celproc.Input]) core.Breaker[engine.ProcessorPolicy, celproc.Input, policy.Evaluation[*celproc.Result]] {
					return core.MakeBreakerFunc(func(_ context.Context, _ engine.ProcessorPolicy, _ celproc.Input, out policy.Evaluation[*celproc.Result]) bool {
						return out.Result != nil || out.Error != nil
					})
				},
			),
			func(_ context.Context, _ core.FactoryContext[engine.ProcessorPolicy, dynamic.Interface, celproc.Input]) core.Resulter[engine.ProcessorPolicy, celproc.Input, policy.Evaluation[*celproc.Result], policy.Evaluation[*celproc.Result]] {
				return resulters.NewFirst[engine.ProcessorPolicy, celproc.Input](func(out policy.Evaluation[*celproc.Result]) bool {
					return out.Result != nil || out.Error != nil
				})
			},
		)),
		dynclient: dynclient,
		failOpen:  failOpen,
	}
}

func NewServer(network, addr string, source engine.ProcessorSource, dynclient dynamic.Interface, failOpen bool) server.ServerFunc {
	return func(ctx context.Context) error {
		grpcServer := grpc.NewServer()
		processor := newService(source, dynclient, failOpen)
		extprocv3.RegisterExternalProcessorServer(grpcServer, processor)
		reflection.Register(grpcServer)
		listener, err := net.Listen(network, addr)
		if err != nil {
			return err
		}
		return server.RunGrpc(ctx, grpcServer, listener)
	}
}

var _ extprocv3.ExternalProcessorServer = (*service)(nil)

func immediate(status int64, body, details string) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extprocv3.ImmediateResponse{
			Status:  &typev3.HttpStatus{Code: typev3.StatusCode(status)},
			Body:    []byte(body),
			Details: details,
		},
	}}
}

func continueCommon() *extprocv3.CommonResponse {
	return &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE}
}

func (s *service) failResponse(err error) *extprocv3.ProcessingResponse {
	if s.failOpen {
		ctrl.Log.Error(err, "ext_proc policy evaluation failed; continuing because fail-open is enabled")
		return nil
	}
	ctrl.Log.Error(err, "ext_proc policy evaluation failed; returning 500")
	return immediate(500, "policy evaluation failed", "kyverno_ext_proc_error")
}

func (s *service) evaluate(ctx context.Context, input celproc.Input) (*celproc.Result, error) {
	out := s.engine.Handle(ctx, s.dynclient, input)
	if out.Error != nil {
		return nil, out.Error
	}
	return out.Result, nil
}

func headerMutation(result *celproc.Result, bodyChanged, updateContentLength bool) *extprocv3.HeaderMutation {
	mutation := &extprocv3.HeaderMutation{}
	for _, header := range result.Headers {
		if bodyChanged && strings.EqualFold(header.Name, "content-length") {
			continue
		}
		if bodyChanged && updateContentLength && strings.EqualFold(header.Name, "transfer-encoding") {
			continue
		}
		if header.Remove {
			mutation.RemoveHeaders = append(mutation.RemoveHeaders, strings.ToLower(header.Name))
		} else {
			mutation.SetHeaders = append(mutation.SetHeaders, &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: strings.ToLower(header.Name), RawValue: []byte(header.Value)}, AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD})
		}
	}
	if bodyChanged && updateContentLength {
		mutation.RemoveHeaders = append(mutation.RemoveHeaders, "transfer-encoding")
		mutation.SetHeaders = append(mutation.SetHeaders, &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: "content-length", Value: fmt.Sprint(len(result.Body))}, AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD})
	} else if bodyChanged {
		mutation.RemoveHeaders = append(mutation.RemoveHeaders, "content-length")
	}
	if len(mutation.SetHeaders) == 0 && len(mutation.RemoveHeaders) == 0 {
		return nil
	}
	return mutation
}

func (s *service) response(ctx context.Context, state *streamState, phase string, body []byte, headers bool) *extprocv3.ProcessingResponse {
	responseBody := string(body)
	if phase == "response" && state.responseSSE {
		state.sseEvents = parseSSE(body)
		if len(state.sseEvents) == 1 {
			responseBody = state.sseEvents[0].Data
		}
	}
	input := celproc.Input{
		Phase: phase,
		Request: celproc.Request{
			Method:  state.request.Method,
			Path:    state.request.Path,
			Headers: cloneMap(state.request.Headers),
			Body:    string(state.requestBody),
		},
		Response: celproc.Response{
			Status:  state.response.Status,
			Headers: cloneMap(state.response.Headers),
			Body:    responseBody,
			Events:  append([]celproc.SSEEvent{}, state.sseEvents...),
		},
	}
	result, err := s.evaluate(ctx, input)
	if err != nil {
		return s.failResponse(err)
	}
	if result == nil || result.Action == "continue" && !result.ReplaceBody && len(result.Headers) == 0 {
		return nil
	}
	if result.Action == "respond" {
		if result.Status < 100 || result.Status > 599 {
			return immediate(500, "invalid response status in policy", "kyverno_ext_proc_invalid_status")
		}
		response := immediate(result.Status, result.Body, "kyverno_ext_proc_response")
		response.GetImmediateResponse().Headers = headerMutation(result, false, false)
		return response
	}
	if result.Action != "continue" {
		return immediate(500, "invalid ext_proc policy result", "kyverno_ext_proc_invalid_result")
	}
	if result.ReplaceBody && phase == "response" && state.responseSSE {
		if len(state.sseEvents) != 1 {
			return immediate(500, "SSE body replacement requires exactly one event", "kyverno_ext_proc_sse_mutation_error")
		}
		result.Body = frameSSE(state.sseEvents[0], result.Body)
	}
	common := &extprocv3.CommonResponse{Status: extprocv3.CommonResponse_CONTINUE}
	// Body messages apply BodyMutation with CONTINUE. Header messages require
	// CONTINUE_AND_REPLACE to supply a body and stop further messages for this phase.
	if headers && result.ReplaceBody {
		common.Status = extprocv3.CommonResponse_CONTINUE_AND_REPLACE
	}
	if result.ReplaceBody {
		common.BodyMutation = &extprocv3.BodyMutation{Mutation: &extprocv3.BodyMutation_Body{Body: []byte(result.Body)}}
	}
	common.HeaderMutation = headerMutation(result, result.ReplaceBody, !(phase == "response" && state.responseSSE))
	if headers {
		if phase == "request" {
			return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{RequestHeaders: &extprocv3.HeadersResponse{Response: common}}}
		}
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{ResponseHeaders: &extprocv3.HeadersResponse{Response: common}}}
	}
	if phase == "request" {
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{RequestBody: &extprocv3.BodyResponse{Response: common}}}
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{ResponseBody: &extprocv3.BodyResponse{Response: common}}}
}

func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func continueResponse(req *extprocv3.ProcessingRequest) *extprocv3.ProcessingResponse {
	switch req.GetRequest().(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{RequestHeaders: &extprocv3.HeadersResponse{Response: continueCommon()}}}
	case *extprocv3.ProcessingRequest_ResponseHeaders:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{ResponseHeaders: &extprocv3.HeadersResponse{Response: continueCommon()}}}
	case *extprocv3.ProcessingRequest_RequestBody:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{RequestBody: &extprocv3.BodyResponse{Response: continueCommon()}}}
	case *extprocv3.ProcessingRequest_ResponseBody:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{ResponseBody: &extprocv3.BodyResponse{Response: continueCommon()}}}
	case *extprocv3.ProcessingRequest_RequestTrailers:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{RequestTrailers: &extprocv3.TrailersResponse{}}}
	case *extprocv3.ProcessingRequest_ResponseTrailers:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseTrailers{ResponseTrailers: &extprocv3.TrailersResponse{}}}
	default:
		return immediate(500, "unsupported ext_proc message", "kyverno_ext_proc_unsupported_message")
	}
}

func statusFromHeaders(headers map[string]string) int64 {
	var code int64
	_, _ = fmt.Sscan(headers[":status"], &code)
	return code
}

func parseSSE(body []byte) []celproc.SSEEvent {
	normalized := strings.ReplaceAll(string(body), "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	events := []celproc.SSEEvent{}
	current := celproc.SSEEvent{}
	dataLines := []string{}
	flush := func() {
		if len(dataLines) == 0 && current.Event == "" && current.ID == "" {
			return
		}
		if current.Event == "" {
			current.Event = "message"
		}
		current.Data = strings.Join(dataLines, "\n")
		events = append(events, current)
		current = celproc.SSEEvent{}
		dataLines = nil
	}
	for _, line := range strings.Split(normalized, "\n") {
		if line == "" {
			flush()
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, hasValue := strings.Cut(line, ":")
		if hasValue {
			value = strings.TrimPrefix(value, " ")
		}
		switch field {
		case "event":
			current.Event = value
		case "id":
			current.ID = value
		case "data":
			dataLines = append(dataLines, value)
		}
	}
	flush()
	return events
}

func frameSSE(event celproc.SSEEvent, data string) string {
	var framed strings.Builder
	if event.Event != "" {
		fmt.Fprintf(&framed, "event: %s\n", event.Event)
	}
	if event.ID != "" {
		fmt.Fprintf(&framed, "id: %s\n", event.ID)
	}
	for _, line := range strings.Split(data, "\n") {
		fmt.Fprintf(&framed, "data: %s\n", line)
	}
	framed.WriteByte('\n')
	return framed.String()
}
