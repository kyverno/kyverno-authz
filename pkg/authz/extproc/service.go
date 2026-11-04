package extproc

import (
	"context"
	"io"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	celproc "github.com/kyverno/kyverno-authz/pkg/cel/libs/authz/extproc"
	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/extensions/policy"
	"k8s.io/client-go/dynamic"
	ctrl "sigs.k8s.io/controller-runtime"
)

type service struct {
	extprocv3.UnimplementedExternalProcessorServer
	engine    core.Engine[dynamic.Interface, celproc.Input, policy.Evaluation[*celproc.Result]]
	dynclient dynamic.Interface
	failOpen  bool
}

type streamState struct {
	request            celproc.Request
	requestSeen        bool
	requestBody        []byte
	requestBodyChunks  int
	response           celproc.Response
	responseBody       []byte
	responseBodyChunks int
	responseSSE        bool
	sseEvents          []celproc.SSEEvent
	skipResponse       bool
}

func (s *service) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	state := &streamState{
		request:  celproc.Request{Headers: map[string]string{}},
		response: celproc.Response{Headers: map[string]string{}},
	}
	for {
		request, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		response := s.process(stream.Context(), state, request)
		if response == nil {
			response = continueResponse(request)
		}
		if err := stream.Send(response); err != nil {
			return err
		}
	}
}

func (s *service) process(ctx context.Context, state *streamState, request *extprocv3.ProcessingRequest) *extprocv3.ProcessingResponse {
	switch message := request.GetRequest().(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		state.requestSeen = true
		state.request.Headers = mapHeaders(message.RequestHeaders.GetHeaders())
		state.request.Method = state.request.Headers[":method"]
		state.request.Path = state.request.Headers[":path"]
		if !message.RequestHeaders.GetEndOfStream() {
			return nil
		}
		return s.response(ctx, state, "request", nil, true)
	case *extprocv3.ProcessingRequest_RequestBody:
		state.requestBody = append(state.requestBody, message.RequestBody.GetBody()...)
		state.requestBodyChunks++
		if !message.RequestBody.GetEndOfStream() {
			return nil
		}
		if state.requestBodyChunks > 1 {
			return nil
		}
		return s.response(ctx, state, "request", state.requestBody, false)
	case *extprocv3.ProcessingRequest_ResponseHeaders:
		state.response.Headers = mapHeaders(message.ResponseHeaders.GetHeaders())
		if !state.requestSeen {
			state.skipResponse = true
			ctrl.LoggerFrom(ctx).Info("skipping ext_proc response policy because this stream has no request phase")
			return nil
		}
		state.response.Status = statusFromHeaders(state.response.Headers)
		encoding := strings.ToLower(strings.TrimSpace(state.response.Headers["content-encoding"]))
		if encoding != "" && encoding != "identity" {
			state.skipResponse = true
			ctrl.LoggerFrom(ctx).Info("skipping ext_proc response policy for content-encoded response", "contentEncoding", encoding)
			return nil
		}
		state.responseSSE = strings.Contains(strings.ToLower(state.response.Headers["content-type"]), "text/event-stream")
		if !message.ResponseHeaders.GetEndOfStream() {
			return nil
		}
		return s.response(ctx, state, "response", nil, true)
	case *extprocv3.ProcessingRequest_ResponseBody:
		state.responseBody = append(state.responseBody, message.ResponseBody.GetBody()...)
		state.responseBodyChunks++
		if state.skipResponse || !message.ResponseBody.GetEndOfStream() {
			return nil
		}
		if state.responseBodyChunks > 1 {
			return nil
		}
		return s.response(ctx, state, "response", state.responseBody, false)
	case *extprocv3.ProcessingRequest_RequestTrailers, *extprocv3.ProcessingRequest_ResponseTrailers:
		return nil
	default:
		return continueResponse(request)
	}
}

func mapHeaders(headerMap *corev3.HeaderMap) map[string]string {
	result := map[string]string{}
	if headerMap == nil {
		return result
	}
	for _, header := range headerMap.GetHeaders() {
		if header == nil {
			continue
		}
		key := strings.ToLower(header.GetKey())
		value := header.GetValue()
		if len(header.GetRawValue()) != 0 {
			value = string(header.GetRawValue())
		}
		if previous, ok := result[key]; ok {
			result[key] = previous + ", " + value
		} else {
			result[key] = value
		}
	}
	return result
}
