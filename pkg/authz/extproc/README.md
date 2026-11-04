# Envoy External Processing prototype

This package hosts a prototype Envoy `ExternalProcessor` alongside the existing ext_authz server. Start it with `authz-server --extproc-address :9083`; evaluation errors return an immediate 500 by default. Set `--extproc-fail-open` to continue unmodified on evaluation errors.

Policies use `spec.evaluation.mode: EnvoyProcessor`. External policy sources are mode-filtered: the ext_authz compiler only receives `Envoy` policies, while this server only receives `EnvoyProcessor` policies. The existing Kubernetes policy watch is still restricted to `Envoy`; processor-mode policies are currently supported only through `--external-policy-source` (file, Git, or OCI sources).

## CEL contract

`object` has these fields:

- `object.phase`: `"request"` or `"response"`.
- `object.request.method`, `.path`, `.headers`, `.body`.
- `object.response.status`, `.headers`, `.body`, and `.events` (a list of `{event, id, data}` values for SSE). For a single-event `text/event-stream` response, `.body` is that event’s `data` payload; for multiple events it remains the raw framed body.

Header maps use lower-case names and combine repeated header values with `", "`. The saved request is available during response evaluation.

`Respond(...).WithHeader(...)` and `.WithoutHeader(...)` also mutate headers on the immediate local response.

The typed result helpers are:

- `extproc.Continue()`
- `extproc.ReplaceBody(string)`
- `extproc.Respond(int)`
- `result.WithBody(string)`, `.WithHeader(name, value)`, `.WithoutHeader(name)`
- `extproc.Marshal(dynValue)` for JSON serialization after `json.Unmarshal` and CEL transformations.

`WithBody` marks the result as a body replacement; it can be chained from either `Continue`, `Respond`, or `ReplaceBody`. `Respond` creates an Envoy ImmediateResponse. Header mutations apply to the current phase. When replacing a normal body, the processor sets `content-length` to the new byte length. For a rewritten SSE event, it preserves the event and ID fields and removes `content-length` (the expected framing is chunked). When setting a new normal-body length, it also removes `transfer-encoding` to avoid conflicting framing headers.

## Example: filter MCP tools/list by user

This policy removes `kube-tools__scale_deployment` from a tools/list JSON-RPC response for everyone except `bob`. The response input uses the request's saved `x-user` header. Copy the same manifest from `testdata/tools-list-filter.yaml`.

```yaml
apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: tools-list-filter
spec:
  evaluation:
    mode: EnvoyProcessor
  failurePolicy: Fail
  variables:
    - name: body
      expression: json.Unmarshal(object.response.body)
  validations:
    - expression: >-
        object.phase == "response"
        && (object.request.method != "POST" || object.request.path != "/mcp" || object.response.status != 200)
        ? extproc.Respond(500).WithBody("unexpected request context")
        : null
    - expression: >-
        object.phase == "response"
        && (object.response.events.size() != 1
          || object.response.events[0].event != "message"
          || object.response.events[0].id == "")
        ? extproc.Respond(500).WithBody("expected one identified SSE event")
        : null
    - expression: >-
        object.phase != "response" || object.request.headers["x-user"] == "bob"
        ? null
        : extproc.ReplaceBody(extproc.Marshal(dyn({
            "jsonrpc": dyn(variables.body.jsonrpc),
            "id": dyn(variables.body.id),
            "result": dyn({
              "ttlMs": dyn(variables.body.result.ttlMs),
              "cacheScope": dyn(variables.body.result.cacheScope),
              "tools": dyn(variables.body.result.tools.filter(
                tool, tool.name != "kube-tools__scale_deployment"
              ))
            })
          })))
```

## Prototype limitations

Configure Envoy for buffered request and response bodies. Header-only end-of-stream requests are evaluated with an empty body. A response-only stream (for example an ext_authz/JWT 401 or 403) is passed through without evaluation because no request identity is available. Non-final streamed chunks are continued without mutation; if a body arrives in multiple chunks, final evaluation is skipped to avoid replacing only the last chunk. Any non-identity `content-encoding` on a response skips response policy evaluation. SSE bodies are parsed into `object.response.events`; replacing the body of a single-event SSE response rewrites its `data:` payload while preserving `event:` and `id:`. Rewriting multi-event SSE responses is not supported and fails with an immediate 500. Body size limits and processing timeouts must be configured in Envoy. Policy failures fail closed by default, but the `--extproc-fail-open` option can opt into pass-through.
