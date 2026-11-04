# Authz Server

The **Kyverno Authz Server** provides programmable and flexible, policy-based authorization for **Envoy proxies** and **HTTP services**.

It uses **Kyverno policies** written in **CEL (Common Expression Language)** to deliver fine-grained, context-aware access control and make a decision given an input request description.

!!! info
    The Kyverno Authz Server runs seamlessly in Kubernetes or as a standalone service outside Kubernetes environments.

## Key Capabilities

- **Dual-mode operation** – Works with Envoy (gRPC) or standalone HTTP services
- **Programmable** – Adapts to the underlying protocol (NGINX, Traefik, ...)
- **Policy-driven authorization** – Write policies using CEL with your decision logic for fast evaluation
- **External data integration** – Query HTTP services, fetch Kubernetes resources or OCI images data for decision-making
- **Lightweight sidecar model** – Low-latency local enforcement with centralized policy management

## Running Modes

- [Envoy Support](./envoy/index.md)
- [HTTP Support](./http/index.md)

## Authorization events and reports

OpenReports results identify the selected decision policy in `policy`, set
`source: kyverno-authz`, and leave `rule` empty. Allowed, denied, and errored
checks produce `pass`, `fail`, and `error` results respectively. Properties
include `method`, `path`, and `host`. Denials include a `reason` (Envoy denied
response body or HTTP denied reason) and a `status` (Envoy HTTP status or the
status produced by the HTTP output expression). Policies that do not expose a
name, and default decisions without a selected policy, leave `policy` empty.

Descriptions (the Go `Description` field, serialized as `message`) retain the
configured `--log-msg-format`, with a redacted JSON request. OpenReports, Kubernetes Events, and writer event logs replace sensitive
header values with `[REDACTED]`, case-insensitively: `authorization`,
`proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`, `api-key`, and any
header name containing `token` or `secret`. Both Envoy header representations
are covered. Request bodies and HTTP parsed MCP payloads are omitted; request
size metadata is retained. The original authorization request is not modified.

For example, an Envoy denial produces these result fields (other fields omitted):

```yaml
policy: tool-guardrails
source: kyverno-authz
result: fail
properties:
  method: POST
  path: /tools/call
  host: tools.internal
  status: "403"
  reason: Tool access denied
message: |
  [2026-10-19T12:00:00Z] envoy: request {"attributes":{"request":{"http":{"method":"POST","headers":{"authorization":"[REDACTED]"},"path":"/tools/call","host":"tools.internal","size":42}}}}, response: Denied
```

Do not echo credentials into policy error messages or denial reasons: these are
recorded as policy-provided text. URLs, query parameters, non-sensitive headers,
and other request metadata are not automatically scrubbed. Keep sensitive data
out of those fields. Event channels are bounded and can drop events under load;
reports are for observability, not a guaranteed audit trail.
