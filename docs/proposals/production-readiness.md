# Kyverno Authz production readiness

| | |
|---|---|
| Status | Draft for discussion |
| Owner | Jim Bugwadia |
| Last updated | 2026-11-13 |
| Scope | `main`, plus the `agent-router`, `agent-router-demo`, and `agent-router-extproc` branches |

## Goals

- Ship one production-ready Kyverno Authz that combines the features from the three Agent Router branches.
- Support Envoy, Envoy Gateway, Istio, and agentgateway through the `ext_authz` and `ext_proc` gRPC protocols.
- Run the same binary and configuration as a central Deployment or as an injected sidecar.
- Select policies and policy exceptions from the cluster, as well as from files and OCI artifacts.
- Write authorization decision reports to the cluster with bounded size across all replicas.
- Coexist with the Kyverno admission controller in the same cluster, and eventually install as an optional component of the Kyverno Helm chart.

## Non-goals

- A full audit log. Reports give a bounded, recent view of decisions. For a complete audit trail, export decisions to a log pipeline (OpenTelemetry logs or stdout).
- Replacing the MCP authorization built into agentgateway. Kyverno Authz adds Kubernetes-native policy and exceptions on top of it.

## Decisions

These are the decisions recorded so far. Each links to the section with the details.

| # | Topic | Decision | Section |
|---|---|---|---|
| D1 | Packaging | Kyverno Authz becomes an optional sub-chart of the Kyverno chart. It never installs `policies.kyverno.io` CRDs. | [Packaging](#packaging-and-the-kyverno-chart) |
| D2 | Mode names | Replace `EnvoyProcessor` with a protocol-based name. | [Evaluation modes](#evaluation-modes) |
| D3 | Policy ownership | Each controller manages only its own policy set, selected by evaluation mode. | [Coexistence](#coexistence-with-the-kyverno-admission-controller) |
| D4 | Reports | Redesign authz reports as a bounded decision log across all replicas, and reuse the Kyverno reports-server where possible. | [Reports](#decision-reports) |
| D5 | Startup state | The server doesn't process requests until its policies are loaded. | [State management](#state-management) |
| D6 | Exceptions | Restrict exceptions to a configured namespace, as Kyverno does. Whether it can share Kyverno's namespace is still open. | [Exceptions](#policy-exceptions) |
| D7 | ext_proc | Response-path policy (`ext_proc`) is a product feature. | [Gateways](#gateway-support) |
| D8 | Sidecar transport | Sidecars default to a Unix domain socket. | [Deployment models](#deployment-models) |
| D9 | Demos | Convert the demos into samples with detailed runbooks. Remove slides and other presentation material. | [Samples](#samples) |

## Current state

### Architecture on `main`

- One binary: `kyverno-authz serve {envoy|http} {authz-server|validation-webhook}`, plus `serve sidecar-injector`.
- **Envoy server** (`pkg/authz/envoy`): implements `ext_authz` v3 `Check`. Policies are evaluated in order, and the first result or error wins. **If no policy matches, the request is allowed.**
- **HTTP server** (`pkg/authz/http`): a plain HTTP authorizer with CEL input and output transforms. It also allows by default.
- **Engine** (`pkg/engine`): compiles `ValidatingPolicy` objects whose `spec.evaluation.mode` is `Envoy` or `HTTP`, plus any `PolicyException` that names them through `policyRefs`.
- **Policy sources:**
  - Kubernetes: a controller-runtime cache with a field selector on `spec.evaluation.mode`. Exceptions are watched in all namespaces.
  - Files, Git, and OCI: loaded once at startup.
- **Events** (`pkg/events`):
  - stdout: always on, and writes the whole request.
  - Kubernetes Events: optional, one per request.
  - OpenReports: optional, one `Report` per pod, holding a ring buffer of 500 results.
- **Webhooks:** a policy validation webhook, and a generic sidecar injector.
- **Charts:** `kyverno-authz-server` and `kyverno-sidecar-injector`. Neither installs CRDs.
- **Probes:** always report healthy.

### What the branches add

| Branch | Product code | Demo material |
|---|---|---|
| `agent-router` | First version of the `ext_proc` server and CEL library, the `EnvoyProcessor` mode, policy attribution, request redaction, the kube source deadlock fix, and exception-store fixes. | `examples/agentrouter`: Envoy AI Gateway, Keycloak, Python apps, `.pptx` and `.pdf` files. |
| `agent-router-extproc` | Everything in `agent-router`, plus scoping exceptions to `ValidatingPolicy`, a CEL JSON fix, and more tests. | `examples/agentrouter-extproc` |
| `agent-router-demo` | Policy attribution (implemented separately), `--reports-filter`, a mutex on the report buffer, and allow-list request properties that hard-code demo fields. | MCP validation and heartbeat changes in the example policies. |

The demo and extproc branches implement the same features in different ways, so merging both conflicts in `pkg/events/{iface,openreports,request}.go`, `pkg/engine/evaluation.go`, and `pkg/authz/envoy/*`.

> **Housekeeping:** the main checkout has uncommitted, staged copies of the agent-router files. Clean it up before you start the consolidation work.

## Findings

Severity: **P0** blocks production use, **P1** is needed for GA, **P2** can follow GA.

### Security

| # | Sev | Finding | Evidence |
|---|---|---|---|
| S1 | P0 | Requests that match no policy are allowed. That includes an empty or unsynced cache, a deleted policy, and an exception that skips a policy. | `pkg/authz/envoy/service.go:46,62`; HTTP authorizer `if result == nil` |
| S2 | P0 | Credentials leak into stdout, Kubernetes Events, and Reports. The whole request is serialized, including `authorization`, cookies, and the body. The branch redaction misses `metadata_context` (where JWT claims land), `context_extensions`, query-string tokens, and some headers. | `pkg/events/writer.go`, `openreports.go:118`, branch `events/request.go` |
| S3 | P0 | Any user who can create a `PolicyException` in any namespace can exempt any authz policy. | `composite_source.go` `handlePolex`, `kube.go` |
| S4 | P0 | `spec.expiresAt` on exceptions is never enforced, and an exception with no `matchConditions` exempts every request. | No references to `ExpiresAt` under `pkg/`; `compiler/policy.go:106-126` |
| S5 | P0 | You can bypass `ext_proc` response policies. Multi-chunk bodies and compressed responses skip evaluation. Body buffering has no cap. Policies can rewrite any header, including `authorization` and pseudo-headers. | `pkg/authz/extproc/service.go:77-79,89-94,106-108`; `server.go:172-174` |
| S6 | P1 | JWKS is fetched on every evaluation, with no cache and no timeout. | `pkg/cel/libs/jwk/impl.go:20` |
| S7 | P1 | Policies that call the API server (for example, SubjectAccessReview) run with the authz service account's permissions. Anyone who can write an authz policy effectively holds that RBAC. | `resource.Post` in the CEL libraries |
| S8 | P1 | The HTTP authorizer reads the request body with no size limit. | `pkg/cel/libs/authz/http/types.go:65` |

### Correctness

| # | Sev | Finding | Status |
|---|---|---|---|
| C1 | P0 | The kube source deadlocks when it fetches a missing policy: it returns while still holding the lock. | Fixed on `agent-router-extproc`. |
| C2 | P1 | An exception that arrives before its policy is dropped, and references removed by an update are never unlinked. | Fixed on `agent-router-extproc`. |
| C3 | P1 | The report ring buffer has a data race between the event loop and the flush goroutine. | Fixed on `agent-router-demo`. |
| C4 | P1 | One policy that fails to compile fails every request. | Open |
| C5 | P1 | The kube source ignores `EnvoyProcessor` policies, so you can only load `ext_proc` policies from files or OCI. | Open |
| C6 | P2 | `NewResultAccessor.MustGet` panics on an unknown result type. | Open |

### Operations

- Probes always pass, and there is no gRPC health service.
- The gRPC server has no TLS, keepalive, or message-size settings.
- Metric labels include the raw `path` and `host`, so the number of label values has no limit.
- There is no OpenTelemetry tracing.
- `GracefulStop` has no deadline.
- RBAC is too broad:
  - The server can patch every `ValidatingWebhookConfiguration`.
  - It has full read-write access to reports and Secrets.
  - It has no SubjectAccessReview permission, even though policies need it.
- The chart is missing:
  - Values for events, reports, `ext_proc`, TLS, and the default decision.
  - A PodDisruptionBudget, ServiceMonitor, NetworkPolicy, and HorizontalPodAutoscaler.
- CI pulls Kyverno CRDs from `kyverno/kyverno@main` instead of a pinned version.

## Packaging and the Kyverno chart

### Current Kyverno chart experience

The Kyverno chart (`kyverno/charts/kyverno`) installs CRDs through **optional sub-charts**. CRDs are installed by default.

| Dependency | Condition | Default | Contents |
|---|---|---|---|
| `crds` | `crds.install` | `true` | `kyverno.io`, `reports.kyverno.io`, and `wgpolicyk8s.io` CRDs. Each kind has its own toggle under `crds.groups.*`. |
| `kyverno-api` (`kyverno.github.io/api`, `0.0.1-alpha.2`) | `crds.install` | `true` | `policies.kyverno.io` CRDs, including `ValidatingPolicy` and `PolicyException` |
| `openreports` | `openreports.installCrds` | `false` | `openreports.io` CRDs |
| `reports-server` (`0.1.6`) | `reportsServer.enabled` | `false` | Reports server, an aggregated API server backed by a database |
| `grafana` | `grafana.enabled` | `false` | Dashboards |

Other related chart settings:

- `crds.migration.enabled` (default `true`) runs a post-upgrade hook that migrates stored CRD versions.
- `crds.reportsServer.enabled` skips the report CRDs when reports-server serves those APIs.
- `features.policyExceptions.namespace` sets the `--exceptionNamespace` flag.

### Proposal

1. Add `kyverno-authz-server` to the Kyverno chart as a dependency with `condition: authz.enabled` (default `false`).
2. Kyverno Authz **never** installs `policies.kyverno.io` CRDs. In the Kyverno chart, the CRDs come from `kyverno-api`. For a standalone install, the authz chart declares the same `kyverno-api` dependency, behind its own `crds.install` condition.
3. Align versions. Authz builds against `kyverno/api v0.0.1-alpha.5`, but the Kyverno chart pins the `kyverno-api` chart at `0.0.1-alpha.2`. Publish a compatibility matrix, and add a CI job that installs the authz chart on top of each supported Kyverno chart version.
4. Parent chart values pass through to authz: the exception namespace, OpenReports enablement, and reports-server enablement.
5. Fold the sidecar injector into the authz chart as an optional component (`sidecarInjector.enabled`).

## Evaluation modes

### Values across projects

| Value | Defined in | Handled by | Notes |
|---|---|---|---|
| `Kubernetes` | `kyverno/api` `api/policies.kyverno.io/modes.go` | Kyverno admission, background, and CLI | Default when `spec.evaluation.mode` is empty. |
| `JSON` | `kyverno/api` `modes.go` | Kyverno engine and CLI, `kyverno-json` | Arbitrary JSON payloads. |
| `Envoy` | `kyverno-authz` `apis/constants.go` | Authz Envoy server (`ext_authz`); Kyverno CLI (`cmd/cli/kubectl-kyverno/policy/load.go:311`) | Not defined in `kyverno/api`. |
| `HTTP` | `kyverno-authz` `apis/constants.go` | Authz HTTP server; Kyverno CLI | Not defined in `kyverno/api`. |
| `EnvoyProcessor` | `agent-router*` branches only | Authz `ext_proc` server | To be replaced. |

Other observations:

- The mode is a free-form string with no enum validation.
- The doc comment on `ValidatingPolicy` v1alpha1 lists `"Kubernetes", "HTTP" or "Envoy"`, while `MutatingPolicy` lists `"Kubernetes" or "JSON"`. Neither is complete.
- `PolicyException.spec.evaluationMode` is also a free-form string.

### Proposal

Name modes after the **protocol**, not the proxy, because agentgateway and other proxies speak the same protocols as Envoy.

| Proposed | Replaces | Meaning |
|---|---|---|
| `ExtAuthz` | `Envoy` (kept as a deprecated alias) | Envoy `ext_authz` v3 `Check`, request path |
| `ExtProc` | `EnvoyProcessor` | Envoy `ext_proc` v3, request and response path |
| `HTTP` | Unchanged | Plain HTTP authorizer |

Other options considered:

- **Keep `Envoy` and add a phase field** (`spec.evaluation.envoy.phase: Request|Response`). This avoids a new mode, but it mixes two protocols with different inputs and outputs in one mode.
- **`EnvoyExtProc`.** This is consistent with `Envoy`, but it ties the name to one proxy.

Work items:

- Define all mode constants in `kyverno/api` `modes.go`, and fix the field docs on every policy kind.
- Add a CRD enum or CEL validation if the API reviewers agree.
- Update the Kyverno CLI to route `ExtAuthz` and `ExtProc` policies.

## Coexistence with the Kyverno admission controller

**Principle (D3): each controller manages its own policy set.** Kyverno owns `Kubernetes` and `JSON`. Kyverno Authz owns `ExtAuthz`, `ExtProc`, `HTTP`, and `Envoy`.

### What happens today

Reading the Kyverno source, Kyverno doesn't yet filter `ValidatingPolicy` objects by mode in its controllers:

- The `vpol` compiler treats every mode other than `JSON` as `Kubernetes` (`pkg/cel/policies/vpol/compiler/compiler.go:58`).
- No mode filter appears in `pkg/controllers/{webhook,policystatus,report}`.

So Kyverno probably tries to compile authz policies, sets status conditions on them, and may report errors. **An e2e test with both controllers installed needs to confirm this.**

On the authz side, the validation webhook matches every `validatingpolicies` object with `failurePolicy: Fail`. If the authz webhook is down, it blocks writes of Kyverno admission policies.

### Proposal

| Area | Kyverno (upstream PR) | Kyverno Authz |
|---|---|---|
| Policy selection | Skip `ValidatingPolicy` objects whose mode isn't `Kubernetes` or `JSON`, in every controller (webhook, status, reports, background). | Watch only its own modes, using the existing field selector. |
| Exceptions | Ignore `PolicyException` objects whose `evaluationMode` isn't one of its own. | Watch only exceptions with its own modes, in the exception namespace. |
| Status | Write status only for the policies it owns. | Write its own condition type (for example, `AuthzReady`) to the policies it owns. |
| Validation webhooks | Scope the webhooks with `matchConditions` on `object.spec.evaluation.mode`. | Same. Validate `PolicyException` objects too. |
| Reports | Use the label `app.kubernetes.io/managed-by: kyverno`. | Use the label `app.kubernetes.io/managed-by: kyverno-authz`, with a distinct `source` field. |
| CRDs | Owns the CRDs through `kyverno-api`. | Never installs CRDs. |

Run the coexistence tests in CI with Kyverno and Kyverno Authz installed together:

- Kyverno admission policies still work while Kyverno Authz is down.
- Neither controller updates status on the other's policies.
- Reports from both controllers stay separate.
- Upgrades work across Kyverno N-1, N, and N+1 CRDs.

## Policy exceptions

**Decision (D6): exceptions are accepted only from a configured namespace.** Add `--exception-namespace`, which matches the Kyverno `--exceptionNamespace` flag (`*` means all namespaces). Kyverno already applies this flag to `policies.kyverno.io` exceptions (`cmd/kyverno/main.go:738`).

### Can it be the same namespace as Kyverno?

| Option | Pros | Cons |
|---|---|---|
| **Shared namespace** (for example, `kyverno-exceptions`) | One place to audit. Simpler for the umbrella chart. | RBAC can't separate exceptions by `evaluationMode`. Anyone who can write admission exceptions can also write authz exceptions, and the reverse. |
| **Separate namespace** (for example, `kyverno-authz-exceptions`) | RBAC separates the two. Authz exceptions, such as break-glass access, often have different approvers than admission exceptions. | Two places to audit. |

**Recommendation:** default to a separate namespace, and allow a shared one through configuration. If you share the namespace, add a ValidatingAdmissionPolicy that restricts who can create exceptions for each `evaluationMode`. The umbrella chart can ship that policy.

### Additional rules

- Enforce `spec.expiresAt`. Drop expired exceptions from the compiled set, and re-queue each exception at its expiry time.
- Reject exceptions that have no `matchConditions`, unless `--allow-unconditional-exceptions` is set.
- Keep the check that limits exceptions to `ValidatingPolicy` (from `agent-router-extproc`).
- Record which exceptions applied in decision reports and metrics.

## State management

**Decision (D5): the server doesn't process requests until its policies are loaded.**

### Lifecycle

```
Starting ──► Syncing ──► Ready ──► Draining ──► Stopped
                │          │  ▲
                │          ▼  │
                └──────► Degraded
```

| State | Behavior |
|---|---|
| Starting | Neither gRPC nor HTTP listeners accept authorization traffic. Liveness passes. Readiness fails. |
| Syncing | All configured sources are loading: kube informers sync, and file, Git, and OCI sources load. The gRPC health service reports `NOT_SERVING`. `Check` returns `UNAVAILABLE`, so the gateway's failure mode applies. |
| Ready | Every source has completed its first load, and a policy snapshot is published. Readiness passes, and the gRPC health service reports `SERVING`. |
| Degraded | A source fails after it was ready. The server keeps serving the **last known good snapshot**. It raises a metric and a condition, and readiness stays up unless the snapshot is older than `--max-snapshot-age`. |
| Draining | On SIGTERM, readiness fails, the server waits `--drain-delay`, and then calls `GracefulStop` with a deadline. |

### Design

- **Immutable snapshots.** Compile the full policy and exception set into a versioned snapshot, then swap it in atomically. Requests evaluate against one snapshot. This removes the lock contention and the deadlock class of bugs in the composite store.
- **Isolate compile failures per policy.** A policy that fails to compile is excluded and reported on its status. It doesn't fail the snapshot. With `--strict`, any compile failure keeps the server in `Syncing` or `Degraded` instead.
- **Ready criteria.** All sources must report an initial sync. `--min-policies` (default `1`) guards against an empty or misconfigured selector.
- **Default decision.** Add `--default-decision=allow|deny` for requests that match no policy. The chart defaults to `deny`. This is a breaking change, so call it out in the release notes.
- **Fail-open or fail-closed.** Document the full matrix (startup, source errors, evaluation errors, timeouts) for each gateway.

## Decision reports

### Requirements

- Bounded total size **across all replicas**, not per pod.
- Recent decisions, filtered by result (default: `fail` and `error`), attributed to a policy and a gateway or route.
- No credentials or request bodies. Only an allow-list of request properties is recorded.
- No coordination on the request path. Recording a decision must never add latency.
- Garbage collection when pods or policies are deleted.

### Proposed design: sharded ring log plus a summary

**Tier 1: decision log, one segment per replica.**

- Each replica owns one `Report` segment, named `kyverno-authz-<pod>`, with an `ownerReference` to its Pod so it's deleted with the Pod.
- A segment is a ring buffer of at most `--report-max-entries` results (default 100) and at most `--report-max-bytes` (default 256 KiB, well under the etcd limit).
- Each segment is labeled `kyverno-authz.io/log=<deployment>`. Readers (CLI, UI, Policy Reporter) list segments by that label and merge them by timestamp.
- Total size is at most replicas × max entries. Sidecars use a much smaller per-pod limit, and you can turn sidecar segments off.
- Writes are batched every `--report-flush-interval` (default 10s) and rate-limited. If the API server is slow, the oldest results are dropped and counted in a metric.

**Tier 2: summary, one per policy.**

- A leader-elected aggregator (using the existing Lease RBAC) periodically reads the segments and writes one `ClusterReport` per policy, holding counts (`pass`, `fail`, `error`, `skip`), the last N denials, and the exceptions that applied.
- The summary survives pod churn and gives dashboards a stable object to read.

**Kubernetes Events:** limit them to policy-level events, such as compile failures, expired exceptions, and source errors. Never create one per request.

### Reusing reports-server

The Kyverno reports-server is an aggregated API server that stores reports in a database instead of etcd. The Kyverno chart already ships it as an optional dependency (`reportsServer.enabled`).

| Approach | Fit |
|---|---|
| **Storage backend (recommended first step).** When reports-server serves the report API group that authz writes to, the segments and summaries above go to its database instead of etcd. No authz code changes are needed. You can raise the size limits, because etcd object size no longer applies. | Good. Verify that the reports-server version in the Kyverno chart serves `openreports.io` `Report` and `ClusterReport`. If it doesn't, add that support. |
| **Native log API (follow-up).** Add an append-only `DecisionLog` resource to reports-server, with server-side retention by count and age. All replicas append to it, so the bound is global and no segments need merging. | Best long-term fit for a log. It needs a new API, plus retention support in reports-server. |
| **Etcd only (fallback).** When reports-server isn't installed, use the segments and summaries in etcd with the default limits. | Always available. |

Recommendation: build the two tiers against the OpenReports API, verify them on etcd and on reports-server, then propose the `DecisionLog` API to reports-server as a follow-up.

## Gateway support

### agentgateway `ext_authz`

- agentgateway calls external authorization through the Envoy `ext_authz` v3 gRPC API.
  - Standalone: [docs](https://agentgateway.dev/docs/standalone/latest/configuration/security/external-authz/)
  - Kubernetes: [docs](https://agentgateway.dev/docs/kubernetes/latest/documentation/security/extauth/byo-ext-auth-service/)
- Work items:
  - **Conformance:** verify against agentgateway source which `CheckRequest` fields it populates, and where JWT claims and gRPC metadata land (`metadata_context` or headers). This isn't confirmed from the docs.
  - **CEL helpers:** add helpers for MCP requests parsed from the body, built on `pkg/cel/libs/mcp`.
  - **Defaults:** document the defaults: the 8 KiB body limit, `appProtocol: kubernetes.io/h2c`, and timeouts.
  - **e2e test:** agentgateway with an MCP server.

### `ext_proc` (D7: a product feature)

Rework `pkg/authz/extproc` instead of merging it as it is:

- Support agentgateway's default `FullDuplexStreamed` body mode and Envoy `STREAMED` by accumulating chunks up to `--extproc-max-body-bytes`. Above the limit, or for compressed bodies, apply `--extproc-oversize=deny|allow` (default `deny`).
- Don't rely on `CONTINUE_AND_REPLACE`, because agentgateway ignores it. Replace bodies only in the body phase.
- Add a list of headers that policies can't change: pseudo-headers, `authorization`, `host`, and `:authority`.
- Add a per-message timeout, plus metrics and decision reports for the `ExtProc` path.
- Load `ExtProc` policies from the kube source.

### Envoy, Envoy Gateway, and Istio

- Keep the existing Istio e2e tests, and add tests for Envoy Gateway `ext_authz` and `ext_proc`.
- Add TLS and mTLS between the gateway and Kyverno Authz, with certificates from cert-manager or the existing `certmanager` package.

## Deployment models

| | Deployment | Sidecar |
|---|---|---|
| Transport | gRPC over TCP, with TLS or mTLS | **Unix domain socket by default (D8)**, TCP optional |
| Identity | Dedicated service account with least-privilege RBAC | See the RBAC open question below |
| Scaling | HorizontalPodAutoscaler, PodDisruptionBudget, anti-affinity | Scales with the app |
| Reports | Segments with a Pod owner reference, plus the leader-elected summary | Small segments, or none. No leader election. |
| Injection | Not applicable | Opt-in label `kyverno-authz.io/inject: "true"`, an idempotency check, and native sidecars (an init container with `restartPolicy: Always`) |

The same binary and flags run in both modes. The chart renders either a Deployment or the injector's sidecar template from the same values.

**Sidecar RBAC open question:** a sidecar runs as the app's service account. That account then needs cluster-wide `list` and `watch` permissions on policies, plus read access to the exception namespace. Options:

- A ClusterRole that the injector binds to each injected service account.
- A projected token for a dedicated service account. This is preferred, if it's feasible.

## Observability

- **Metrics:** use bounded labels (policy, mode, result, and route name instead of raw path). Add per-policy latency, snapshot age, source sync status, dropped report entries, and JWKS cache hits.
- **Tracing:** add OpenTelemetry tracing, propagating trace context from Envoy and agentgateway.
- **Logs:** turn off stdout decision logs by default, and use the same allow-list redaction as reports.
- **Chart:** add an optional ServiceMonitor, and Grafana dashboards that plug into the Kyverno chart's `grafana` sub-chart.

## Performance

- Target p99 evaluation latency under 5 ms, not counting external calls.
- Cache JWKS with background refresh and a timeout bound to the request context. Optionally cache SubjectAccessReview results with a short TTL.
- Set a CEL cost limit and a deadline for each request.
- Add a k6 baseline to CI (`tests/performance-test`), and publish sizing guidance.

## Samples

**Decision (D9):** convert `examples/agentrouter*` into `samples/`, with this structure:

```
samples/
  mcp-request-authz/       # from agent-router-demo
    README.md              # runbook
    policies/
    manifests/
    apps/                  # minimal MCP server, identity provider config
  mcp-response-filtering/  # from agent-router-extproc
    README.md
    ...
```

- Remove the `.pptx` and `.pdf` files and other presentation material.
- Remove demo-specific code from `pkg/` (for example, `addBodyProperties` in `events/request.go`).
- Exclude samples from `go test ./...` and from release artifacts. Give sample tests their own `go.mod`, or put them behind a build tag.
- Each runbook covers:
  1. What you learn, and the scenario (the Alice SRE assistant).
  2. Prerequisites, with pinned versions.
  3. Setup from the repository root, one command per step.
  4. Exercises, each with the command, the expected output, and an explanation:
     - The request is denied, and why.
     - Grant access with a policy change.
     - Grant temporary access with a time-boxed `PolicyException`.
     - Revoke access.
     - Inspect decision reports.
  5. Troubleshooting.
  6. Cleanup.
- Run each sample's runbook commands in CI on kind (nightly), so the samples don't drift.

## Plan

### M0: Hygiene

1. Clean up the main checkout, and land #237 (fe9504b).
2. PR: fix the kube source deadlock and the exception-store bugs. Cherry-pick these from `agent-router-extproc`, with their tests.
3. PR: add the report buffer mutex (from `agent-router-demo`).
4. PR: pin Kyverno CRDs in CI to a released `kyverno-api` chart version.

### M1: Secure defaults and state (P0)

1. PR: add a lifecycle state machine, immutable snapshots, readiness gated on sync, and the gRPC health service (D5).
2. PR: add `--default-decision`, with the chart defaulting to `deny`.
3. PR: replace full-request serialization with allow-list redaction, and turn off stdout decision logs by default.
4. PR: add `--exception-namespace`, enforce `expiresAt`, and reject unconditional exceptions (D6).
5. PR: scope the validation webhook by mode, and validate `PolicyException` objects.

### M2: API and coexistence

1. Upstream `kyverno/api`: define the `ExtAuthz`, `ExtProc`, and `HTTP` constants, and fix the field docs (D2).
2. Upstream `kyverno/kyverno`: filter policies by mode in every controller, and add webhook `matchConditions` (D3). Tracked in [kyverno/kyverno#18611](https://github.com/kyverno/kyverno/issues/18611).
3. PR: add the authz-specific status condition, and per-policy compile isolation.
4. Add a coexistence e2e suite with both controllers installed.

### M3: Reports

1. PR: keep one `engine.Evaluation` and policy attribution implementation, plus `--reports-filter`.
2. PR: add tier 1 segments with owner references, size bounds, batching, and drop metrics.
3. PR: add the tier 2 leader-elected summary report per policy.
4. Validate on reports-server, and draft the `DecisionLog` proposal for reports-server (D4).

### M4: Gateways

1. PR: agentgateway `ext_authz` conformance tests, MCP CEL helpers, and an e2e test.
2. PR: the reworked `ext_proc` server (streaming, size caps, the protected-header list), and loading `ExtProc` policies from the kube source (D7).
3. PR: Envoy Gateway `ext_authz` and `ext_proc` e2e tests.

### M5: Operations and packaging

1. PR: TLS and mTLS, OpenTelemetry tracing, drain on shutdown, and metrics with bounded labels.
2. PR: chart values for everything above, a PodDisruptionBudget, ServiceMonitor, and NetworkPolicy, and an RBAC split.
3. PR: an opinionated sidecar mode, with a Unix domain socket and native sidecars (D8).
4. PR: JWKS caching, CEL cost limits, and a k6 baseline.
5. Upstream `kyverno/kyverno` chart: add the `authz.enabled` dependency (D1).

### M6: Samples

1. PR: move `examples/agentrouter*` to `samples/` with runbooks, remove the slides, and remove demo code from `pkg/` (D9).
2. Add nightly CI that runs the runbooks.

### Test matrix

| Dimension | Values |
|---|---|
| Gateway | Istio, Envoy Gateway, agentgateway (standalone and Kubernetes) |
| Protocol | `ext_authz`, `ext_proc`, HTTP |
| Deployment | Deployment, sidecar |
| Kyverno | Not installed, installed (N-1, N, N+1) |
| Reports backend | etcd, reports-server |

## Open questions

1. **Exception namespace:** use a separate namespace by default (recommended), or share Kyverno's namespace?
2. **Mode names:** use `ExtAuthz` and `ExtProc` (recommended), or add a phase field to `Envoy`?
3. **Reports:** should the summary tier be a `ClusterReport` per policy, or one per gateway or route?
4. **Retention:** how many entries, and how much age, should the decision log keep by default?
5. **Sidecar identity:** bind RBAC to the app's service account, or use a projected token?
6. **Default deny rollout:** make it the default immediately, or warn for one release first?
7. **Kyverno version floor:** which is the oldest Kyverno version with `selectableFields` support, and with mode filtering after M2?
8. **reports-server:** does the version in the Kyverno chart serve the `openreports.io` APIs?
