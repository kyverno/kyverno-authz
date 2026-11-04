# Agent Router + Kyverno Authz

A deterministic, end-to-end technical demo of runtime authorization for MCP tools
and model traffic. It uses real Keycloak tokens, MCP sessions, Kubernetes
SubjectAccessReviews (SARs), deployment updates, policy exceptions, and OpenReports.
A local OpenAI-compatible backend substitutes for a model provider; no provider
key or Python package installation is required.

## Quick start

From the repository root:

```bash
./examples/agentrouter/scripts/setup.sh
./examples/agentrouter/scripts/run.sh
./examples/agentrouter/scripts/run.sh --check
./examples/agentrouter/scripts/reset.sh
```

For a live talk, `./examples/agentrouter/scripts/run.sh --scenario 1` resets the demo
and runs only that scenario (any of 1–7), logging to `.state/scenario-1.log` so the
full-run log is kept. Scenarios 2 and 5 add a small setup step when run alone.

All operations explicitly target **`kind-kyverno-agentrouter`**. Use a disposable
cluster: setup reconciles workloads, controllers, routes, RBAC, and policies.
Prerequisites: Docker running (approximately 8 GiB available), `kind`, `kubectl`,
`helm`, `go`, `ko`, Python 3.10+, internet access, and free local ports 18080–18083.
The Go toolchain must support the repository's `go.mod`.

Setup is idempotent: it compiles runtime policies, upgrades Helm releases, installs
the Report CRD, builds this checkout with `ko`, loads the image into Kind, applies
policies, restarts workloads, and checks actual gateway decisions. Generated
Keycloak passwords remain in a Kubernetes Secret and are reused across setups.
`run.sh` resets initial state first and logs results under `.state/last-run.log`.
`--check` verifies the exception carrier is absent and Bob remains denied even
with the incident header. It does not modify RBAC, exceptions, or deployments, but traffic creates
reports and backend audit records. Reset deletes leftover demo exceptions,
restores Alice's write access, and seeds team A=0 / team B=1 replicas.

| Component | Version/source |
|---|---|
| Kind node | `kindest/node:v1.35.1` |
| Envoy Gateway | Helm `v1.9.2` |
| Agent Router | Helm `v1.2.0` |
| Kyverno admission + cleanup controllers | Helm `3.9.1` / Kyverno `v1.19.1` |
| Keycloak | `quay.io/keycloak/keycloak:26.3.3` |
| MCP/model/checkout backends | `python:3.13.7-alpine3.22` |
| Kyverno Authz | Repository source, built with `ko` |
| OpenReports Report CRD | Vendored from `github.com/openreports/reports-api v0.2.1` |

## Native capabilities versus Kyverno Authz

| Capability | Agent Router / Envoy Gateway built-ins | Kyverno Authz value |
|---|---|---|
| Simple per-user MCP tool and argument checks | Possible with experimental `MCPRoute.authorization.rules[].cel` | Same versioned, unit-tested policy language across tool, model, and platform policy |
| Live Kubernetes permissions | Native CEL has no external lookups | SAR checks current RBAC on every relevant request, without replacing tokens or sessions |
| Per-user tool discovery | Native authorization is request allow/deny | `ext_proc` filters `tools/list` response bodies using the verified user's SAR |
| Model request governance | `AIGatewayRoute` has no CEL authorization | Inspect body fields and prompt credentials; inject trusted `x-tenant-id` |
| Incident-scoped exceptions | No equivalent native policy-exception lifecycle | PolicyException file, governed ConfigMap, explicit authz rollout, and request-time expiry |
| Policy decision audit | Gateway access logs are not policy reports | OpenReports results with policy identity and request correlation |
| Fail-closed integration | JWT, body limits, and external authorization failure handling are built-ins | Runtime policy composes with those built-ins; not a Kyverno-only feature |

Native MCPRoute CEL is experimental, supports at most **32 rules × 4096
characters**, and returns allow/deny only. Its environment exposes only `request`:
method, headers, path, JWT claims/scopes, and MCP method/backend/tool/params.
Evaluation errors mean no match. This demo does not claim simple user/tool or
argument checks require Kyverno.

## Layout

| Path | Contents |
|---|---|
| `scripts/` | Setup, run, reset, token helper, and shared explicit-context commands |
| `install/` | Helm values and vendored `openreports.io_reports.yaml` |
| `manifests/` | Workloads, namespaces, RBAC, MCP/model routes, and ext_proc configuration |
| `policies/authz/` | File-loaded Envoy-mode MCP and model policies |
| `policies/processor/` | File-source-only EnvoyProcessor discovery policy |
| `policies/exceptions/` | Narrow incident PolicyException source |
| `policies/admission/` | Route/exception admission guardrails and violating `cases/` |
| `apps/` | Bounded MCP backends, deterministic model backend, identity generator |
| `client/demo.py` | Gateway client, seven scenarios, audit/state assertions, and smoke checks |
| `tests/` | Runtime policy/exception compilation and Python unit tests |

## Architecture

```text
Client -- Keycloak access token --> Envoy Gateway + Agent Router
  JWT authentication, MCP sessions, aggregation, tool/model routing
  |
  +--> Kyverno Authz ext_authz (:9081)
  |      /mcp: user/tool/argument checks + live Kubernetes SAR
  |      /v1/*: model entitlement, token budget, prompt checks, tenant header
  |      File source: Envoy ValidatingPolicies + optional PolicyException
  |      OpenReports --> reports.openreports.io in agentrouter-demo
  |
  +--> Kyverno Authz ext_proc (:9083)
  |      tools/list response filtering + live Kubernetes SAR
  |      File source: ConfigMap demo-policies (processor policy)
  |
  +--> MCPRoute --> kube-tools --> Kubernetes checkout deployments
  |             --> runbooks   --> local recovery instructions
  +--> AIGatewayRoute --> deterministic OpenAI-compatible llm-backend

Kyverno admission --> rejects unsafe routes and ungoverned Envoy exceptions
Kyverno cleanup   --> deletes exception ConfigMaps with cleanup.kyverno.io/ttl
```

`--kube-policy-source=false --external-policy-source=file:///policies` loads both
Envoy policies and the processor policy from ConfigMap `demo-policies`. A projected
volume overlays optional ConfigMap `demo-exceptions` in the same directory, so
its PolicyException can be associated with its policy **in the same file source**.
The file source uses `NewOnce`: it does not watch projected-volume changes.
Setup and the exception scenario explicitly roll the authorizer to reload files.
This restarts authz, not Agent Router or the caller's MCP session/token.

JWT authentication precedes external authorization through
`EnvoyProxy.filterOrder`. MCPRoute extAuth forwards the JSON-RPC body (16 KiB
limit), `authorization`, `x-demo-id`, and `x-incident-id`, with `failOpen: false`.
The MCPRoute controller owns its generated SecurityPolicy; do not edit it.
Model traffic uses its own JWT + extAuth SecurityPolicy. Services are ClusterIP;
loopback-only port-forwards are checked for responsiveness and only their own
processes are terminated.

Alice owns `team-a-dev`; Bob owns `team-b-dev`. Both may read their named
`checkout` deployment and scale it to 1–3 replicas when RBAC permits.
The MCP backend validates inputs independently, exposes no generic execution tool,
and executes with its own bounded ServiceAccount, not the user's credentials.

| Aggregated MCP tool | Kubernetes permission checked |
|---|---|
| `runbooks__get_runbook` | None; no Kubernetes token mounted |
| `kube-tools__get_workload_status` | Get named deployment |
| `kube-tools__get_events` | List namespace events |
| `kube-tools__get_logs` | List pods AND get pod logs |
| `kube-tools__scale_deployment` | Update named deployments/scale |

## Scenarios

Each scenario prints its incremental value and asserts HTTP decisions, backend
audit correlation, and/or actual Kubernetes state.

1. **Live RBAC and tool discovery.** Kyverno Authz adds live SARs and per-user
   response filtering beyond native request-only CEL. Revoke Alice's RoleBinding:
   scale disappears from her tool list and direct calls fail, while reads and Bob's
   access remain intact. Restore RBAC: the same token/session discovers and uses
   scale again, recovering checkout to three ready replicas.
2. **Request guardrails.** Simple user/tool/argument checks are possible natively;
   here they share versioned, unit-tested policy language. Diagnose checkout,
   reject cross-namespace access, unknown tools, extra arguments, wrong workloads,
   and missing/invalid replica counts; allow bounded remediation.
3. **Model governance.** AIGatewayRoute has no CEL authorization; Kyverno Authz
   inspects request bodies and injects verified identity. Alice gets `demo-mini`
   with bounded `max_tokens`; premium model, missing/excessive budget, multiple
   completions, tool calling, and credential-bearing prompts fail. Bob can use
   `demo-pro`. A spoofed tenant header is replaced; denied traffic never reaches
   the model backend.
4. **Break-glass exceptions.** Kyverno Authz adds incident-scoped file exceptions,
   governed ConfigMaps, request-time expiry, and explicit reloads. Bob's cross-namespace scale is
   denied, then succeeds only with the narrow exception and incident header.
   Missing header, excessive replicas, Alice using Bob's incident, and unrelated
   cross-namespace tools remain denied; Bob's normal access is unaffected.
   Deleting the carrier ConfigMap and reloading returns the incident request to denied.
5. **Decision reports.** Kyverno Authz adds persisted, correlated OpenReports
   policy decisions beyond routing/access logs. Print pass/fail/error summaries
   and this run's results with deciding policy names. Assert both runtime policy
   names and pass/fail results exist, and bearer credentials do not appear.
6. **Admission guardrails.** Complementary Kyverno admission prevents unsafe
   routes and ungoverned Envoy exceptions, rather than replacing runtime checks.
   Server-side dry runs reject missing auth/body forwarding, fail-open, wildcard
   tool exposure, token forwarding, inline secrets, unapproved models, and invalid
   exception metadata/scope. The demo's valid routes are accepted.
7. **Fail closed.** Runtime policy composes with gateway authentication, body
   limits, and fail-closed external authorization. Reject missing/malformed/badly
   signed tokens, malformed/oversized bodies, and authorizer outages; restore the
   authorizer and confirm positive requests recover.

### Kyverno 1.19.1 coexistence limitation

Envoy-mode ValidatingPolicies are ignored during controller reconciliation
(no resource-webhook rules generated and no status assigned), but **not by
Kyverno's policy self-validation webhooks**. Key lines from the actual rejection:

```text
admission webhook "validate-policy.kyverno.svc" denied the request:
ERROR: <input>:1:1: undeclared reference to 'jwt' (in container '')
ERROR: <input>:2:3: undeclared reference to 'jwks' (in container '')
spec.matchConstraints: Required value: a matchConstraints with at least one resource rule is required
```

For the Envoy PolicyException's policy-variable condition:

```text
Warning: PolicyException resources would not be processed until it is enabled.
admission webhook "kyverno-svc.kyverno.svc" denied the request:
spec.matchConditions[0].expression: Invalid value: "variables.http.method ...":
ERROR: <input>:1:1: undeclared reference to 'variables' (in container '')
```

Chart `config.webhooks` objectSelector / `config.matchConditions` apply to resource
webhooks, not these policy self-validation hooks. `config.excludeGroups` is not
applied by their handler chain. The image's `--autoUpdateWebhooks=false` affects
resource webhooks; policy-webhook reconciliation still hardcodes auto-update.
`--enablePolicyException` does not disable exception validation. Direct webhook
patches are immediately reverted. Thus this version has no clean configuration
switch to co-validate these external CEL environments.

The demo uses a **file-source fallback**, without intercepting, weakening,
replacing, or patching Kyverno's policy-validation webhooks. Kubernetes-sourced
live exceptions are not demonstrated. A file source reads both policy and
exception at startup; a separate kube exception source cannot attach exceptions
to an already-compiled file policy. Prefer a future upstream fix that skips
self-validation for externally evaluated modes before enabling live kube sources.

## Exception management

Source: [`policies/exceptions/break-glass-inc-1234.yaml`](policies/exceptions/break-glass-inc-1234.yaml).
This is the authorizer's `policies.kyverno.io/v1 PolicyException` document, loaded
as a **file**, not submitted as a Kubernetes PolicyException. It references only
`agentrouter-bounded-operations` with `spec.evaluationMode: Envoy`.
All matchConditions must hold: verified Bob, POST tools/call, exact scale tool,
team-a-dev/checkout, header `x-incident-id: INC-1234`, no extra arguments, and
integer replicas 1–3. Conditions reuse the referenced policy's lazy variables.

**An exception skips the entire referenced policy, including its SAR. With no
other matching policy, authorization allows by default.** The backend still uses
its own ServiceAccount. A header is a scope marker, not incident approval or proof
of identity; only authorized operators should be allowed to install exceptions.

The client serializes the source into `demo-exceptions.data["exception.json"]`,
preserving incident annotation `demo.kyverno.io/incident: INC-1234` and label
`cleanup.kyverno.io/ttl: 15m` on the ConfigMap. It appends an `expires-at`
matchCondition comparing Envoy's request timestamp with the activation time plus
15 minutes. This provides **request-time expiry even though files do not reload**.
The request timestamp comes from the gateway, not a caller-supplied header.
Keep operator and gateway clocks synchronized.

Kyverno admission governs both Envoy PolicyException resources and the
file-carrier ConfigMap: non-empty incident annotation, positive TTL ≤1h (integer
seconds/minutes or `1h`), only known runtime policy references, and non-empty
matchConditions. File carriers additionally require an expires-at condition and exactly one Envoy
PolicyException in `exception.json`; additional policy files are forbidden.
The demo validates these rules using ConfigMap cases, avoiding the incompatible
PolicyException self-validator. These are structural checks, not proof arbitrary
CEL is narrow: privileged review must still reject expressions such as `true` or
unreasonably distant timestamps.

Kyverno's cleanup controller deletes the TTL-labelled carrier ConfigMap.
Deletion does not revoke an already-loaded file exception until reload, so
request-time expiry is essential. The demo explicitly deletes the ConfigMap and
rolls the authorizer for deterministic immediate revocation. Reset also removes
leftover carriers and reloads when necessary. Use fully qualified
`policyexceptions.policies.kyverno.io` when inspecting any legacy leftovers;
Kyverno also installs a distinct `kyverno.io` PolicyException kind.

## Reporting and audit

`--openreports-enabled=true --report-flush-interval=2s --result-buffer-size=200`
creates namespaced `openreports.io/v1alpha1 Report` resources. Downward-API
`POD_NAME` gives each authz Pod an `envoy-authz-report-<hash>` name. RBAC grants
create/get/update only in `agentrouter-demo`. No Kubernetes Events are enabled.
The Go result Description (JSON `message`) includes redacted request metadata (bodies omitted) for `x-demo-id` correlation;
`policy` identifies the evaluated runtime policy. A skipped exception returns default
allow/pass with an empty policy name, not an attributed exception/skip result. JWT bearer tokens must not be
stored. The client checks every existing report, not just correlated results.
A run produces output such as (counts and Pod hashes vary):

```text
REPORT | envoy-authz-report-3fb17f086cf44880 | pass=29; fail=23; error=0
RESULT | fail | policy=agentrouter-bounded-operations | x-demo-id=...
RESULT | pass | policy=(default allow) | x-demo-id=...-5
PASS | REPORT | break-glass is pass/default allow, not an attributed exception/skip
```


```bash
kubectl --context kind-kyverno-agentrouter -n agentrouter-demo get reports.openreports.io
kubectl --context kind-kyverno-agentrouter -n agentrouter-demo get reports.openreports.io -o json
kubectl --context kind-kyverno-agentrouter -n agentrouter-demo logs deploy/kyverno-authz
```

Reports are buffered/recent decisions, not durable unlimited audit storage.
Restarted Pods create different report names. Decisions rejected by gateway JWT
or size enforcement never reach authz and do not generate authz results.
**ext_proc processor decisions are not reported yet.** The demo separately asserts
tool discovery and MCP/model backend execution to cover those boundaries.

## Validation

```bash
./examples/agentrouter/scripts/setup.sh
./examples/agentrouter/scripts/run.sh
./examples/agentrouter/scripts/run.sh --check
./examples/agentrouter/scripts/reset.sh
./examples/agentrouter/scripts/run.sh --check
go test ./examples/agentrouter/tests
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s examples/agentrouter/tests
shellcheck -x -P examples/agentrouter/scripts examples/agentrouter/scripts/*.sh
git diff --check
```

To obtain a token without adding it to the demo log, use
`./examples/agentrouter/scripts/get-token.sh alice` (or `bob`). Treat it as a
credential; do not paste it into logs, reports, or version control.

## Production gaps

- Use managed identity/production OAuth flows instead of demo password grants;
  replace plaintext in-cluster identity and backend connections with TLS/mTLS.
- Restrict who can edit policies, RBAC, routes, and exceptions; admission's
  structural checks do not establish business approval or safe exception CEL.
- Narrow exception scope further with an approval workflow. File activation and
  revocation require authorizer rollouts; TTL cleanup is periodic. Keep the
  generated request-time expiry condition and synchronize clocks.
- Policies that fail compilation may be skipped, and unmatched requests allow by
  default. Compilation tests, complementary route matching, and negative probes
  are mandatory safeguards, not a universal default-deny guarantee.
- Add durable report export/retention and data minimization for request bodies;
  credential-header redaction is not a comprehensive prompt/PII scrubber.
- Processor reporting, high availability, load tests, streaming model output,
  production model providers, and multiple deployment discovery remain outside
  this demo. SAR calls add Kubernetes API dependency and latency.
