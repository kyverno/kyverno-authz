# Agent Router response governance with Kyverno ext_proc

This **prototype extension** adds response inspection and transformation to Agent
Router's MCP gateway. Alice's `tools/list` response is filtered using a live
Kubernetes SubjectAccessReview (SAR): revoking scale permission yields **four
tools**, restoring the grant yields **five tools**, using the **same OAuth token
and MCP session**. Bob's discovery remains unchanged.

Hiding a tool is **not a security boundary**. The existing ext_authz request
policy independently denies Alice's direct `tools/call` while RBAC is revoked.
This example is self-contained and does not require `examples/agentrouter`.
The independent [baseline-demo PR #249](https://github.com/kyverno/kyverno-authz/pull/249)
demonstrates request governance on the existing authorizer without introducing
this response-processing extension.

## Setup once

From the repository root:

```bash
./examples/agentrouter-extproc/scripts/setup.sh
./examples/agentrouter-extproc/scripts/run.sh --check
```

Requirements: Docker, `kind`, `kubectl`, `helm`, Go, `ko`, Python 3.10+, internet
access, and free local ports **19080–19083**. Setup creates the disposable Kind
cluster **`kyverno-agentrouter-extproc`**. Every Kubernetes command explicitly uses
**`kind-kyverno-agentrouter-extproc`**. This is independent of the baseline demo's
cluster, image tag, and client ports. Allow adequate Docker memory for both.

Setup compiles every policy (including the typed `EnvoyProcessor` policy), installs
Envoy Gateway v1.9.2, Agent Router v1.2.0 and Kyverno v1.19.1, builds this checkout,
installs OpenReports, and deploys real Keycloak and bounded MCP backends. A local
OpenAI-compatible backend supplies contextual model-policy tests without an
external provider or API key. Setup is deliberately not part of each presenter step.

## Presenter runbook: one meaningful action per command

Run these **separately**, in order, after setup. Each command asserts its expected
result and exits nonzero on failure. `reset` is the only step that resets workloads
and establishes new identities/sessions; subsequent steps reuse them across
separate client processes. Each command opens and closes its own loopback port
forwards; no background terminal is required.

```bash
# Reset incident state and establish Alice/Bob MCP sessions once.
./examples/agentrouter-extproc/scripts/step.sh reset
# Alice initially sees all five tools.
./examples/agentrouter-extproc/scripts/step.sh list
# Revoke only Alice's live scale grant; do not refresh token or session.
./examples/agentrouter-extproc/scripts/step.sh revoke
# Response inspection removes scale_deployment: four tools, same token/session.
./examples/agentrouter-extproc/scripts/step.sh list-hidden
# Bypass discovery and name the hidden tool directly: ext_authz denies, no execution.
./examples/agentrouter-extproc/scripts/step.sh direct-denied
# Bob's independent grant still permits five tools.
./examples/agentrouter-extproc/scripts/step.sh bob-list
# Restore only Alice's RBAC grant.
./examples/agentrouter-extproc/scripts/step.sh grant
# Five tools again, still the original Alice token/session.
./examples/agentrouter-extproc/scripts/step.sh list-visible
# Execute the now-authorized scale: checkout becomes two replicas.
./examples/agentrouter-extproc/scripts/step.sh scale
```

Optional supporting exception/report sequence (continue the same sessions):

```bash
# Admit a narrowly scoped, 15-minute incident exception; explicitly reload files.
./examples/agentrouter-extproc/scripts/step.sh exception-activate
# Bob + INC-1234 may scale team A's checkout to two replicas.
./examples/agentrouter-extproc/scripts/step.sh exception-allow
# No incident header, excessive replicas, and another operation remain denied.
./examples/agentrouter-extproc/scripts/step.sh exception-narrow
# Flush request reports, remove exception, reload, and verify Bob is denied again.
./examples/agentrouter-extproc/scripts/step.sh exception-revoke
# Inspect correlated ext_authz decisions and assert credentials are absent.
./examples/agentrouter-extproc/scripts/step.sh reports
```

The corresponding client interface is
`python3 examples/agentrouter-extproc/client/demo.py --step list-hidden`.
State is stored in ignored `.state/session.json` with permissions **0600** in a
**0700** directory. Tokens are never printed and expire after **30 minutes**.
Expired credentials or a replaced cluster/identity or restarted Keycloak/gateway
invalidate state; rerun
`step.sh reset`, rather than silently refreshing a token and weakening the
same-token demonstration. Setup and `scripts/reset.sh` remove old presenter state.
Do not share `.state`. Use one presenter process at a time.

## What happens on the wire

1. Agent Router verifies Keycloak JWTs and manages the MCP session.
2. Kyverno ext_authz authorizes the saved request, including bounded tool
   arguments, user/workload boundaries, and live Kubernetes SARs.
3. Envoy sends buffered request/response data to the separate ext_proc service
   on port 9083. The `EnvoyProcessor` policy verifies the request identity and
   filters the `tools/list` response using live scale permissions.
4. The processor replaces the single SSE event's JSON payload while preserving
   its event and ID framing. The caller receives only entitled tools.

Processor policy sources currently support **file, Git, or OCI external sources**,
not Kubernetes policy watching. The example mounts authz and processor policies
from a ConfigMap into a watched file directory; policy sources are mode-filtered
so an ext_authz compiler never receives an `EnvoyProcessor` policy.

## Supporting changes, not ext_proc dependencies

The broader automated context demonstrates request/body and model constraints,
admission guardrails, fail-closed authorization, incident exceptions, and
OpenReports. Reporting attribution/redaction, exception source merging and
mode filtering, and embedded PolicyException schemas are supporting prototype
fixes. They are useful independently and are **not capabilities inherently
dependent on ext_proc**.

The file-backed exception skips the **entire matching policy, including its SAR**.
Other policies still execute. Its incident, user, operation, workload, replica,
and expiry conditions are therefore important. The governed ConfigMap is admitted
by Kyverno, then the authorizer is explicitly restarted to reload the exception;
this is not a native TTL controller or automatic lifecycle integration.
The client waits for request reports to flush before restarting the process-local
reporter, so the incident demo does not lose its preceding request decisions.

OpenReports describe **ext_authz request decisions only**. A matching exception
currently appears as **pass/default allow without a deciding policy**, not as an
attributed exception/skip. Reports redact authorization/cookie/token headers and
omit bodies; they are not a general arbitrary-data sanitization guarantee.
**ext_proc response decisions are not reported**; this remains an observability gap.

## Hard prototype limitations

- Configure **buffered** bodies and Envoy size/time limits. Non-final streamed
  chunks pass through; **multi-chunk bodies intentionally bypass final evaluation**
  rather than incorrectly replacing only the last chunk.
- Non-identity **compressed responses intentionally bypass response evaluation**.
  Do not claim universal filtering or deploy this as a standalone security boundary.
- Single-event SSE data can be rewritten. A replacement of **multi-event SSE fails
  closed with HTTP 500**; this demo's discovery policy additionally requires exactly
  one identified `message` event. This is not general streaming response governance.
- Response-only streams (for example JWT/ext_authz denials without saved request
  context) pass through. Evaluation errors fail closed by default; enabling
  `--extproc-fail-open` deliberately weakens that behavior.
- This is local prototype code, not a production compatibility/security guarantee.
  See [the processor contract and limitations](../../pkg/authz/extproc/README.md).

## Executable proof manifests and tests

These repository paths are the proof-manifest references for the PR documentation
process (the repository's template links the upstream Kyverno PR documentation
guide; there is no local `.github/pr_documentation.md`):

| Proof | Manifests | Verification |
| --- | --- | --- |
| Live per-user response filtering | [`policies/processor/mcp-tool-discovery.yaml`](policies/processor/mcp-tool-discovery.yaml), [`manifests/extproc.yaml`](manifests/extproc.yaml), [`manifests/alice-scale.yaml`](manifests/alice-scale.yaml) | `list-hidden`, `bob-list`, `list-visible`; processor compile/SAR tests |
| Direct request authorization | [`policies/authz/mcp-operations.yaml`](policies/authz/mcp-operations.yaml), [`manifests/rbac.yaml`](manifests/rbac.yaml) | `direct-denied`, `scale`; correlated backend audit |
| Bounded incident override | [`policies/exceptions/break-glass-inc-1234.yaml`](policies/exceptions/break-glass-inc-1234.yaml), [`policies/admission/exception-guardrails.yaml`](policies/admission/exception-guardrails.yaml) | optional exception steps; invalid [`admission/cases`](policies/admission/cases) |
| Model/request context | [`policies/authz/llm-models.yaml`](policies/authz/llm-models.yaml), [`manifests/models.yaml`](manifests/models.yaml) | contextual scenarios in full run |

```bash
# Same isolated response steps first, then the broader contextual request suite.
./examples/agentrouter-extproc/scripts/run.sh
# Non-mutating authentication, discovery, calls, models, and report smoke check.
./examples/agentrouter-extproc/scripts/run.sh --check
# Optional contextual scenario N (1–7); unlike step.sh, this resets the demo.
./examples/agentrouter-extproc/scripts/run.sh --scenario 1
go test ./examples/agentrouter-extproc/tests
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s examples/agentrouter-extproc/tests
shellcheck -x -P examples/agentrouter-extproc/scripts examples/agentrouter-extproc/scripts/*.sh
kubectl --context kind-kyverno-agentrouter-extproc -n agentrouter-demo get reports.openreports.io -o json
```

Full `run.sh` deliberately resets between the response runbook and contextual suite;
use `step.sh` for presentation. To clean up:

```bash
kind delete cluster --name kyverno-agentrouter-extproc
rm -rf examples/agentrouter-extproc/.state
```
