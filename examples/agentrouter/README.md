# Agent Router + current Kyverno Authz

A live, local demo of [Envoy Agent Router](https://aigateway.envoyproxy.io/)
with **the current upstream/main Kyverno Authz implementation**. Setup builds
the unchanged authorizer from this checkout with `ko`; it does not use a
prototype or modify the authorizer. The latest published release, v0.4.0,
predates upstream/main; release compatibility is not asserted here.

## Native capability vs. added value

Agent Router already provides OAuth/JWT authentication, MCP aggregation,
explicit tool selection, request CEL authorization, and model routing.
Simple identity/tool/argument predicates can be implemented natively.
This demo adds:

* **Live Kubernetes authorization:** Kyverno performs a SubjectAccessReview
  for each gateway-originated Kubernetes tool execution. Revoke and restore Alice's scale
  RoleBinding while keeping the **same JWT and MCP session**.
* **Versioned runtime policies:** namespace/workload boundaries and bounded
  tool arguments, with compilation tests before deployment.
* **Model request-body governance:** model entitlement, output-token limits,
  completion count, function-calling restrictions, and example credential
  patterns. The verified identity overwrites a spoofed `x-tenant-id`.
* **Complementary Kyverno admission:** unsafe MCPRoutes and AIGatewayRoutes
  are rejected before installation, including model routes referencing a
  backend other than the approved demo AIServiceBackend. Admission is not runtime authorization.
* **Existing OpenReports summaries:** accumulated pass/fail counts, without
  attributed policy names or per-request correlation.
* **Fail closed:** authorizer downtime must not reach the Kubernetes backend
  or change deployment replicas.

`tools/list` remains the same five-tool catalog even after revocation:
discovery is **not** permission-filtered; calls are authorized at execution.
Policy exceptions, response filtering, and attributed/redacted reporting are
not part of this demo.

## Architecture

```text
Alice/Bob -> Keycloak JWT -> Agent Router / Envoy
                              | ext_authz gRPC + buffered request body
                              v
                         Kyverno Authz
                         | JWT/JWKS + CEL
                         | live Kubernetes SubjectAccessReview
                              |
              +---------------+-----------------+
              v                                 v
        MCP tool backends                local OpenAI-compatible backend
        real deployments/scale           deterministic responses, no paid API

Kyverno admission -> MCPRoute/AIGatewayRoute platform guardrails
```

The MCP backend uses a ServiceAccount to execute calls; the authorizer checks
the JWT user's permission separately. This is not Kubernetes impersonation.
**Authorization claims apply only to traffic through the gateway.** This Kind
demo has no backend authentication or network isolation: any pod able to reach
the `kube-tools` ClusterIP can bypass JWT/SAR checks and invoke the backend's
ServiceAccount permissions directly. Do not expose or reuse these backends
outside this disposable demo. Production requires backend authentication and/or
gateway-only ingress isolation using a NetworkPolicy-enforcing CNI; Kind's
default kindnet does not enforce NetworkPolicy.

For model routing, Agent Router's native model-routing processor extracts
`model` from the OpenAI JSON body and sets `x-ai-eg-model` before HTTPRoute
matching. The client deliberately omits that header; the live allow/deny tests
verify this native extraction path, rather than requiring callers to set it.
This processor belongs to Agent Router, not a Kyverno response-processing feature.

Runtime policies are mounted files: changes require an authorizer restart.
Both runtime path match conditions are complements because unmatched requests
are allowed by the current authorizer. Invalid file policies may be skipped;
setup first runs compilation tests to avoid deploying broken policies.

## Setup

Prerequisites: Docker running, `kind`, `kubectl`, Helm, Go, `ko`, and Python 3.
Allow roughly 8 GiB of available Docker memory for this multi-controller demo.
Setup installs Envoy Gateway v1.9.2, Agent Router v1.2.0, Kyverno chart 3.9.1
(Kyverno v1.19.1), Keycloak, and small Python backends in a disposable Kind
cluster. No paid models or external credentials are required.

From the repository root:

```bash
examples/agentrouter/scripts/setup.sh
```

The default context is `kind-kyverno-agentrouter`. To use an independent
cluster, export `CLUSTER_NAME=your-demo-name` before **all** commands
(`CONTEXT` can also be overridden). Other contexts are not modified.
Local ports 18080–18083 must be free for the automated suite. The manual
walkthrough uses 18080 for the gateway and briefly 18081 for the token helper.
Do not run the suite while the manual port-forward is active.

# Demo

Run setup once, then follow these numbered sections from the repository root.
All Kubernetes commands explicitly select the demo context; no context switch
is required. The examples use Bash, `curl`, and Python's standard library
(no `jq`). Keep terminal tracing off: never print the token or use `curl -v`.

## 1. Connect to the gateway and establish Alice's identity

In **terminal A**, discover the generated gateway Service and keep this
port-forward running in the foreground. Wait for `Forwarding from 127.0.0.1:18080`.
Stop it with **Ctrl-C** when the walkthrough ends.

```bash
export CONTEXT="${CONTEXT:-kind-${CLUSTER_NAME:-kyverno-agentrouter}}"
GATEWAY_SERVICE=$(kubectl --context "$CONTEXT" \
  -n envoy-gateway-system get services \
  -l 'gateway.envoyproxy.io/owning-gateway-name=agentrouter,gateway.envoyproxy.io/owning-gateway-namespace=agentrouter-demo' \
  -o jsonpath='{.items[0].metadata.name}')
kubectl --context "$CONTEXT" -n envoy-gateway-system \
  port-forward --address=127.0.0.1 "service/$GATEWAY_SERVICE" 18080:8080
```

In **terminal B**, seed the incident once and acquire a finite-lived JWT into
a shell variable. The helper opens/closes its own Keycloak port-forward;
command substitution captures its token instead of printing it.

```bash
set +x
export CONTEXT="${CONTEXT:-kind-${CLUSTER_NAME:-kyverno-agentrouter}}"
kubectl --context "$CONTEXT" apply -f examples/agentrouter/manifests/alice-scale.yaml
kubectl --context "$CONTEXT" -n team-a-dev scale deployment/checkout --replicas=0
kubectl --context "$CONTEXT" -n team-a-dev get deployment checkout
ALICE_TOKEN=$(examples/agentrouter/scripts/get-token.sh alice)
test -n "$ALICE_TOKEN" && printf 'Alice token acquired (not displayed).\n'
```

Expected: checkout has desired replicas `0`; the token remains only in this
shell. Initialize MCP, capture the response headers, and extract the
`Mcp-Session-Id` without exposing the bearer token:

```bash
INITIALIZE=$(curl -sS -i --max-time 20 http://127.0.0.1:18080/mcp \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"manual-demo","version":"1.0"}}}')
SESSION_ID=$(printf '%s\n' "$INITIALIZE" | python3 -c \
  'import sys; print(next(line.split(":",1)[1].strip() for line in sys.stdin if line.lower().startswith("mcp-session-id:")))')
test -n "$SESSION_ID" && printf 'MCP session established (HTTP 200 expected).\n'
printf '%s\n' "$INITIALIZE" | python3 -c \
  'import sys; print(sys.stdin.read().split("\r\n\r\n",1)[1])'
curl -sS --max-time 20 -w '\nHTTP %{http_code}\n' http://127.0.0.1:18080/mcp \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Mcp-Session-Id: $SESSION_ID" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  --data '{"jsonrpc":"2.0","method":"notifications/initialized"}'
```

Expected: initialize returns `result` with server capabilities (JSON or SSE
`data: {...}`); the notification returns HTTP 202. Keep **these same shell
variables and this terminal** through revocation and restoration.

## 2. Diagnose the real deployment

“The catalog advertises a tool; authorization decides whether it can execute.”

```bash
curl -sS --max-time 20 -w '\nHTTP %{http_code}\n' http://127.0.0.1:18080/mcp \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Mcp-Session-Id: $SESSION_ID" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
curl -sS --max-time 20 -w '\nHTTP %{http_code}\n' http://127.0.0.1:18080/mcp \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Mcp-Session-Id: $SESSION_ID" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  --data '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"kube-tools__get_workload_status","arguments":{"namespace":"team-a-dev","name":"checkout"}}}'
```

Expected: HTTP 200, five tools including `kube-tools__scale_deployment`.
The read result's text contains `"replicas": 0` and `"readyReplicas": 0`.
MCP responses may be SSE (`event: message`, `data: {...}`), not bare JSON.

## 3. Revoke writes, not the token or session

“A live Kubernetes SubjectAccessReview overrides an already authenticated
session.” Delete the RoleBinding and confirm the API says `no`:

```bash
kubectl --context "$CONTEXT" -n team-a-dev delete rolebinding alice-scale
kubectl --context "$CONTEXT" auth can-i update deployments/checkout \
  --subresource=scale -n team-a-dev --as=alice
curl -sS --max-time 20 -w '\nHTTP %{http_code}\n' http://127.0.0.1:18080/mcp \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Mcp-Session-Id: $SESSION_ID" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  --data '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":2}}}'
kubectl --context "$CONTEXT" -n team-a-dev get deployment checkout \
  -o jsonpath='{.spec.replicas}{"\n"}'
```

Expected: `no` (`can-i` exits 1 intentionally), HTTP **403** with
`Kubernetes SAR denied`, and replicas still **0**. Discovery remains unfiltered;
the tool's presence does not grant permission.

## 4. Restore permission and recover checkout

“No new JWT or MCP session: Kubernetes permission changed, so execution changes.”

```bash
kubectl --context "$CONTEXT" apply -f examples/agentrouter/manifests/alice-scale.yaml
kubectl --context "$CONTEXT" auth can-i update deployments/checkout \
  --subresource=scale -n team-a-dev --as=alice
curl -sS --max-time 20 -w '\nHTTP %{http_code}\n' http://127.0.0.1:18080/mcp \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Mcp-Session-Id: $SESSION_ID" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  --data '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":2}}}'
kubectl --context "$CONTEXT" -n team-a-dev rollout status deployment/checkout --timeout=120s
kubectl --context "$CONTEXT" -n team-a-dev get deployment checkout
```

Expected: `yes`, HTTP 200, `isError: false`, then **2/2** ready replicas.
Permission alone is not enough to bypass argument governance:

```bash
curl -sS --max-time 20 -w '\nHTTP %{http_code}\n' http://127.0.0.1:18080/mcp \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Mcp-Session-Id: $SESSION_ID" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  --data '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":50}}}'
```

Expected: HTTP **403**, `replicas must be an integer from 1 through 3`.

## 5. Govern the model request body

“Alice's entitlement permits demo-mini, not demo-pro.” Agent Router derives
its routing header from the body; callers do not need `x-ai-eg-model`.

```bash
curl -sS --max-time 20 -w '\nHTTP %{http_code}\n' http://127.0.0.1:18080/v1/chat/completions \
  -H "Authorization: Bearer $ALICE_TOKEN" -H 'Content-Type: application/json' \
  --data '{"model":"demo-mini","messages":[{"role":"user","content":"How should I recover checkout?"}],"max_tokens":128}'
curl -sS --max-time 20 -w '\nHTTP %{http_code}\n' http://127.0.0.1:18080/v1/chat/completions \
  -H "Authorization: Bearer $ALICE_TOKEN" -H 'Content-Type: application/json' \
  --data '{"model":"demo-pro","messages":[{"role":"user","content":"How should I recover checkout?"}],"max_tokens":128}'
```

Expected: HTTP **200** with a deterministic `choices` response, then HTTP
**403** with `model not allowed for alice`. No paid model API is involved.

## 6. Persist summaries without serializing credentials

“Existing OpenReports show accumulated pass/fail counts, not policy
attribution or per-request correlation.” Allow the two-second flush to settle,
then print only safe summary fields:

```bash
sleep 3
kubectl --context "$CONTEXT" -n agentrouter-demo get reports.openreports.io \
  -o 'custom-columns=NAME:.metadata.name,PASS:.summary.pass,FAIL:.summary.fail'
```

Expected: report rows with nonzero pass/fail counts (counts vary by prior runs).
Do not project raw report descriptions; setup explicitly disables request
serialization through the positional log format described below.

## 7. Block unsafe routes at admission

“Runtime checks are complemented by platform admission guardrails.” These
server dry-runs intentionally fail and do **not** replace the working routes:

```bash
kubectl --context "$CONTEXT" apply --dry-run=server \
  -f examples/agentrouter/policies/admission/cases/mcproute-fail-open.yaml
kubectl --context "$CONTEXT" apply --dry-run=server \
  -f examples/agentrouter/policies/admission/cases/aigatewayroute-unapproved-backend.yaml
```

Expected: admission `denied the request`, respectively `fail closed` and
`approved demo AIServiceBackend`. Both commands intentionally exit nonzero.

The model-route guardrail evaluates only **AIGatewayRoute create/update**:
it verifies a matching SecurityPolicy exists at that time, not its subsequent
lifecycle. Deleting or weakening that SecurityPolicy later can remove JWT and
ext_authz protection without re-evaluating the admitted route. Production must
separately protect SecurityPolicy update/delete through platform ownership,
RBAC, and admission controls; this demo does not enforce those controls.

## 8. Fail closed when the authorizer is unavailable

“No authorizer means no execution, not unrestricted remediation.” Scale it
down and wait until its pods are gone before attempting a call:

```bash
kubectl --context "$CONTEXT" -n agentrouter-demo scale deployment/kyverno-authz --replicas=0
kubectl --context "$CONTEXT" -n agentrouter-demo wait \
  --for=delete pod -l app=kyverno-authz --timeout=120s
curl -sS --max-time 20 -w '\nHTTP %{http_code}\n' http://127.0.0.1:18080/mcp \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Mcp-Session-Id: $SESSION_ID" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  --data '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":3}}}'
kubectl --context "$CONTEXT" -n team-a-dev get deployment checkout \
  -o jsonpath='{.spec.replicas}{"\n"}'
```

Expected: HTTP **500 or 503** (gateway-generated error), replicas still **2**,
not 3. Always run the recovery commands, even if the demonstration is interrupted:

```bash
kubectl --context "$CONTEXT" -n agentrouter-demo scale deployment/kyverno-authz --replicas=1
kubectl --context "$CONTEXT" -n agentrouter-demo rollout status deployment/kyverno-authz --timeout=120s
sleep 3
curl -sS --max-time 20 -w '\nHTTP %{http_code}\n' http://127.0.0.1:18080/mcp \
  -H "Authorization: Bearer $ALICE_TOKEN" -H "Mcp-Session-Id: $SESSION_ID" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  --data '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"kube-tools__get_workload_status","arguments":{"namespace":"team-a-dev","name":"checkout"}}}'
unset ALICE_TOKEN SESSION_ID INITIALIZE
```

Expected: HTTP **200**, the actual deployment still has **2** replicas.
Stop terminal A's port-forward with Ctrl-C.

### Troubleshooting and repeating the demo

JWTs expire after 30 minutes. If requests return 401, reacquire the token and
repeat initialization in section 1; do not silently change identity during
the revoke/restore comparison. A lost MCP session requires reinitialization.
If Kubernetes `can-i` has not yet reflected a RoleBinding change, repeat it
before continuing. If recovery briefly returns 503, retry the read after
endpoints propagate. To restart the incident, rerun section 1's seed commands.
After interruption, restore the RoleBinding and authorizer as shown above
(or run `scripts/reset.sh` **after** stopping the manual port-forward).

## Full suite and non-mutating checks

```bash
examples/agentrouter/scripts/run.sh
examples/agentrouter/scripts/run.sh --check
examples/agentrouter/scripts/run.sh --scenario 1
```

The full suite resets once, then checks live SAR, argument guardrails, model
governance, summaries, admission, and fail-closed behavior. `--scenario 1`
through `6` selects those respective scenarios (each begins with a reset).
`--check` verifies authentication, the unfiltered catalog, read authorization,
and allowed/denied model requests. It does **not** reset, revoke/grant RBAC,
scale deployments. Requests still
produce ordinary backend audit records and authorizer reports.

`run.sh` saves noncredential output to ignored `.state/*.log`.
`scripts/get-token.sh alice` deliberately prints a token for manual clients;
do not use it on a projected terminal or log its output.

## Reporting and local-demo limitations

The upstream default report description serializes the entire request,
including bearer tokens. This deployment explicitly overrides it with:

```text
--log-msg-format=[%[1]s] decision: %[3]s
```

Go positional formatting skips argument 2 (the request), with no unused
argument diagnostic. A focused Go test verifies this. Reporting checks also
reject bearer strings and the current token in persisted reports. The demo
prints **only summaries**, not report descriptions. This is configuration to
omit request serialization, not a new redaction feature. Do not substitute
the default format. Summaries are accumulated, not correlated to one run;
there is no claim of attributed policy names or universal response/header
redaction. Do not use real secrets in any requests.

This is disposable demo infrastructure: plaintext HTTP, Keycloak development
mode, password grant, example users, single replicas, and synthetic credential
patterns. It is not production identity, DLP, spend accounting, or policy
distribution guidance. Runtime guardrails protect the shown routes;
admission examples illustrate complementary configuration constraints.
The model backend allowlist restricts route references to `llm-backend` in
`agentrouter-demo`; it does not govern edits to that AIServiceBackend or its
underlying Backend endpoint. Those resources require separate platform ownership
and admission controls in production.

## Offline validation

```bash
go test ./examples/agentrouter/tests -count=1
python3 -m unittest discover -s examples/agentrouter/tests -p 'test_*.py'
shellcheck examples/agentrouter/scripts/*.sh
```

Validated on 2026-11-05 against upstream/main `fe9504b`: fresh setup, the
automated suite and non-mutating checks, and the manual Demo commands above
passed on Kind. The manual revoke/restore requests use the same shell-held
JWT/session. This evidence applies to that checkout, not release v0.4.0.

## Cleanup

```bash
kind delete cluster --name "${CLUSTER_NAME:-kyverno-agentrouter}"
rm -rf examples/agentrouter/.state
```
