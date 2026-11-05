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
  for each Kubernetes tool execution. Revoke and restore Alice's scale
  RoleBinding while keeping the **same JWT and MCP session**.
* **Versioned runtime policies:** namespace/workload boundaries and bounded
  tool arguments, with compilation tests before deployment.
* **Model request-body governance:** model entitlement, output-token limits,
  completion count, function-calling restrictions, and example credential
  patterns. The verified identity overwrites a spoofed `x-tenant-id`.
* **Complementary Kyverno admission:** unsafe MCPRoutes and AIGatewayRoutes
  are rejected before installation. Admission is not runtime authorization.
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
Local ports 18080–18083 must be free; each command opens and closes its own
loopback-only port-forwards. Do not run clients concurrently.

## Presentation: ordered copy/paste runbook

Run setup once beforehand. Each invocation below executes one named segment
and prints `SAY`, `ACTION`, and verified `PASS` output. It never automatically
runs the remaining segments. Only `status` resets the incident and acquires
identity; other steps require the saved session and do not silently refresh it.

```bash
# 1. Seed zero replicas and establish a private Alice JWT + MCP session.
examples/agentrouter/scripts/step.sh status

# 2. "Alice reads her actual deployment through the router."
examples/agentrouter/scripts/step.sh read

# 3. "Now revoke Kubernetes write permission, not the token or session."
examples/agentrouter/scripts/step.sh revoke

# 4. "Same JWT, same session: execution now fails a live SAR."
examples/agentrouter/scripts/step.sh denied

# 5. "Restore permission without issuing a new token."
examples/agentrouter/scripts/step.sh restore

# 6. "The same identity can recover checkout, but only within the bounds."
examples/agentrouter/scripts/step.sh scale

# 7. "Alice can use demo-mini; a premium model request never reaches the backend."
examples/agentrouter/scripts/step.sh models

# 8. "Existing reports persist accumulated pass/fail summaries."
examples/agentrouter/scripts/step.sh reports

# 9. "Admission prevents unsafe routing configuration before runtime."
examples/agentrouter/scripts/step.sh guardrails

# 10. "Stop the authorizer: no execution. Restore it and verify recovery."
examples/agentrouter/scripts/step.sh fail-closed
```

Tokens have a bounded 30-minute lifetime. Token, session, sequence, and run ID
persist in ignored `.state/session.json` (directory 0700, file 0600). Tokens
are never printed by the presentation steps. An absent, expired, or
wrong-context session gives a prerequisite error: restart at `status`.
`fail-closed` restores the authorizer in `finally`; after an interrupted
presentation, use `scripts/reset.sh` to restore permission and authorizer
availability, then `step.sh status` to start again.

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
scale deployments, or write presentation session state. Requests still
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

## Offline validation

```bash
go test ./examples/agentrouter/tests -count=1
python3 -m unittest discover -s examples/agentrouter/tests -p 'test_*.py'
shellcheck examples/agentrouter/scripts/*.sh
```

Validated on 2026-11-05 against upstream/main `fe9504b`: fresh
`setup.sh`, full `run.sh`, `run.sh --check`, and all ten presentation steps
in the order above passed on Kind. A separate check compared the saved JWT
and session after every step (unchanged, mode 0600), and verified `--check`
preserved workload specs, RBAC, and presentation state. Persisted reports
contained neither the presentation token nor bearer/request authorization
strings. This evidence applies to that checkout, not release v0.4.0.

## Cleanup

```bash
kind delete cluster --name "${CLUSTER_NAME:-kyverno-agentrouter}"
rm -rf examples/agentrouter/.state
```
