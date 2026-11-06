# Limit an SRE assistant's tools with Agent Router and Kyverno Authz

Alice is a site reliability engineer (SRE). She keeps apps running. Her AI
assistant uses tools to help her, but it must stay within her permissions.
Showing it tools Alice can't use can lead to failed calls and confusion.

Agent Router connects your assistant to models and tools. **This Kyverno Authz
prototype checks Alice's current permissions and filters the tool list sent
back to her assistant.** It also checks each call, so the assistant can't bypass
the rules by remembering a tool's name.

## What you'll show

Alice asks her SRE assistant to run two copies of the checkout app. The assistant
remembers the tool from an earlier tool list, but permission has changed.

1. The assistant calls the remembered tool. Kyverno Authz blocks it because
   Alice doesn't currently have permission.
2. Alice approves access. You add her Kubernetes permission.
3. You refresh the tool list. All five tools appear, and the same call succeeds.
4. Alice withdraws access. You remove her permission.
5. The assistant tries the remembered tool again. The call is blocked.
   Refresh the list: only four tools remain.

The assistant keeps using the same Alice sign-in token and connection. It can
still read app status for her. Bob's tool list doesn't change because his
permissions haven't changed.

In the story, Alice approves and withdraws access. In the demo, you use an
administrator terminal to add and remove Alice's Kubernetes permission.
There is no approval screen or separate permission grant for the assistant.
The assistant cannot grant itself access, and removing this permission also
limits Alice's own calls through the gateway.

## Why it matters

**Acting for Alice doesn't give her assistant extra access.** Kyverno Authz
blocks actions she can't take and helps the assistant avoid those actions in
the first place. The same live Kubernetes permissions guide both checks.
You don't need to keep a separate tool list for each person. The checks happen
outside the assistant; they don't rely on it following instructions.

The [request-only demo](https://github.com/kyverno/kyverno-authz/tree/agent-router-demo/examples/agentrouter) checks calls but leaves the
tool list unchanged. This prototype also changes the response before the
assistant receives it. It uses the Model Context Protocol (MCP), which lets an
assistant find and call tools.

## How the prototype works

The request check uses Envoy's external authorization interface, `ext_authz`.
The new response check uses its external processing interface, `ext_proc`, to
filter the `tools/list` response. This demo requires the prototype implementation
in this branch, not just the current Kyverno Authz release.

Inspector or the Python client stands in for Alice's assistant and sends her
JWT, a signed identity token. The demo does not run an autonomous agent or a
model-driven tool loop. It has no separate agent identity, token exchange, or
proof that Alice approved a specific action. It demonstrates tool calls checked
against Alice's permissions, not a full delegation system.

**Hiding a tool doesn't secure it.** The separate request check blocks direct
calls to a hidden tool. These checks protect
**gateway-originated traffic only**: this disposable demo has no backend
authentication or network isolation, so pods reaching the `kube-tools` ClusterIP
can bypass the gateway and use its ServiceAccount. Production needs backend
authentication and/or gateway-only ingress with a NetworkPolicy-enforcing CNI;
Kind's default kindnet does not enforce NetworkPolicy.

The example is independent of the [request-only baseline demo, PR #249](https://github.com/kyverno/kyverno-authz/pull/249).
It does not require `examples/agentrouter` or its cluster.

## Setup

Stay in the repository root for every command below. Requirements: Docker,
`kind`, `kubectl`, `curl`, `helm`, Go, `ko`, Python 3.10+, internet access,
and free local ports **19080–19083**. No `jq` or Python packages are needed.

```bash
export CONTEXT="${CONTEXT:-kind-kyverno-agentrouter-extproc}"
./examples/agentrouter-extproc/scripts/setup.sh
```

Setup creates **`kyverno-agentrouter-extproc`**, installs Envoy Gateway v1.9.2,
Agent Router v1.2.0, Kyverno v1.19.1, and OpenReports, compiles the policies,
builds this checkout, and deploys Keycloak and bounded MCP backends. Its context,
image tag, and client ports are independent of the baseline demo. Allow adequate
Docker memory for both clusters. Setup is not repeated during the walkthrough.

## Demo

### Live demo: permissions limit Alice's assistant

Use [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector)
to show the actual tools and results, with a terminal beside it for RBAC changes.
Pre-stage transport, identity, and arguments; do not explain curl or JSON-RPC
framing during the live story.

**Rehearsal prerequisite:** the raw commands below are tested, but Inspector
compatibility with this gateway is not yet validated. Test authenticated
Streamable HTTP, denial rendering, and explicit catalog refresh without
reconnecting. Pin the working Inspector version and install its supported Node.js
runtime before presenting.

#### Pre-stage

1. From the repository root, set up and reset the demo:

   ```bash
   examples/agentrouter-extproc/scripts/setup.sh
   examples/agentrouter-extproc/scripts/reset.sh
   ```

   Keep the gateway port-forward from the reproduction runbook below running.
2. Launch `npx @modelcontextprotocol/inspector`; open its printed authenticated
   local URL and configure Streamable HTTP at `http://127.0.0.1:19080/mcp`.
3. Use the authentication section below to acquire Alice's token privately.
   Configure her Authorization header and connect before screen sharing.
   Do not project bearer tokens, header panes, or authentication settings.
   Do not disable Inspector's own access-token protection.
4. Fetch the catalog: Alice should see five tools. Prepare the scale tool
   `kube-tools__scale_deployment` with `team-a-dev / checkout / 2` and the
   workload-status tool with `team-a-dev / checkout`.
5. Export the context in the demonstration terminal:

   ```bash
   export CONTEXT="${CONTEXT:-kind-kyverno-agentrouter-extproc}"
   kubectl --context "$CONTEXT" -n team-a-dev delete rolebinding alice-scale --ignore-not-found
   ```

   Keep the scale tool selected from step 4. Don't refresh the list yet.
   Explain that this is a remembered tool: a fresh list would already hide it.

Keep the same authenticated connection through the story. Tokens last 24 hours
for this local demo, with matching Keycloak session limits. This extended
lifetime is not a production recommendation; live RBAC changes still take
effect without replacing the token.
Setup preserves existing identity Secrets: older clusters retain their original
realm settings unless updated or recreated. Existing JWTs keep their original
expiry; acquire new tokens after changing realm settings.

#### Show the execution boundary first

Click **Run Tool** for the selected scale tool: the call must be denied.
The assistant knows the tool's name, but that doesn't grant permission.
Read workload status to show that reads still work.

Alice approves access. In the administrator terminal, grant permission:

```bash
kubectl --context "$CONTEXT" apply -f examples/agentrouter-extproc/manifests/alice-scale.yaml
```

Refresh **List Tools** on the same connection: all five tools appear.
Repeat the prepared scale call. It succeeds; desired replicas become 2.

#### Revoke access and show the response change

Alice withdraws access. Remove her permission:

```bash
kubectl --context "$CONTEXT" -n team-a-dev delete rolebinding alice-scale
```

Repeat the scale call **before refreshing the tool list**: it must be denied.
Then refresh **List Tools**. Only four tools remain; scale is absent.
Read workload status: reads still work and desired replicas remain 2.

| State | Tool list | Execution |
|---|---|---|
| Before approval | Remembered scale tool; a fresh list has 4 tools | Scale blocked |
| Permission granted | Fresh list has 5 tools, including scale | Scale allowed |
| Permission revoked | Fresh list has 4 tools, without scale | Remembered scale call blocked |

**Takeaway:** “Alice's assistant acts for her, not above her permissions.
Kyverno Authz blocks calls she can't make and removes that tool from the
assistant's list. The assistant keeps the same token and connection.”

The live story ends with the grant removed. To restore the default state after
the demo, run the grant command above.

Keep execution to three minutes and discovery to one more. A pre-connected Bob
tab can optionally show unaffected access, but avoid switching identities in the
main story. Exceptions and reports are supplementary sections below. Discovery
filtering is not a substitute for execution authorization, and the demo's
unisolated backends remain reachable outside the gateway.

If Inspector reconnects, renews credentials, or cannot render the denial,
do not claim an unchanged session. Use the tested raw runbook instead.

### Reproduction runbook: raw commands and optional follow-ons

Run the story one command at a time, as in the
[native network-policy demo](https://github.com/nirmata/demo-network-policy-automation#demo).
This fuller runbook starts with access granted, then revokes and restores it;
the shorter live story above starts and ends with access blocked.
Use Bash and keep the main terminal open: tokens and sessions live in shell
variables, not a presenter-state file. Do not enable `set -x`, print tokens,
record authentication commands with expanded credentials, or share `.state`.
Tokens expire after **24 hours**; if they expire or Keycloak/the gateway
restarts, repeat authentication and initialization explicitly. Do not refresh
them between the permission changes.

### 1. Open the gateway and establish a clean incident

In **terminal A**, discover the generated gateway Service and leave this
loopback-only port-forward running in the foreground:
Set `CONTEXT` consistently in each terminal; environment exports are not shared
between existing terminals. The default below selects only this demo cluster.

```bash
# Terminal A
export CONTEXT="${CONTEXT:-kind-kyverno-agentrouter-extproc}"
GATEWAY_SERVICE=$(kubectl --context "$CONTEXT" \
  -n envoy-gateway-system get service \
  -l gateway.envoyproxy.io/owning-gateway-name=agentrouter,gateway.envoyproxy.io/owning-gateway-namespace=agentrouter-demo \
  -o jsonpath='{.items[0].metadata.name}')
kubectl --context "$CONTEXT" -n envoy-gateway-system \
  port-forward --address=127.0.0.1 "service/$GATEWAY_SERVICE" 19080:8080
```

Expected: `Forwarding from 127.0.0.1:19080 -> 8080`.

In **terminal B**, leave Keycloak's port-forward running:

```bash
# Terminal B
export CONTEXT="${CONTEXT:-kind-kyverno-agentrouter-extproc}"
kubectl --context "$CONTEXT" -n agentrouter-demo \
  port-forward --address=127.0.0.1 service/keycloak 19081:8080
```

In the **main terminal**, initialize paths and reset only the demo workloads:

```bash
set -euo pipefail
set +x
umask 077
export CONTEXT="${CONTEXT:-kind-kyverno-agentrouter-extproc}"
DEMO=examples/agentrouter-extproc
MCP=http://127.0.0.1:19080/mcp
TOKEN_URL=http://127.0.0.1:19081/realms/demo/protocol/openid-connect/token
RUN_ID=native-$(python3 -c 'import uuid; print(uuid.uuid4().hex[:10])')
mkdir -p "$DEMO/.state"
chmod 700 "$DEMO/.state"
./examples/agentrouter-extproc/scripts/reset.sh
kubectl --context "$CONTEXT" -n team-a-dev get deployment checkout \
  -o jsonpath='{.spec.replicas}{"\n"}'
```

Expected: `0` replicas in team A; Alice's scale grant is restored and no incident
exception remains. This creates no OAuth token or MCP session.

### 2. Authenticate Alice and Bob, then initialize MCP once

The generated demo password comes from the existing Kubernetes Secret. Pass it
to `curl` through stdin; assign token responses without displaying them:

```bash
PASSWORD=$(kubectl --context "$CONTEXT" -n agentrouter-demo get secret demo-identity \
  -o jsonpath='{.data.password}' | python3 -c 'import base64,sys; print(base64.b64decode(sys.stdin.read()).decode())')
ALICE_TOKEN=$(printf '%s' "$PASSWORD" | curl --fail-with-body -sS "$TOKEN_URL" \
  --data-urlencode grant_type=password --data-urlencode client_id=demo-cli \
  --data-urlencode username=alice --data-urlencode scope='openid profile' \
  --data-urlencode password@- \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
BOB_TOKEN=$(printf '%s' "$PASSWORD" | curl --fail-with-body -sS "$TOKEN_URL" \
  --data-urlencode grant_type=password --data-urlencode client_id=demo-cli \
  --data-urlencode username=bob --data-urlencode scope='openid profile' \
  --data-urlencode password@- \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
unset PASSWORD
test -n "$ALICE_TOKEN" && test -n "$BOB_TOKEN"
printf 'Alice and Bob authenticated; tokens not displayed.\n'
```

Expected: the confirmation above. These are the tokens used for the entire story.
Authorization headers below use curl's stdin config so credentials are not
placed in its command-line arguments.

Initialize Alice and extract the session from **response headers**, using only
Python's standard library. Files are private under the `umask` set above:

```bash
printf 'header = "Authorization: Bearer %s"\n' "$ALICE_TOKEN" \
  | curl --fail-with-body -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-alice-init" \
    -D "$DEMO/.state/alice.headers" -o "$DEMO/.state/alice-init.sse" \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"native-demo","version":"1.0"}}}'
ALICE_SESSION=$(python3 -c 'from pathlib import Path; import sys; print(next(line.split(":",1)[1].strip() for line in Path(sys.argv[1]).read_text().splitlines() if line.lower().startswith("mcp-session-id:")))' "$DEMO/.state/alice.headers")
test -n "$ALICE_SESSION"
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$ALICE_TOKEN" "$ALICE_SESSION" \
  | curl --fail-with-body -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' \
    --data '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    -o /dev/null -w 'Alice initialized: HTTP %{http_code}\n'
```

Expected: successful initialize response in `alice-init.sse`, followed by
`Alice initialized: HTTP 202` (200/204 are also valid for this notification).
Do not print the header file/session during a recorded presentation.

Initialize Bob the same way, once:

```bash
printf 'header = "Authorization: Bearer %s"\n' "$BOB_TOKEN" \
  | curl --fail-with-body -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-bob-init" \
    -D "$DEMO/.state/bob.headers" -o "$DEMO/.state/bob-init.sse" \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"native-demo","version":"1.0"}}}'
BOB_SESSION=$(python3 -c 'from pathlib import Path; import sys; print(next(line.split(":",1)[1].strip() for line in Path(sys.argv[1]).read_text().splitlines() if line.lower().startswith("mcp-session-id:")))' "$DEMO/.state/bob.headers")
test -n "$BOB_SESSION"
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$BOB_TOKEN" "$BOB_SESSION" \
  | curl --fail-with-body -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' \
    --data '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    -o /dev/null -w 'Bob initialized: HTTP %{http_code}\n'
```

### 3. Alice sees all five tools

```bash
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$ALICE_TOKEN" "$ALICE_SESSION" \
  | curl --fail-with-body -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-alice-list-before" \
    --data '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    | tee "$DEMO/.state/alice-before.sse"
```

Expected: a finite SSE response containing **five** entries in `result.tools`:
`kube-tools__get_workload_status`, `kube-tools__get_events`,
`kube-tools__get_logs`, `kube-tools__scale_deployment`, and
`runbooks__get_runbook`. The actual framing is:

```text
event: message
id: <gateway-generated event ID>
data: {"jsonrpc":"2.0","id":2,"result":{"tools":[...],"ttlMs":0,"cacheScope":"public"}}
```

The `[...]` above abbreviates tool descriptions/schemas, not a literal payload.
The `curl` command prints the real complete JSON and SSE framing.

### 4. Revoke Alice's grant: response governance removes scale

Change Kubernetes RBAC, **not** the token or MCP session:

```bash
kubectl --context "$CONTEXT" -n team-a-dev delete rolebinding alice-scale
kubectl --context "$CONTEXT" auth can-i update deployments/checkout \
  --subresource=scale -n team-a-dev --as=alice || true
```

Expected: `rolebinding ... deleted`, then `no`. Now repeat discovery with the
same shell variables:

```bash
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$ALICE_TOKEN" "$ALICE_SESSION" \
  | curl --fail-with-body -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-alice-list-hidden" \
    --data '{"jsonrpc":"2.0","id":3,"method":"tools/list"}' \
    | tee "$DEMO/.state/alice-hidden.sse"
```

Expected: the same single-event SSE shape, but **four** tools: no
`kube-tools__scale_deployment`. The response processor used a live SAR and
replaced `result.tools`, preserving the JSON-RPC fields and SSE framing.

### 5. Calling the hidden tool directly still fails

Do not rely on discovery as authorization. Name the hidden tool explicitly:

```bash
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$ALICE_TOKEN" "$ALICE_SESSION" \
  | curl -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-alice-direct-denied" \
    --data '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":2}}}' \
    -w '\nHTTP %{http_code}\n'
kubectl --context "$CONTEXT" -n team-a-dev get deployment checkout \
  -o jsonpath='{.spec.replicas}{"\n"}'
```

Expected: **HTTP 403**, `Kubernetes SAR denied`, and **0** replicas.
The independent ext_authz request policy prevented execution.

### 6. Bob is unaffected; restore Alice and execute

Bob still has his own team B scale grant:

```bash
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$BOB_TOKEN" "$BOB_SESSION" \
  | curl --fail-with-body -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-bob-list" \
    --data '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    | tee "$DEMO/.state/bob-list.sse"
kubectl --context "$CONTEXT" apply -f "$DEMO/manifests/alice-scale.yaml"
kubectl --context "$CONTEXT" auth can-i update deployments/checkout \
  --subresource=scale -n team-a-dev --as=alice
```

Expected: Bob receives **five** tools; Alice's permission check returns `yes`.
No reauthentication or reinitialization:

```bash
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$ALICE_TOKEN" "$ALICE_SESSION" \
  | curl --fail-with-body -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-alice-list-restored" \
    --data '{"jsonrpc":"2.0","id":5,"method":"tools/list"}' \
    | tee "$DEMO/.state/alice-restored.sse"
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$ALICE_TOKEN" "$ALICE_SESSION" \
  | curl --fail-with-body -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-alice-scale" \
    --data '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":2}}}' \
    -w '\nHTTP %{http_code}\n'
kubectl --context "$CONTEXT" -n team-a-dev get deployment checkout \
  -o jsonpath='{.spec.replicas}{"\n"}'
```

Expected: Alice receives **five** tools again, the scale response is successful,
and the workload now has **2** replicas. The primary response-governance story
is complete: **5 → 4 → 5 tools, one token and one session**.

### 7. Supporting incident exception: bounded break glass

This is an independent request-authorization feature, not an ext_proc dependency.
Bob normally cannot scale Alice's workload, even with an incident header:

```bash
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$BOB_TOKEN" "$BOB_SESSION" \
  | curl -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-bob-before-exception" \
    -H 'x-incident-id: INC-1234' \
    --data '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":2}}}' \
    -w '\nHTTP %{http_code}\n'
```

Expected: **403**, `namespace or workload boundary`.

Before restarting the authorizer, wait for the last request report to flush.
The reporter is process-local; do not discard unflushed decisions:

```bash
for attempt in $(seq 1 60); do
  if kubectl --context "$CONTEXT" -n agentrouter-demo get reports.openreports.io -o json \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if any(sys.argv[1] in r.get("message","") for p in d["items"] for r in p.get("results",[])) else 1)' "$RUN_ID-bob-before-exception"; then
    break
  fi
  test "$attempt" -lt 60
  sleep 1
done
```

Render the **existing exception manifest**, append a request-time expiry exactly
15 minutes ahead, and wrap it in the admitted ConfigMap. This is inline standard
Python, not a demo client command:

```bash
kubectl --context "$CONTEXT" create --dry-run=client \
  -f "$DEMO/policies/exceptions/break-glass-inc-1234.yaml" -o json \
  | python3 -c '
import json,sys
from datetime import datetime,timedelta,timezone
exception=json.load(sys.stdin)
expires=(datetime.now(timezone.utc)+timedelta(minutes=15)).isoformat().replace("+00:00","Z")
exception["spec"]["matchConditions"].append({
    "name":"expires-at",
    "expression":f"object.attributes.request.time < timestamp(\"{expires}\")"
})
print(json.dumps({
    "apiVersion":"v1","kind":"ConfigMap",
    "metadata":{**exception["metadata"],"name":"demo-exceptions","namespace":"agentrouter-demo"},
    "data":{"exception.json":json.dumps(exception)}
}))
' | kubectl --context "$CONTEXT" apply -f -
kubectl --context "$CONTEXT" -n agentrouter-demo rollout restart deployment/kyverno-authz
kubectl --context "$CONTEXT" -n agentrouter-demo rollout status deployment/kyverno-authz --timeout=120s
for attempt in $(seq 1 60); do
  if [[ "$(printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$BOB_TOKEN" "$BOB_SESSION" \
    | curl -sS --config - "$MCP" -H 'Content-Type: application/json' \
      -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2025-06-18' \
      --data '{"jsonrpc":"2.0","id":90,"method":"ping"}' -o /dev/null -w '%{http_code}')" == 200 ]]; then
    break
  fi
  test "$attempt" -lt 60
  sleep 1
done
```

Expected: ConfigMap admitted, deployment rolled out, gateway ping succeeds.
The probe waits for Envoy to observe the new authorizer endpoints; deployment
readiness alone does not guarantee that its old gRPC connection has recovered.
The exception applies only
to Bob + `INC-1234`, scale of team A's `checkout`, integer replicas **1–3**, and
unexpired requests. It skips the **whole matching policy, including its SAR**;
other policies still run. File sources require explicit reload, not a native
exception TTL controller.

```bash
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$BOB_TOKEN" "$BOB_SESSION" \
  | curl --fail-with-body -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-bob-incident-allowed" \
    -H 'x-incident-id: INC-1234' \
    --data '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":2}}}' \
    -w '\nHTTP %{http_code}\n'
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$BOB_TOKEN" "$BOB_SESSION" \
  | curl -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-bob-no-incident" \
    --data '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":2}}}' \
    -w '\nHTTP %{http_code}\n'
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$BOB_TOKEN" "$BOB_SESSION" \
  | curl -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-bob-excessive-replicas" \
    -H 'x-incident-id: INC-1234' \
    --data '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":50}}}' \
    -w '\nHTTP %{http_code}\n'
```

Expected: the incident call succeeds; missing incident and 50-replica calls
both return **403**. The workload remains at **2** replicas.

Wait for the last decision, revoke the carrier, and reload:

```bash
for attempt in $(seq 1 60); do
  if kubectl --context "$CONTEXT" -n agentrouter-demo get reports.openreports.io -o json \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if any(sys.argv[1] in r.get("message","") for p in d["items"] for r in p.get("results",[])) else 1)' "$RUN_ID-bob-excessive-replicas"; then
    break
  fi
  test "$attempt" -lt 60
  sleep 1
done
kubectl --context "$CONTEXT" -n agentrouter-demo delete configmap demo-exceptions
kubectl --context "$CONTEXT" -n agentrouter-demo rollout restart deployment/kyverno-authz
kubectl --context "$CONTEXT" -n agentrouter-demo rollout status deployment/kyverno-authz --timeout=120s
for attempt in $(seq 1 60); do
  if [[ "$(printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$BOB_TOKEN" "$BOB_SESSION" \
    | curl -sS --config - "$MCP" -H 'Content-Type: application/json' \
      -H 'Accept: application/json, text/event-stream' -H 'MCP-Protocol-Version: 2025-06-18' \
      --data '{"jsonrpc":"2.0","id":91,"method":"ping"}' -o /dev/null -w '%{http_code}')" == 200 ]]; then
    break
  fi
  test "$attempt" -lt 60
  sleep 1
done
printf 'header = "Authorization: Bearer %s"\nheader = "Mcp-Session-Id: %s"\n' "$BOB_TOKEN" "$BOB_SESSION" \
  | curl -sS --config - "$MCP" \
    -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -H "x-demo-id: $RUN_ID-bob-exception-revoked" \
    -H 'x-incident-id: INC-1234' \
    --data '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"kube-tools__scale_deployment","arguments":{"namespace":"team-a-dev","name":"checkout","replicas":2}}}' \
    -w '\nHTTP %{http_code}\n'
```

Expected: **403** again despite the incident header; no new token/session needed.

### 8. Inspect request decisions without printing tokens

Wait for the final decision, then print only report summaries and selected
result properties. Never dump header files or arbitrary report messages:

```bash
for attempt in $(seq 1 60); do
  if kubectl --context "$CONTEXT" -n agentrouter-demo get reports.openreports.io -o json \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if any(sys.argv[1] in r.get("message","") for p in d["items"] for r in p.get("results",[])) else 1)' "$RUN_ID-bob-exception-revoked"; then
    break
  fi
  test "$attempt" -lt 60
  sleep 1
done
kubectl --context "$CONTEXT" -n agentrouter-demo get reports.openreports.io -o json \
  | python3 -c '
import json,sys
for report in json.load(sys.stdin)["items"]:
    print(report["metadata"]["name"], report.get("summary",{}))
    for result in report.get("results",[]):
        if sys.argv[1] in result.get("message",""):
            print(" ",result["result"],result.get("policy") or "(default allow)",
                  {k:v for k,v in result.get("properties",{}).items() if k in ("method","path","status")})
' "$RUN_ID"
```

Expected: pass/fail request results attributed to
`agentrouter-bounded-operations`; the incident exemption is **pass/default allow**,
not an attributed exception/skip. Reports omit request bodies and redact
credential headers, but do not sanitize arbitrary policy messages or URLs.
**There are no ext_proc response-decision reports.** That observability gap,
and bounded event channels that may drop events under load, remain limitations.

### 9. Reset or clean up

In the main terminal, release shell secrets and private session-response files:

```bash
unset ALICE_TOKEN BOB_TOKEN ALICE_SESSION BOB_SESSION
rm -f "$DEMO/.state/alice.headers" "$DEMO/.state/bob.headers" \
  "$DEMO/.state/alice-init.sse" "$DEMO/.state/bob-init.sse" \
  "$DEMO/.state/alice-before.sse" "$DEMO/.state/alice-hidden.sse" \
  "$DEMO/.state/alice-restored.sse" "$DEMO/.state/bob-list.sse"
./examples/agentrouter-extproc/scripts/reset.sh
```

Expected: Alice's grant restored, team A **0** replicas, team B **1**, exception
absent. Press **Ctrl-C** in terminals A/B to stop both foreground port-forwards.
To remove only this demo's disposable cluster:

```bash
# Optional cluster cleanup
kind delete cluster --name kyverno-agentrouter-extproc
rm -rf examples/agentrouter-extproc/.state
```

## Automated verification

The native walkthrough above is the presentation interface. The existing client
still provides the full contextual suite (requests, models, admission, incidents,
reports, and fail closed) and non-mutating smoke checks. Stop the manual
port-forwards first: these commands manage their own ports and sessions.

```bash
./examples/agentrouter-extproc/scripts/run.sh
./examples/agentrouter-extproc/scripts/run.sh --check
./examples/agentrouter-extproc/scripts/run.sh --scenario 1
go test ./examples/agentrouter-extproc/tests
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s examples/agentrouter-extproc/tests
shellcheck -x -P examples/agentrouter-extproc/scripts examples/agentrouter-extproc/scripts/*.sh
```

## Prototype contract and hard limitations

Envoy saves the request and sends buffered responses to the separate ext_proc
service on 9083. `EnvoyProcessor` policies filter discovery using live SARs and
replace a single SSE event's data while preserving its event/ID framing.
Processor policies use external file/Git/OCI sources, not Kubernetes watching;
the mounted ConfigMap files are **loaded once** and changes require a restart.
Sources are mode-filtered so ext_authz never compiles processor policies.

- Configure buffered bodies and Envoy size/time limits. **Multi-chunk bodies
  intentionally bypass final evaluation**, not just the last-chunk replacement.
- **Compressed responses intentionally bypass response evaluation.**
- Rewriting **multi-event SSE fails closed with 500**; this discovery policy
  requires exactly one identified `message` event. Indefinite/general streaming
  response governance is unsupported.
- Response-only streams without saved request context pass through. Evaluation
  errors fail closed unless `--extproc-fail-open` is explicitly enabled.
- Reporting redaction/attribution, exception source fixes, and embedded schemas
  are supporting changes useful independently, not inherent ext_proc dependencies.
- The model-route guardrail restricts references to `llm-backend` in
  `agentrouter-demo`, not changes to that backend or its endpoint. It checks the
  protecting SecurityPolicy only when the AIGatewayRoute is **created or updated**;
  it does not prevent later deletion or weakening of that SecurityPolicy. Separate
  platform ownership/admission controls must preserve protection over time. Agent Router's
  native model processor derives `x-ai-eg-model` from the OpenAI body before
  routing; that is request routing, not Kyverno response processing.

See [the processor contract](../../pkg/authz/extproc/README.md). This remains
a local prototype, not a production compatibility/security guarantee.

## Proof manifests

These paths satisfy the PR template's proof-manifest references:

| Proof | Manifests | Native verification |
| --- | --- | --- |
| Response filtering | [`processor policy`](policies/processor/mcp-tool-discovery.yaml), [`extension`](manifests/extproc.yaml), [`grant`](manifests/alice-scale.yaml) | Demo 3–6: same-session 5/4/5 discovery |
| Direct authorization | [`request policy`](policies/authz/mcp-operations.yaml), [`RBAC`](manifests/rbac.yaml) | Demo 5–6: denied call then actual scale |
| Bounded exception | [`exception`](policies/exceptions/break-glass-inc-1234.yaml), [`admission`](policies/admission/exception-guardrails.yaml) | Demo 7: admit/allow/narrowness/revoke |
| Request reports | [`workloads`](manifests/workloads.yaml), [`report schema`](install/openreports.io_reports.yaml) | Demo 8: request-only attribution |
| Secondary model/admission context | [`model policy`](policies/authz/llm-models.yaml), [`models`](manifests/models.yaml), [`invalid cases`](policies/admission/cases) | Automated suite |
