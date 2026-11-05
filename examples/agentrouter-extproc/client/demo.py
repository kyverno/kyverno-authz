"""Exercise the real gateway, authorizer, MCP backends, and Kubernetes API."""

import argparse
import base64
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import uuid

DEMO_DIR = Path(__file__).resolve().parent.parent
CONTEXT = "kind-kyverno-agentrouter-extproc"
NAMESPACE = "agentrouter-demo"
GATEWAY = "http://127.0.0.1:19080/mcp"
KEYCLOAK = "http://127.0.0.1:19081/realms/demo"
AUDIT = "http://127.0.0.1:19082/audit"
MODELS = "http://127.0.0.1:19080/v1/chat/completions"
MODEL_AUDIT = "http://127.0.0.1:19083/audit"
REQUEST_IDS = set()
BREAK_GLASS_ID = None


def kubectl(*args):
    return subprocess.check_output(
        ["kubectl", "--context", CONTEXT, *args], text=True,
    ).strip()


def http(url, body=None, headers=None, method=None):
    request = Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urlopen(request, timeout=20) as response:
            return response.status, dict(response.headers), response.read().decode()
    except HTTPError as error:
        return error.code, dict(error.headers), error.read().decode()


@contextmanager
def port_forward(namespace, resource, local_port, remote_port, probe):
    state_dir = DEMO_DIR / ".state"
    state_dir.mkdir(exist_ok=True)
    with tempfile.TemporaryFile(mode="w+", dir=state_dir) as log:
        process = subprocess.Popen(
            ["kubectl", "--context", CONTEXT, "-n", namespace, "port-forward",
             "--address=127.0.0.1", resource, f"{local_port}:{remote_port}"],
            stdout=log, stderr=log,
        )
        try:
            deadline = time.monotonic() + 60
            while True:
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(f"port-forward exited: {log.read()}")
                log.seek(0)
                forwarding = f"Forwarding from 127.0.0.1:{local_port}" in log.read()
                if forwarding:
                    try:
                        http(probe)
                        break
                    except (URLError, TimeoutError, ConnectionError):
                        pass
                if time.monotonic() > deadline:
                    raise TimeoutError(f"port-forward did not become responsive: {resource}")
                time.sleep(0.25)
            yield
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def gateway_service():
    services = json.loads(kubectl(
        "get", "services", "-n", "envoy-gateway-system",
        "-l", "gateway.envoyproxy.io/owning-gateway-name=agentrouter,"
        "gateway.envoyproxy.io/owning-gateway-namespace=agentrouter-demo",
        "-o", "json",
    ))["items"]
    if len(services) != 1:
        raise RuntimeError(f"expected exactly one gateway Service, found {len(services)}")
    return "service/" + services[0]["metadata"]["name"]


class Client:
    def __init__(self, token=None):
        self.token = token
        self.session = None
        self.sequence = 0
        self.run_id = uuid.uuid4().hex[:10]
        self.headers = {}

    def raw(self, payload, demo_id=None):
        headers = {
            **self.headers,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-06-18",
            "x-demo-id": demo_id or f"{self.run_id}-{self.sequence}",
        }
        REQUEST_IDS.add(headers["x-demo-id"])
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        return http(GATEWAY, payload, headers)

    def request(self, method, params=None):
        self.sequence += 1
        payload = {"jsonrpc": "2.0", "id": self.sequence, "method": method}
        if params is not None:
            payload["params"] = params
        status, headers, body = self.raw(json.dumps(payload).encode())
        if status != 200:
            raise AssertionError(f"{method}: HTTP {status}: {body}")
        response = decode_rpc(body)
        if "error" in response:
            raise AssertionError(f"{method}: JSON-RPC error: {response['error']}")
        for key, value in headers.items():
            if key.lower() == "mcp-session-id":
                self.session = value
        return response["result"]

    def initialize(self):
        self.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "kyverno-agentrouter-demo", "version": "1.0"},
        })
        status, _, body = self.raw(json.dumps({
            "jsonrpc": "2.0", "method": "notifications/initialized",
        }).encode())
        if status not in (200, 202, 204):
            raise AssertionError(f"initialize notification: HTTP {status}: {body}")


EXPECTED_TOOLS = {
    "kube-tools__get_workload_status", "kube-tools__get_events",
    "kube-tools__get_logs", "kube-tools__scale_deployment", "runbooks__get_runbook",
}
SCALE_TOOL = "kube-tools__scale_deployment"


def tools_list(user):
    return {tool["name"] for tool in user.request("tools/list")["tools"]}


def check_discovery(user, label, can_scale):
    expected = EXPECTED_TOOLS if can_scale else EXPECTED_TOOLS - {SCALE_TOOL}
    tools = tools_list(user)
    if tools != expected:
        raise AssertionError(f"{label}: expected {sorted(expected)}, got {sorted(tools)}")
    print(f"PASS | TOOLS | {label} | scale_deployment={'visible' if can_scale else 'hidden'}; "
          f"{len(tools)} tools", flush=True)


def decode_rpc(body):
    if body.lstrip().startswith("{"):
        return json.loads(body)
    for line in body.splitlines():
        if line.startswith("data:"):
            value = json.loads(line[5:].strip())
            if "result" in value or "error" in value:
                return value
    raise AssertionError(f"no JSON-RPC response in: {body}")


def token(username, password):
    status, _, body = http(
        KEYCLOAK + "/protocol/openid-connect/token",
        urlencode({
            "grant_type": "password", "client_id": "demo-cli",
            "username": username, "password": password, "scope": "openid profile",
        }).encode(),
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status != 200:
        raise AssertionError(f"Keycloak token request failed: HTTP {status}: {body}")
    return json.loads(body)["access_token"]


def password():
    return base64.b64decode(kubectl(
        "get", "secret", "demo-identity", "-n", NAMESPACE,
        "-o", "jsonpath={.data.password}",
    )).decode()


def replicas(namespace):
    return int(kubectl(
        "get", "deployment", "checkout", "-n", namespace,
        "-o", "jsonpath={.spec.replicas}",
    ))


def audit():
    status, _, body = http(AUDIT)
    if status != 200:
        raise AssertionError(f"backend audit endpoint failed: HTTP {status}")
    return json.loads(body)


def allowed(client, tool, arguments):
    result = client.request("tools/call", {"name": tool, "arguments": arguments})
    if result.get("isError"):
        raise AssertionError(f"{tool}: backend error: {result}")
    if tool.startswith("kube-tools__") and not any(
        record["phase"] == "success" and record["demo_id"] == f"{client.run_id}-{client.sequence}"
        for record in audit()
    ):
        raise AssertionError("allowed request has no correlated successful backend execution")
    return result["content"][0]["text"]


def denied(client, tool, arguments, reason, expected_status=403, label=None):
    demo_id = f"{client.run_id}-deny-{uuid.uuid4().hex[:8]}"
    before = {namespace: replicas(namespace) for namespace in ("team-a-dev", "team-b-dev")}
    status, _, body = client.raw(json.dumps({
        "jsonrpc": "2.0", "id": demo_id, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }).encode(), demo_id)
    statuses = expected_status if isinstance(expected_status, tuple) else (expected_status,)
    if status not in statuses or reason not in body:
        raise AssertionError(f"expected HTTP {expected_status} / {reason!r}, got {status}: {body}")
    if any(record["demo_id"] == demo_id for record in audit()):
        raise AssertionError("denied request reached the Kubernetes MCP backend")
    for namespace, count in before.items():
        if replicas(namespace) != count:
            raise AssertionError(f"denied request changed {namespace}")
    print(f"PASS | DENY  | {label or reason} | HTTP {status}; no backend execution or state change", flush=True)


def wait_until(description, predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise TimeoutError(description)
        time.sleep(0.5)


def alice_can_scale():
    result = subprocess.run(
        ["kubectl", "--context", CONTEXT, "auth", "can-i", "update", "deployments/checkout",
         "--subresource=scale", "-n", "team-a-dev", "--as=alice"],
        text=True, capture_output=True,
    )
    if result.returncode not in (0, 1) or result.stdout.strip() not in ("yes", "no"):
        raise RuntimeError(f"cannot query Alice's permissions: {result.stderr}")
    return result.stdout.strip() == "yes"


def authorizer_ready():
    slices = json.loads(kubectl(
        "get", "endpointslices", "-n", NAMESPACE,
        "-l", "kubernetes.io/service-name=kyverno-authz", "-o", "json",
    ))["items"]
    return any(
        endpoint.get("conditions", {}).get("ready", False)
        for item in slices for endpoint in item.get("endpoints", [])
    )


def chat(access_token, request, demo_id, extra_headers=None):
    REQUEST_IDS.add(demo_id)
    headers = {"Content-Type": "application/json", "x-demo-id": demo_id, **(extra_headers or {})}
    if access_token:
        headers["Authorization"] = "Bearer " + access_token
    return http(MODELS, json.dumps(request).encode(), headers)


def model_audit():
    status, _, body = http(MODEL_AUDIT)
    if status != 200:
        raise AssertionError(f"model backend audit endpoint failed: HTTP {status}")
    return json.loads(body)


def prompt(model, text="checkout has zero replicas; what should I do?", **fields):
    return {"model": model, "messages": [{"role": "user", "content": text}], "max_tokens": 128, **fields}


def model_allowed(user, access_token, request, label):
    demo_id = "model-" + uuid.uuid4().hex[:10]
    # A spoofed tenant header must be replaced by the identity Kyverno verified.
    status, _, body = chat(access_token, request, demo_id, {"x-tenant-id": "spoofed"})
    if status != 200:
        raise AssertionError(f"{label}: expected HTTP 200, got {status}: {body}")
    answer = json.loads(body)["choices"][0]["message"]["content"]
    records = [record for record in model_audit() if record["demo_id"] == demo_id]
    if len(records) != 1 or records[0]["tenant"] != user or records[0]["model"] != request["model"]:
        raise AssertionError(f"{label}: backend did not see one request attributed to {user}: {records}")
    print(f"PASS | ALLOW | {label} | tenant={user}; {answer}", flush=True)


def model_denied(access_token, request, reason, label, expected_status=403):
    demo_id = "model-" + uuid.uuid4().hex[:10]
    status, _, body = chat(access_token, request, demo_id)
    if status != expected_status or reason not in body:
        raise AssertionError(f"{label}: expected HTTP {expected_status} / {reason!r}, got {status}: {body}")
    if any(record["demo_id"] == demo_id for record in model_audit()):
        raise AssertionError(f"{label}: denied request reached the model backend")
    print(f"PASS | DENY  | {label} | HTTP {status}; model backend never called", flush=True)


def admission_cases():
    for path in sorted((DEMO_DIR / "policies/admission/cases").glob("*.yaml")):
        expected = json.loads(kubectl("create", "--dry-run=client", "-f", str(path), "-o", "json"))[
            "metadata"]["annotations"]["demo.kyverno.io/expected-denial"]
        result = subprocess.run(
            ["kubectl", "--context", CONTEXT, "apply", "--dry-run=server", "-f", str(path)],
            text=True, capture_output=True,
        )
        if result.returncode == 0 or "denied the request" not in result.stderr or expected not in result.stderr:
            raise AssertionError(f"{path.name}: expected admission denial {expected!r}: {result.stdout}{result.stderr}")
        message = result.stderr.strip().split("failed: ", 1)[-1]
        print(f"PASS | DENY  | {path.stem} | {message}", flush=True)
    for manifest in ("manifests/gateway.yaml", "manifests/models.yaml"):
        kubectl("apply", "--dry-run=server", "-f", str(DEMO_DIR / manifest))
    print("PASS | ALLOW | the demo's own MCPRoute and AIGatewayRoute satisfy every guardrail", flush=True)


def scene(number, title, value):
    print(f"\nScenario {number}: {title}\nKyverno Authz value: {value}", flush=True)


def report_matches(result, identifier):
    text = result.get("message", result.get("description", "")) + json.dumps(result.get("properties", {}))
    return json.dumps(identifier) in text


def decision_reports(tokens, required_policies=None):
    if required_policies is None:
        required_policies = {"agentrouter-bounded-operations", "agentrouter-model-governance"}
    def results_for_run():
        reports = json.loads(kubectl("get", "reports.openreports.io", "-n", NAMESPACE, "-o", "json"))["items"]
        encoded = json.dumps(reports)
        if "Bearer " in encoded or any(secret and secret in encoded for secret in tokens):
            raise AssertionError("credential leaked into an OpenReport")
        results = [result for report in reports for result in report.get("results", [])
                   if any(report_matches(result, identifier) for identifier in REQUEST_IDS)]
        policies = {result.get("policy") for result in results}
        return reports, results, policies

    wait_until("correlated pass/fail decisions and policy names were not reported", lambda: (
        required_policies <= results_for_run()[2] and
        {"pass", "fail"} <= {result["result"] for result in results_for_run()[1]} and
        (not BREAK_GLASS_ID or any(report_matches(result, BREAK_GLASS_ID) and
                                  result["result"] == "pass" and not result.get("policy")
                                  for result in results_for_run()[1]))
    ), timeout=45)
    reports, results, _ = results_for_run()
    for report in reports:
        if not any(report_matches(result, identifier) for result in report.get("results", []) for identifier in REQUEST_IDS):
            continue
        summary = report.get("summary", {})
        print(f"REPORT | {report['metadata']['name']} | " +
              "; ".join(f"{key}={summary.get(key, 0)}" for key in ("pass", "fail", "error")), flush=True)
    for result in results:
        identifiers = sorted(identifier for identifier in REQUEST_IDS if report_matches(result, identifier))
        print(f"RESULT | {result['result']} | policy={result.get('policy') or '(default allow)'} | "
              f"x-demo-id={','.join(identifiers)}", flush=True)
    if BREAK_GLASS_ID:
        incident_results = [result for result in results if report_matches(result, BREAK_GLASS_ID)]
        if not any(result["result"] == "pass" and not result.get("policy") for result in incident_results):
            raise AssertionError("break-glass request must report pass with no deciding policy")
        print("PASS | REPORT | break-glass is pass/default allow, not an attributed exception/skip", flush=True)
    print(f"PASS | REPORT | {len(results)} correlated decisions; no bearer credentials", flush=True)


def reload_authorizer():
    kubectl("rollout", "restart", "deployment/kyverno-authz", "-n", NAMESPACE)
    kubectl("rollout", "status", "deployment/kyverno-authz", "-n", NAMESPACE, "--timeout=120s")
    wait_until("authorizer did not become ready after file reload", authorizer_ready)


def incident_configmap():
    path = str(DEMO_DIR / "policies/exceptions/break-glass-inc-1234.yaml")
    exception = json.loads(kubectl("create", "--dry-run=client", "-f", path, "-o", "json"))
    expires = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat().replace("+00:00", "Z")
    exception["spec"]["matchConditions"].append({
        "name": "expires-at",
        "expression": f'object.attributes.request.time < timestamp("{expires}")',
    })
    return {
        "apiVersion": "v1", "kind": "ConfigMap",
        "metadata": {**exception["metadata"], "name": "demo-exceptions", "namespace": NAMESPACE},
        "data": {"exception.json": json.dumps(exception)},
    }


def break_glass(alice, bob, own, other, report_policies):
    global BREAK_GLASS_ID
    configmap = incident_configmap()
    arguments = {**own, "replicas": 2}
    denied(bob, SCALE_TOOL, arguments, "namespace or workload boundary")
    kubectl("delete", "rolebinding", "alice-scale", "-n", "team-a-dev")
    try:
        wait_until("Alice RBAC revocation not observed", lambda: not alice_can_scale())
        decision_reports([alice.token, bob.token], report_policies)
        subprocess.check_output(["kubectl", "--context", CONTEXT, "apply", "-f", "-"],
                                input=json.dumps(configmap), text=True)
        reload_authorizer()
        bob.headers["x-incident-id"] = "INC-1234"
        payload = json.dumps({"jsonrpc": "2.0", "id": "exception-watch", "method": "tools/call",
                              "params": {"name": SCALE_TOOL, "arguments": arguments}}).encode()
        wait_until("exception was not observed", lambda: bob.raw(payload, f"{bob.run_id}-watch-{uuid.uuid4().hex[:8]}")[0] == 200)
        allowed(bob, SCALE_TOOL, arguments)
        BREAK_GLASS_ID = f"{bob.run_id}-{bob.sequence}"
        if replicas("team-a-dev") != 2:
            raise AssertionError("break-glass call did not scale team A")
        print("PASS | ALLOW | Bob + INC-1234 remediates team A; whole policy including SAR skipped", flush=True)
        bob.headers.clear()
        denied(bob, SCALE_TOOL, arguments, "namespace or workload boundary", label="Bob without incident header")
        bob.headers["x-incident-id"] = "INC-1234"
        denied(bob, SCALE_TOOL, {**arguments, "replicas": 50}, "namespace or workload boundary", label="exception replica bound")
        alice.headers["x-incident-id"] = "INC-1234"
        denied(alice, SCALE_TOOL, arguments, "Kubernetes SAR denied", label="Alice cannot use Bob's exception")
        denied(bob, "kube-tools__get_workload_status", own, "namespace or workload boundary")
        allowed(bob, SCALE_TOOL, {**other, "replicas": 2})
        def incident_flushed():
            reports = json.loads(kubectl("get", "reports.openreports.io", "-n", NAMESPACE, "-o", "json"))["items"]
            results = [result for report in reports for result in report.get("results", [])]
            return all(any(report_matches(result, identifier) for result in results)
                       for identifier in (BREAK_GLASS_ID, f"{bob.run_id}-{bob.sequence}"))
        wait_until("incident audit decisions were not flushed before authorizer reload", incident_flushed)
    finally:
        alice.headers.clear()
        bob.headers.clear()
        kubectl("delete", "configmap", "demo-exceptions", "-n", NAMESPACE, "--ignore-not-found")
        reload_authorizer()
        kubectl("apply", "-f", str(DEMO_DIR / "manifests/alice-scale.yaml"))
    bob.headers["x-incident-id"] = "INC-1234"
    try:
        wait_until("exception deletion was not observed", lambda: bob.raw(payload, f"{bob.run_id}-watch-{uuid.uuid4().hex[:8]}")[0] == 403)
        denied(bob, SCALE_TOOL, arguments, "namespace or workload boundary", label="exception removed")
    finally:
        bob.headers.clear()
    wait_until("Alice RBAC restoration not observed", alice_can_scale)


def run_demo(only=None):
    global BREAK_GLASS_ID
    def want(number):
        return only is None or only == number

    subprocess.run([str(DEMO_DIR / "scripts/reset.sh")], check=True)
    REQUEST_IDS.clear()
    BREAK_GLASS_ID = None
    if replicas("team-a-dev") != 0:
        raise AssertionError("reset did not seed the zero-replica incident")
    demo_password = password()
    alice = Client(token("alice", demo_password))
    bob = Client(token("bob", demo_password))
    for client in (alice, bob):
        client.initialize()
    check_discovery(alice, "Alice after reset", True)
    check_discovery(bob, "Bob (team-b-dev scaler)", True)

    own = {"namespace": "team-a-dev", "name": "checkout"}
    other = {"namespace": "team-b-dev", "name": "checkout"}
    if want(1):
        scene(1, "Live RBAC and tool discovery", "Live SubjectAccessReviews and per-user tools/list response filtering exceed native request-only CEL.")
        kubectl("delete", "rolebinding", "alice-scale", "-n", "team-a-dev")
        try:
            wait_until("RBAC revocation was not observed", lambda: not alice_can_scale())
            check_discovery(alice, "Alice before grant", False)
            check_discovery(bob, "Bob while Alice is revoked", True)
            denied(alice, "kube-tools__scale_deployment", {**own, "replicas": 2}, "Kubernetes SAR denied")
            allowed(alice, "kube-tools__get_workload_status", own)
            print("PASS | ALLOW | revoking writes preserves Alice's read access", flush=True)
        finally:
            kubectl("apply", "-f", str(DEMO_DIR / "manifests/alice-scale.yaml"))
        wait_until("RBAC restoration was not observed", alice_can_scale)
        check_discovery(alice, "Alice after grant (same token/session)", True)
        allowed(alice, "kube-tools__scale_deployment", {**own, "replicas": 3})
        kubectl("rollout", "status", "deployment/checkout", "-n", "team-a-dev", "--timeout=120s")
        recovered = json.loads(allowed(alice, "kube-tools__get_workload_status", own))
        if recovered["replicas"] != 3 or recovered["readyReplicas"] != 3:
            raise AssertionError(f"workload did not recover: {recovered}")
        allowed(alice, "kube-tools__get_logs", own)
        allowed(bob, "kube-tools__scale_deployment", {**other, "replicas": 2})
        print("PASS | ALLOW | restored permission recovers team A; Bob can remediate team B", flush=True)

    if want(2):
        scene(2, "Request guardrails", "Simple user/tool/argument checks are possible natively; here they share versioned, unit-tested policy language.")
        if only == 2:
            # Scenario 1 normally recovers team A to 3 replicas; do that directly when run alone.
            allowed(alice, "kube-tools__scale_deployment", {**own, "replicas": 3})
            kubectl("rollout", "status", "deployment/checkout", "-n", "team-a-dev", "--timeout=120s")
            print("SETUP | team A recovered to 3 replicas for a standalone run", flush=True)
        print(allowed(alice, "runbooks__get_runbook", {}), flush=True)
        status = json.loads(allowed(alice, "kube-tools__get_workload_status", own))
        if status["replicas"] != 3:
            raise AssertionError(f"expected the recovered deployment: {status}")
        allowed(alice, "kube-tools__get_events", own)
        allowed(alice, "kube-tools__get_logs", own)
        print("PASS | ALLOW | Alice diagnoses her deployment", flush=True)
        denied(alice, "kube-tools__get_workload_status", other, "namespace or workload boundary")
        denied(bob, "kube-tools__scale_deployment", {**own, "replicas": 2}, "namespace or workload boundary")

        denied(alice, "kube-tools__scale_deployment", {**other, "replicas": 2}, "namespace or workload boundary")
        for value in (50, 0, -1, 1.5, "2", True):
            denied(alice, "kube-tools__scale_deployment", {**own, "replicas": value},
                   "replicas must be an integer from 1 through 3")
        denied(alice, "kube-tools__scale_deployment", own, "replicas must be an integer from 1 through 3")
        denied(alice, "kube-tools__shell", own, "tool not allowed")
        denied(alice, "kube-tools__scale_deployment",
               {**own, "replicas": 2, "command": "ignored"}, "unexpected tool arguments")
        denied(alice, "kube-tools__scale_deployment",
               {**own, "name": "another-deployment", "replicas": 2}, "namespace or workload boundary")
        allowed(alice, "kube-tools__scale_deployment", {**own, "replicas": 2})
        if replicas("team-a-dev") != 2:
            raise AssertionError("authorized remediation did not change the actual deployment")
        print("PASS | ALLOW | bounded remediation changed the actual deployment to 2 replicas", flush=True)

    if want(3):
        scene(3, "Model governance", "AIGatewayRoute has no CEL authorization; inspect bodies and inject verified x-tenant-id.")
        model_allowed("alice", alice.token, prompt("demo-mini"), "Alice asks demo-mini for help")
        model_denied(alice.token, prompt("demo-pro"), "model not allowed for alice", "Alice requests a premium model")
        model_denied(alice.token, prompt("demo-mini", max_tokens=4000), "max_tokens exceeds the limit for alice",
                     "Alice requests 4000 output tokens")
        unbounded = prompt("demo-mini")
        del unbounded["max_tokens"]
        model_denied(alice.token, unbounded, "max_tokens is required", "unbounded completion")
        model_denied(alice.token, prompt("demo-mini", n=5), "only one completion per request", "five completions")
        model_denied(alice.token, prompt("demo-mini", tools=[{"type": "function", "function": {"name": "shell"}}]),
                     "tool calling not allowed for alice", "Alice enables function calling")
        model_denied(alice.token, prompt("demo-mini", "debug with key AKIA" + "ABCDEFGHIJKLMNOP"),
                     "prompt contains a credential", "credential pasted into a prompt")
        model_denied(None, prompt("demo-mini"), "", "missing token", 401)
        model_allowed("bob", bob.token, prompt("demo-pro", max_tokens=1024), "Bob uses his premium entitlement")

    if want(4):
        scene(4, "Break-glass exceptions", "Incident-scoped policy exception files, governed ConfigMap + TTL, explicit reload; no native lifecycle equivalent.")
        break_glass(alice, bob, own, other,
                    None if only is None else {"agentrouter-bounded-operations"})

    if want(5):
        scene(5, "Decision reports", "OpenReports persists correlated policy decisions beyond gateway routing and access logs.")
        if only == 5:
            # Reports need pass and fail decisions from both runtime policies in this run.
            allowed(alice, "kube-tools__get_workload_status", own)
            denied(alice, "kube-tools__get_workload_status", other, "namespace or workload boundary")
            model_allowed("alice", alice.token, prompt("demo-mini"), "Alice asks demo-mini for help")
            model_denied(alice.token, prompt("demo-pro"), "model not allowed for alice", "Alice requests a premium model")
            print("SETUP | generated MCP and model decisions for a standalone run", flush=True)
        decision_reports([alice.token, bob.token])

    if want(6):
        scene(6, "Admission guardrails", "Complementary Kyverno admission blocks unsafe routes and ungoverned Envoy exceptions.")
        admission_cases()

    if want(7):
        scene(7, "Fail closed", "Gateway authentication, body limits, and fail-closed external authorization compose with runtime policy.")
        denied(Client(), "kube-tools__scale_deployment", {**own, "replicas": 2}, "", 401,
               "missing token")
        denied(Client("not-a-jwt"), "kube-tools__scale_deployment", {**own, "replicas": 2}, "", 401,
               "malformed token")
        segments = alice.token.split(".")
        segments[2] = ("A" if segments[2][0] != "A" else "B") + segments[2][1:]
        denied(Client(".".join(segments)), "kube-tools__scale_deployment",
               {**own, "replicas": 2}, "", 401, "invalid token signature")
        for payload, expected in ((b"{not-json", 503), (b"x" * 17000, 413)):
            before = len(audit())
            status, _, body = alice.raw(payload)
            if status != expected or len(audit()) != before:
                raise AssertionError(f"bad body not rejected before execution: HTTP {status}: {body}")
            print(f"PASS | DENY  | bad body rejected with HTTP {status}; no backend execution", flush=True)
        kubectl("scale", "deployment/kyverno-authz", "-n", NAMESPACE, "--replicas=0")
        try:
            wait_until("authorizer endpoints did not disappear", lambda: not authorizer_ready())
            denied(alice, "kube-tools__scale_deployment", {**own, "replicas": 2}, "",
                   (500, 503), "authorizer unavailable")
        finally:
            kubectl("scale", "deployment/kyverno-authz", "-n", NAMESPACE, "--replicas=1")
            kubectl("rollout", "status", "deployment/kyverno-authz", "-n", NAMESPACE, "--timeout=120s")
        # A positive probe confirms recovery instead of ending on an expected failure.
        wait_until("authorizer endpoints did not recover", authorizer_ready)
        wait_until("gateway did not observe authorizer recovery", lambda: alice.raw(
            b'{"jsonrpc":"2.0","id":"recovery","method":"ping"}',
        )[0] == 200)
        allowed(alice, "kube-tools__get_workload_status", own)
    if only is None:
        print("\nPASS: All demo scenarios completed against the real Agent Router gateway.", flush=True)
        print(f"Cluster retained: {CONTEXT}; team A=2 replicas; team B=2 replicas.", flush=True)
    else:
        print(f"\nPASS: Scenario {only} completed against the real Agent Router gateway.", flush=True)
        print(f"Cluster retained: {CONTEXT}; team A={replicas('team-a-dev')} replicas; "
              f"team B={replicas('team-b-dev')} replicas.", flush=True)


def smoke_check():
    alice = Client(token("alice", password()))
    alice.initialize()
    check_discovery(alice, "Alice (current live RBAC)", alice_can_scale())
    bob = Client(token("bob", password()))
    bob.initialize()
    check_discovery(bob, "Bob (team-b-dev scaler)", True)
    allowed(alice, "kube-tools__get_workload_status", {
        "namespace": "team-a-dev", "name": "checkout",
    })
    denied(alice, "kube-tools__get_workload_status", {
        "namespace": "team-b-dev", "name": "checkout",
    }, "namespace or workload boundary")
    model_allowed("alice", alice.token, prompt("demo-mini"), "Alice uses an entitled model")
    model_denied(alice.token, prompt("demo-pro"), "model not allowed for alice", "Alice requests a premium model")
    exceptions = json.loads(kubectl("get", "configmaps", "-n", NAMESPACE, "-o", "json"))["items"]
    if any(item["metadata"]["name"] == "demo-exceptions" for item in exceptions):
        raise AssertionError("break-glass exception remains installed")
    bob.headers["x-incident-id"] = "INC-1234"
    try:
        denied(bob, SCALE_TOOL, {"namespace": "team-a-dev", "name": "checkout", "replicas": 2},
               "namespace or workload boundary", label="break-glass absent even with incident header")
    finally:
        bob.headers.clear()
    decision_reports([alice.token, bob.token])
    print("PASS: discovery, tool calls, models, reports, and absence of break-glass exception verified.", flush=True)


STEPS = (
    "reset", "list", "revoke", "list-hidden", "direct-denied", "bob-list",
    "grant", "list-visible", "scale", "exception-activate", "exception-allow",
    "exception-narrow", "exception-revoke", "reports",
)


def token_expiry(access_token):
    payload = access_token.split(".")[1]
    return int(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["exp"])


def state_identity():
    def runtime(namespace, selector):
        pods = json.loads(kubectl("get", "pods", "-n", namespace, "-l", selector, "-o", "json"))["items"]
        return sorted(
            [pod["metadata"]["uid"], sorted(
                [container["name"], container.get("restartCount", 0)]
                for container in pod.get("status", {}).get("containerStatuses", [])
            )]
            for pod in pods if not pod["metadata"].get("deletionTimestamp")
        )
    return {
        "cluster": kubectl("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}"),
        "identity": kubectl("get", "secret", "demo-identity", "-n", NAMESPACE,
                            "-o", "jsonpath={.metadata.uid}"),
        "keycloak": runtime(NAMESPACE, "app=keycloak"),
        "gateway": runtime("envoy-gateway-system",
                           "gateway.envoyproxy.io/owning-gateway-name=agentrouter,"
                           "gateway.envoyproxy.io/owning-gateway-namespace=" + NAMESPACE),
    }


def save_session(state, clients):
    directory = DEMO_DIR / ".state"
    directory.mkdir(mode=0o700, exist_ok=True)
    directory.chmod(0o700)
    state["clients"] = {
        name: {key: getattr(client, key) for key in ("token", "session", "sequence", "run_id")}
        for name, client in clients.items()
    }
    state["request_ids"] = sorted(REQUEST_IDS)
    state["break_glass_id"] = BREAK_GLASS_ID
    with tempfile.NamedTemporaryFile(mode="w", dir=directory, delete=False) as stream:
        path = Path(stream.name)
        try:
            os.chmod(path, 0o600)
            json.dump(state, stream)
            stream.flush()
            os.replace(path, directory / "session.json")
        finally:
            path.unlink(missing_ok=True)


def load_session():
    path = DEMO_DIR / ".state/session.json"
    if not path.exists():
        raise RuntimeError("No presenter session; run scripts/step.sh reset first.")
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077:
        raise RuntimeError("Presenter session must be a private regular file (0600). Run reset.")
    state = json.loads(path.read_text())
    if state["identity"] != state_identity():
        path.unlink()
        raise RuntimeError("Cluster, identity, or session server changed; run scripts/step.sh reset.")
    clients = {}
    for name, saved in state["clients"].items():
        if token_expiry(saved["token"]) <= time.time() + 30:
            path.unlink()
            raise RuntimeError("Presenter token expired; run scripts/step.sh reset (no automatic refresh).")
        client = Client()
        for key in ("token", "session", "sequence", "run_id"):
            setattr(client, key, saved[key])
        clients[name] = client
    REQUEST_IDS.update(state["request_ids"])
    return state, clients


def presenter_step(step):
    global BREAK_GLASS_ID
    own = {"namespace": "team-a-dev", "name": "checkout"}
    arguments = {**own, "replicas": 2}
    if step == "reset":
        subprocess.run([str(DEMO_DIR / "scripts/reset.sh")], check=True)
        REQUEST_IDS.clear()
        BREAK_GLASS_ID = None
        clients = {name: Client(token(name, password())) for name in ("alice", "bob")}
        for client in clients.values():
            client.initialize()
        state = {"identity": state_identity()}
        print("PASS | SESSION | new Alice and Bob sessions; private finite-lived tokens saved, not printed")
    else:
        state, clients = load_session()
        original_sessions = {name: (client.token, client.session) for name, client in clients.items()}
        BREAK_GLASS_ID = state["break_glass_id"]
        alice, bob = clients["alice"], clients["bob"]
        if step in ("list", "list-visible"):
            if not alice_can_scale():
                raise AssertionError("Expected Alice RBAC grant; run grant first.")
            check_discovery(alice, "Alice, same token/session", True)
        elif step == "revoke":
            kubectl("delete", "rolebinding", "alice-scale", "-n", "team-a-dev", "--ignore-not-found")
            wait_until("Alice revocation not observed", lambda: not alice_can_scale())
            print("PASS | RBAC | revoked Alice scale; session and token unchanged")
        elif step == "list-hidden":
            if alice_can_scale():
                raise AssertionError("Expected revoked Alice RBAC; run revoke first.")
            check_discovery(alice, "Alice, same token/session", False)
        elif step == "direct-denied":
            denied(alice, SCALE_TOOL, arguments, "Kubernetes SAR denied")
        elif step == "bob-list":
            check_discovery(bob, "Bob unaffected by Alice revocation", True)
        elif step == "grant":
            kubectl("apply", "-f", str(DEMO_DIR / "manifests/alice-scale.yaml"))
            wait_until("Alice grant not observed", alice_can_scale)
            print("PASS | RBAC | restored Alice scale; session and token unchanged")
        elif step == "scale":
            allowed(alice, SCALE_TOOL, arguments)
            if replicas("team-a-dev") != 2:
                raise AssertionError("Alice scale did not update the Deployment.")
            print("PASS | EXECUTE | Alice scaled checkout to 2, correlated backend execution")
        elif step == "exception-activate":
            denied(bob, SCALE_TOOL, arguments, "namespace or workload boundary")
            decision_reports([alice.token, bob.token], {"agentrouter-bounded-operations"})
            subprocess.check_output(["kubectl", "--context", CONTEXT, "apply", "-f", "-"],
                                    input=json.dumps(incident_configmap()), text=True)
            reload_authorizer()
            state["exception_expires"] = time.time() + 15 * 60
            print("PASS | EXCEPTION | incident ConfigMap admitted; authorizer explicitly reloaded; 15m TTL")
        elif step == "exception-allow":
            if time.time() >= state.get("exception_expires", 0):
                raise AssertionError("Activate a fresh incident exception first.")
            bob.headers["x-incident-id"] = "INC-1234"
            try:
                allowed(bob, SCALE_TOOL, arguments)
                BREAK_GLASS_ID = f"{bob.run_id}-{bob.sequence}"
                if replicas("team-a-dev") != 2:
                    raise AssertionError("Exception did not execute scale.")
            finally:
                bob.headers.clear()
            print("PASS | EXCEPTION | Bob + incident scales team A; entire matching policy skipped")
        elif step == "exception-narrow":
            denied(bob, SCALE_TOOL, arguments, "namespace or workload boundary",
                   label="Bob without incident cannot use exception")
            bob.headers["x-incident-id"] = "INC-1234"
            try:
                denied(bob, SCALE_TOOL, {**arguments, "replicas": 50}, "namespace or workload boundary")
                denied(bob, "kube-tools__get_workload_status", own, "namespace or workload boundary")
            finally:
                bob.headers.clear()
        elif step == "exception-revoke":
            # Flush ext_authz reports before replacing the process-local reporter on reload.
            decision_reports([alice.token, bob.token], {"agentrouter-bounded-operations"})
            kubectl("delete", "configmap", "demo-exceptions", "-n", NAMESPACE, "--ignore-not-found")
            reload_authorizer()
            bob.headers["x-incident-id"] = "INC-1234"
            try:
                denied(bob, SCALE_TOOL, arguments, "namespace or workload boundary",
                       label="incident exception revoked")
            finally:
                bob.headers.clear()
            state.pop("exception_expires", None)
        elif step == "reports":
            decision_reports([alice.token, bob.token], {"agentrouter-bounded-operations"})
            print("NOTE | REPORT | ext_authz only; ext_proc response decisions are not reported")
        else:
            raise ValueError(step)
        if any((client.token, client.session) != original_sessions[name]
               for name, client in clients.items()):
            raise AssertionError("Presenter token/session changed unexpectedly; run reset explicitly.")
    save_session(state, clients)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="Run non-mutating authentication and policy smoke checks.")
    modes.add_argument("--step", choices=STEPS, help="One isolated presenter action, preserving token/session.")
    modes.add_argument("--scenario", type=int, choices=range(1, 8), metavar="N",
                       help="Run only scenario N (1-7) after the usual reset, e.g. --scenario 1 for a live talk.")
    args = parser.parse_args()
    with ExitStack() as stack:
        stack.enter_context(port_forward(
            "envoy-gateway-system", gateway_service(), 19080, 8080, GATEWAY,
        ))
        if not args.step:
            wait_until("gateway did not publish its OAuth challenge", lambda: http(
                GATEWAY, b'{"jsonrpc":"2.0","id":0,"method":"tools/list"}',
                {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
            )[0] == 401, timeout=90)
            print("PASS | DENY  | public MCP endpoint requires a verified OAuth token", flush=True)
        stack.enter_context(port_forward(
            NAMESPACE, "service/keycloak", 19081, 8080, KEYCLOAK + "/.well-known/openid-configuration",
        ))
        stack.enter_context(port_forward(
            NAMESPACE, "service/kube-tools", 19082, 8080, AUDIT,
        ))
        stack.enter_context(port_forward(
            NAMESPACE, "service/llm-backend", 19083, 8080, MODEL_AUDIT,
        ))
        if args.step:
            presenter_step(args.step)
        elif args.check:
            smoke_check()
        else:
            if args.scenario is None:
                print("\nResponse governance: isolated presenter actions, same Alice token/session.", flush=True)
                for step in STEPS:
                    presenter_step(step)
            run_demo(args.scenario)


if __name__ == "__main__":
    main()
