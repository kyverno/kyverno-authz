"""Exercise current Kyverno Authz through the real Agent Router gateway."""

import argparse
import base64
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import uuid

DEMO_DIR = Path(__file__).resolve().parent.parent
CONTEXT = os.environ.get("CONTEXT", "kind-" + os.environ.get("CLUSTER_NAME", "kyverno-agentrouter"))
NAMESPACE = "agentrouter-demo"
GATEWAY = "http://127.0.0.1:18080/mcp"
KEYCLOAK = "http://127.0.0.1:18081/realms/demo"
AUDIT = "http://127.0.0.1:18082/audit"
MODELS = "http://127.0.0.1:18080/v1/chat/completions"
MODEL_AUDIT = "http://127.0.0.1:18083/audit"
OWN = {"namespace": "team-a-dev", "name": "checkout"}
OTHER = {"namespace": "team-b-dev", "name": "checkout"}
SCALE_TOOL = "kube-tools__scale_deployment"
EXPECTED_TOOLS = {
    "kube-tools__get_workload_status", "kube-tools__get_events",
    "kube-tools__get_logs", SCALE_TOOL, "runbooks__get_runbook",
}


def kubectl(*args):
    return subprocess.check_output(["kubectl", "--context", CONTEXT, *args], text=True).strip()


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
    state_dir.mkdir(mode=0o700, exist_ok=True)
    log_path = state_dir / f"port-forward-{local_port}.log"
    with log_path.open("w+") as log:
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
                if f"Forwarding from 127.0.0.1:{local_port}" in log.read():
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
            log_path.unlink(missing_ok=True)


def gateway_service():
    services = json.loads(kubectl(
        "get", "services", "-n", "envoy-gateway-system",
        "-l", "gateway.envoyproxy.io/owning-gateway-name=agentrouter,"
        "gateway.envoyproxy.io/owning-gateway-namespace=agentrouter-demo", "-o", "json",
    ))["items"]
    if len(services) != 1:
        raise RuntimeError(f"expected one gateway Service, found {len(services)}")
    return "service/" + services[0]["metadata"]["name"]


def decode_rpc(body):
    if body.lstrip().startswith("{"):
        return json.loads(body)
    for line in body.splitlines():
        if line.startswith("data:"):
            value = json.loads(line[5:].strip())
            if "result" in value or "error" in value:
                return value
    raise AssertionError("no JSON-RPC response")


class Client:
    def __init__(self, token=None):
        self.token = token
        self.session = None
        self.sequence = 0
        self.run_id = uuid.uuid4().hex[:10]

    def raw(self, payload, demo_id=None):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-06-18",
            "x-demo-id": demo_id or f"{self.run_id}-{self.sequence}",
        }
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
            raise AssertionError(f"{method}: HTTP {status}")
        response = decode_rpc(body)
        if "error" in response:
            raise AssertionError(f"{method}: JSON-RPC error")
        for key, value in headers.items():
            if key.lower() == "mcp-session-id":
                self.session = value
        return response["result"]

    def initialize(self):
        self.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "kyverno-agentrouter-demo", "version": "1.0"},
        })
        status, _, _ = self.raw(json.dumps({
            "jsonrpc": "2.0", "method": "notifications/initialized",
        }).encode())
        if status not in (200, 202, 204) or not self.session:
            raise AssertionError("MCP initialization did not establish a session")


def tools_list(client):
    return {tool["name"] for tool in client.request("tools/list")["tools"]}


def check_discovery(client, label):
    if tools_list(client) != EXPECTED_TOOLS:
        raise AssertionError(f"{label}: unexpected tool catalog")
    print(f"PASS | TOOLS | {label}: all five tools visible; execution is authorized separately", flush=True)


def token(username, demo_password):
    status, _, body = http(
        KEYCLOAK + "/protocol/openid-connect/token",
        urlencode({"grant_type": "password", "client_id": "demo-cli",
                   "username": username, "password": demo_password, "scope": "openid profile"}).encode(),
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    if status != 200:
        raise AssertionError(f"Keycloak token request failed: HTTP {status}")
    return json.loads(body)["access_token"]


def password():
    return base64.b64decode(kubectl(
        "get", "secret", "demo-identity", "-n", NAMESPACE, "-o", "jsonpath={.data.password}",
    )).decode()


def replicas(namespace):
    return int(kubectl("get", "deployment", "checkout", "-n", namespace, "-o", "jsonpath={.spec.replicas}"))


def audit(url=AUDIT):
    status, _, body = http(url)
    if status != 200:
        raise AssertionError(f"backend audit failed: HTTP {status}")
    return json.loads(body)


def allowed(client, tool, arguments):
    result = client.request("tools/call", {"name": tool, "arguments": arguments})
    if result.get("isError"):
        raise AssertionError(f"{tool}: backend error")
    if tool.startswith("kube-tools__") and not any(
        record["phase"] == "success" and record["demo_id"] == f"{client.run_id}-{client.sequence}"
        for record in audit()
    ):
        raise AssertionError("allowed call has no successful backend execution")
    return result["content"][0]["text"]


def denied(client, tool, arguments, reason, expected_status=403, label=None):
    identifier = "deny-" + uuid.uuid4().hex[:10]
    before = {namespace: replicas(namespace) for namespace in ("team-a-dev", "team-b-dev")}
    status, _, body = client.raw(json.dumps({
        "jsonrpc": "2.0", "id": identifier, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }).encode(), identifier)
    statuses = expected_status if isinstance(expected_status, tuple) else (expected_status,)
    if status not in statuses or reason not in body:
        raise AssertionError(f"expected HTTP {expected_status} / {reason!r}, got HTTP {status}")
    if any(record["demo_id"] == identifier for record in audit()):
        raise AssertionError("denied request reached the Kubernetes backend")
    if any(replicas(namespace) != count for namespace, count in before.items()):
        raise AssertionError("denied request changed deployment state")
    print(f"PASS | DENY | {label or reason}: HTTP {status}; no backend execution or state change", flush=True)


def wait_until(description, predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise TimeoutError(description)
        time.sleep(0.5)


def alice_can_scale():
    result = subprocess.run(
        ["kubectl", "--context", CONTEXT, "auth", "can-i", "update", "deployments/checkout",
         "--subresource=scale", "-n", "team-a-dev", "--as=alice"], text=True, capture_output=True,
    )
    if result.returncode not in (0, 1) or result.stdout.strip() not in ("yes", "no"):
        raise RuntimeError("cannot query Alice's permissions")
    return result.stdout.strip() == "yes"


def authorizer_ready():
    slices = json.loads(kubectl(
        "get", "endpointslices", "-n", NAMESPACE,
        "-l", "kubernetes.io/service-name=kyverno-authz", "-o", "json",
    ))["items"]
    return any(endpoint.get("conditions", {}).get("ready", False)
               for item in slices for endpoint in item.get("endpoints", []))


def prompt(model, text="checkout has zero replicas; what should I do?", **fields):
    return {"model": model, "messages": [{"role": "user", "content": text}], "max_tokens": 128, **fields}


def model_request(access_token, request, reason=None):
    identifier = "model-" + uuid.uuid4().hex[:10]
    # Agent Router's model-routing processor derives x-ai-eg-model from the
    # OpenAI JSON model field before HTTPRoute matching; test that native path.
    headers = {"Content-Type": "application/json", "x-demo-id": identifier, "x-tenant-id": "spoofed"}
    if access_token:
        headers["Authorization"] = "Bearer " + access_token
    status, _, body = http(MODELS, json.dumps(request).encode(), headers)
    records = [record for record in audit(MODEL_AUDIT) if record["demo_id"] == identifier]
    if reason is not None:
        if status != 403 or reason not in body or records:
            raise AssertionError(f"model denial failed: HTTP {status}")
        print(f"PASS | DENY | {reason}: HTTP 403; model backend never called", flush=True)
    else:
        if status != 200 or len(records) != 1 or records[0]["tenant"] != "alice":
            raise AssertionError(f"model allow/verified tenant failed: HTTP {status}")
        print("PASS | ALLOW | demo-mini executed; verified tenant overwrites spoofed header", flush=True)


def admission_cases():
    for path in sorted((DEMO_DIR / "policies/admission/cases").glob("*.yaml")):
        expected = json.loads(kubectl("create", "--dry-run=client", "-f", str(path), "-o", "json"))[
            "metadata"]["annotations"]["demo.kyverno.io/expected-denial"]
        result = subprocess.run(
            ["kubectl", "--context", CONTEXT, "apply", "--dry-run=server", "-f", str(path)],
            text=True, capture_output=True,
        )
        if result.returncode == 0 or "denied the request" not in result.stderr or expected not in result.stderr:
            raise AssertionError(f"{path.name}: expected admission denial {expected!r}: {result.stderr}")
        print(f"PASS | ADMISSION | {path.stem}: {expected}", flush=True)
    for manifest in ("gateway.yaml", "models.yaml"):
        kubectl("apply", "--dry-run=server", "-f", str(DEMO_DIR / "manifests" / manifest))
    print("PASS | ADMISSION | demo routes satisfy the guardrails", flush=True)


def decision_reports(tokens):
    def summaries():
        reports = json.loads(kubectl("get", "reports.openreports.io", "-n", NAMESPACE, "-o", "json"))["items"]
        encoded = json.dumps(reports)
        if "Bearer " in encoded or any(secret and secret in encoded for secret in tokens):
            raise AssertionError("credential leaked into an OpenReport")
        return reports

    wait_until("pass/fail summaries were not reported", lambda: (
        sum(report.get("summary", {}).get("pass", 0) for report in summaries()) > 0 and
        sum(report.get("summary", {}).get("fail", 0) for report in summaries()) > 0
    ), timeout=45)
    for report in summaries():
        summary = report.get("summary", {})
        print(f"REPORT | {report['metadata']['name']} | pass={summary.get('pass', 0)}; "
              f"fail={summary.get('fail', 0)}", flush=True)
    print("PASS | REPORT | accumulated summaries only; no policy attribution or per-request correlation", flush=True)


def fail_closed(client):
    kubectl("scale", "deployment/kyverno-authz", "-n", NAMESPACE, "--replicas=0")
    try:
        wait_until("authorizer endpoints did not disappear", lambda: not authorizer_ready())
        denied(client, SCALE_TOOL, {**OWN, "replicas": 2}, "", (500, 503), "authorizer unavailable")
    finally:
        kubectl("scale", "deployment/kyverno-authz", "-n", NAMESPACE, "--replicas=1")
        kubectl("rollout", "status", "deployment/kyverno-authz", "-n", NAMESPACE, "--timeout=120s")
    wait_until("authorizer did not recover", authorizer_ready)
    wait_until("gateway did not observe recovery", lambda: client.raw(
        b'{"jsonrpc":"2.0","id":"recovery","method":"ping"}')[0] == 200)
    allowed(client, "kube-tools__get_workload_status", OWN)
    print("PASS | authorizer restored and real backend read succeeds", flush=True)


def request_guardrails(client):
    denied(client, "kube-tools__get_workload_status", OTHER, "namespace or workload boundary")
    for value in (50, 0, -1, 1.5, "2", True):
        denied(client, SCALE_TOOL, {**OWN, "replicas": value}, "replicas must be an integer from 1 through 3")
    denied(client, SCALE_TOOL, OWN, "replicas must be an integer from 1 through 3")
    denied(client, "kube-tools__shell", OWN, "tool not allowed")
    denied(client, SCALE_TOOL, {**OWN, "replicas": 2, "command": "ignored"}, "unexpected tool arguments")


def run_demo(only=None):
    subprocess.run([str(DEMO_DIR / "scripts/reset.sh")], check=True)
    client = Client(token("alice", password()))
    client.initialize()
    if replicas("team-a-dev") != 0:
        raise AssertionError("incident was not seeded")
    if only is None or only == 1:
        try:
            allowed(client, "kube-tools__get_workload_status", OWN)
            kubectl("delete", "rolebinding", "alice-scale", "-n", "team-a-dev")
            wait_until("RBAC revocation not observed", lambda: not alice_can_scale())
            denied(client, SCALE_TOOL, {**OWN, "replicas": 2}, "Kubernetes SAR denied")
            check_discovery(client, "Alice after revoke (same JWT/session)")
            allowed(client, "kube-tools__get_workload_status", OWN)
            print("PASS | revoking scale preserves Alice's read access", flush=True)
        finally:
            kubectl("apply", "-f", str(DEMO_DIR / "manifests/alice-scale.yaml"))
        wait_until("RBAC restoration not observed", alice_can_scale)
        allowed(client, SCALE_TOOL, {**OWN, "replicas": 2})
        kubectl("rollout", "status", "deployment/checkout", "-n", "team-a-dev", "--timeout=120s")
        status = json.loads(allowed(client, "kube-tools__get_workload_status", OWN))
        if status["replicas"] != 2 or status["readyReplicas"] != 2:
            raise AssertionError("checkout did not recover")
        print("PASS | same JWT/session recovers checkout to two ready replicas", flush=True)
    if only is None or only == 2:
        request_guardrails(client)
    if only is None or only == 3:
        model_request(client.token, prompt("demo-mini"))
        model_request(client.token, prompt("demo-pro"), "model not allowed for alice")
        model_request(client.token, prompt("demo-mini", max_tokens=4000), "max_tokens exceeds the limit for alice")
        model_request(client.token, prompt("demo-mini", n=5), "only one completion per request")
        model_request(client.token, prompt("demo-mini", tools=[]), "tool calling not allowed for alice")
        model_request(client.token, prompt("demo-mini", "key AKIA" + "ABCDEFGHIJKLMNOP"), "prompt contains a credential")
    if only is None or only == 4:
        if only == 4:
            denied(client, SCALE_TOOL, {**OWN, "replicas": 50}, "replicas must be an integer from 1 through 3")
        decision_reports([client.token])
    if only is None or only == 5:
        admission_cases()
    if only is None or only == 6:
        denied(Client(), SCALE_TOOL, {**OWN, "replicas": 2}, "", 401, "missing JWT")
        denied(Client("not-a-jwt"), SCALE_TOOL, {**OWN, "replicas": 2}, "", 401, "malformed JWT")
        for payload, expected in ((b"{not-json", 503), (b"x" * 17000, 413)):
            before = len(audit())
            status, _, _ = client.raw(payload)
            if status != expected or len(audit()) != before:
                raise AssertionError(f"malformed/oversized body not rejected: HTTP {status}")
            print(f"PASS | bad body rejected: HTTP {status}", flush=True)
        fail_closed(client)
    print("\nPASS: requested demo scenarios completed against the real gateway.", flush=True)


def smoke_check():
    client = Client(token("alice", password()))
    client.initialize()
    check_discovery(client, "Alice (catalog is not permission-filtered)")
    allowed(client, "kube-tools__get_workload_status", OWN)
    denied(client, "kube-tools__get_workload_status", OTHER, "namespace or workload boundary")
    model_request(client.token, prompt("demo-mini"))
    model_request(client.token, prompt("demo-pro"), "model not allowed for alice")
    print("PASS: non-mutating checks completed (no reset, RBAC changes, or scale calls).", flush=True)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="Non-mutating checks; no incident reset.")
    modes.add_argument("--token", choices=("alice", "bob"), help="Print a demo token without logging it.")
    modes.add_argument("--scenario", type=int, choices=range(1, 7), metavar="N",
                       help="Run scenario 1-6 after resetting the incident.")
    return parser.parse_args(argv)


def main():
    os.umask(0o077)
    args = parse_args()
    with ExitStack() as stack:
        if args.token:
            stack.enter_context(port_forward(NAMESPACE, "service/keycloak", 18081, 8080,
                                             KEYCLOAK + "/.well-known/openid-configuration"))
            print(token(args.token, password()))
            return
        for namespace, resource, local, remote, probe in (
            ("envoy-gateway-system", gateway_service(), 18080, 8080, GATEWAY),
            (NAMESPACE, "service/keycloak", 18081, 8080, KEYCLOAK + "/.well-known/openid-configuration"),
            (NAMESPACE, "service/kube-tools", 18082, 8080, AUDIT),
            (NAMESPACE, "service/llm-backend", 18083, 8080, MODEL_AUDIT),
        ):
            stack.enter_context(port_forward(namespace, resource, local, remote, probe))
        if args.check:
            smoke_check()
        else:
            run_demo(args.scenario)


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, RuntimeError, TimeoutError) as error:
        raise SystemExit(str(error)) from error
