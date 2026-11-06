"""Small, stateless Streamable HTTP MCP servers for the local demo."""

import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

MAX_BODY = 16384
SERVICE_ACCOUNT = Path("/var/run/secrets/kubernetes.io/serviceaccount")
RUNBOOK = (
    "Checkout recovery: inspect status, events and logs in your own namespace. "
    "If replicas are zero, scale checkout to 2, then verify readyReplicas. "
    "Do not modify another team's namespace or request more than 3 replicas."
)


def tool(name, description, properties, required):
    return {
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        },
    }


TARGET = {
    "namespace": {"type": "string", "enum": ["team-a-dev", "team-b-dev"]},
    "name": {"type": "string", "enum": ["checkout"]},
}
KUBE_TOOLS = [
    tool("get_workload_status", "Read checkout deployment health.", TARGET, list(TARGET)),
    tool("get_events", "Read recent namespace events.", TARGET, list(TARGET)),
    tool("get_logs", "Read checkout pod logs.", TARGET, list(TARGET)),
    tool(
        "scale_deployment",
        "Set checkout replicas; authorization is enforced before execution.",
        {**TARGET, "replicas": {"type": "integer", "minimum": 1, "maximum": 100}},
        [*TARGET, "replicas"],
    ),
]
RUNBOOK_TOOLS = [tool("get_runbook", "Read the checkout recovery runbook.", {}, [])]


def validate_call(name, arguments, backend):
    tools = RUNBOOK_TOOLS if backend == "runbooks" else KUBE_TOOLS
    names = {item["name"] for item in tools}
    if not isinstance(name, str) or name not in names:
        raise ValueError("unknown tool")
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")
    if backend == "runbooks":
        if arguments:
            raise ValueError("get_runbook takes no arguments")
        return
    expected = {"namespace", "name"}
    if name == "scale_deployment":
        expected.add("replicas")
    if set(arguments) != expected:
        raise ValueError("missing or unexpected arguments")
    if arguments["namespace"] not in ("team-a-dev", "team-b-dev"):
        raise ValueError("unsupported namespace")
    if arguments["name"] != "checkout":
        raise ValueError("unsupported deployment")
    if name == "scale_deployment":
        replicas = arguments["replicas"]
        if type(replicas) is not int or not 1 <= replicas <= 3:
            raise ValueError("replicas must be an integer from 1 through 3")


def kube_request(path, method="GET", body=None):
    context = ssl.create_default_context(cafile=str(SERVICE_ACCOUNT / "ca.crt"))
    token = (SERVICE_ACCOUNT / "token").read_text().strip()
    request = Request(
        "https://kubernetes.default.svc" + path,
        method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urlopen(request, context=context, timeout=10) as response:
        content = response.read().decode()
    return content if "/log?" in path else json.loads(content)


def execute(name, arguments, backend):
    validate_call(name, arguments, backend)
    if backend == "runbooks":
        return RUNBOOK
    namespace = quote(arguments["namespace"], safe="")
    deployment = f"/apis/apps/v1/namespaces/{namespace}/deployments/checkout"
    if name == "get_workload_status":
        result = kube_request(deployment)
        return {
            "namespace": arguments["namespace"],
            "name": "checkout",
            "replicas": result["spec"]["replicas"],
            "readyReplicas": result.get("status", {}).get("readyReplicas", 0),
        }
    if name == "scale_deployment":
        scale = kube_request(deployment + "/scale")
        scale["spec"]["replicas"] = arguments["replicas"]
        result = kube_request(deployment + "/scale", "PUT", scale)
        return {"namespace": arguments["namespace"], "replicas": result["spec"]["replicas"]}
    if name == "get_events":
        events = kube_request(f"/api/v1/namespaces/{namespace}/events")
        return [
            {"reason": item.get("reason"), "message": item.get("message")}
            for item in events["items"][-10:]
        ]
    pods = kube_request(f"/api/v1/namespaces/{namespace}/pods?labelSelector=app%3Dcheckout")
    return {
        pod["metadata"]["name"]: kube_request(
            f"/api/v1/namespaces/{namespace}/pods/"
            f"{quote(pod['metadata']['name'], safe='')}/log?tailLines=10"
        )
        for pod in pods["items"]
        if pod.get("status", {}).get("phase") == "Running"
    }


class MCPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, backend):
        super().__init__(address, Handler)
        self.backend = backend
        self.audit = []
        self.audit_lock = threading.Lock()

    def record(self, record):
        with self.audit_lock:
            self.audit.append(record)
        print(json.dumps(record), flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def respond(self, status, data=None):
        content = b"" if data is None else json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self):
        if self.path == "/healthz":
            self.respond(200, {"status": "ready"})
        elif self.path == "/audit":
            with self.server.audit_lock:
                records = list(self.server.audit)
            self.respond(200, records)
        else:
            self.respond(405, {"error": "This stateless backend does not open SSE streams."})

    def do_DELETE(self):
        self.respond(200)

    def do_POST(self):
        if self.path != "/mcp":
            self.respond(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                self.close_connection = True
                self.respond(413, {"error": "body must contain 1 through 16384 bytes"})
                return
            request = json.loads(self.rfile.read(length))
            if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
                raise ValueError("expected a JSON-RPC 2.0 object")
        except (ValueError, UnicodeDecodeError) as error:
            self.respond(400, {"error": str(error)})
            return
        method = request.get("method")
        request_id = request.get("id")
        if method == "notifications/initialized":
            self.respond(202)
            return
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": f"demo-{self.server.backend}", "version": "1.0.0"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {
                "tools": RUNBOOK_TOOLS if self.server.backend == "runbooks" else KUBE_TOOLS,
            }
        elif method == "tools/call":
            params = request.get("params", {})
            if not isinstance(params, dict):
                self.respond(400, {"error": "params must be an object"})
                return
            name = params.get("name")
            arguments = params.get("arguments", {})
            demo_id = self.headers.get("x-demo-id", "")[:128]
            try:
                validate_call(name, arguments, self.server.backend)
                self.server.record({
                    "phase": "execute", "demo_id": demo_id,
                    "tool": name, "arguments": arguments,
                })
                value = execute(name, arguments, self.server.backend)
                result = {
                    "content": [{
                        "type": "text",
                        "text": value if isinstance(value, str) else json.dumps(value),
                    }],
                    "isError": False,
                }
                self.server.record({"phase": "success", "demo_id": demo_id, "tool": name})
            except (ValueError, HTTPError, URLError, TimeoutError) as error:
                self.server.record({
                    "phase": "error", "demo_id": demo_id, "tool": name, "error": str(error),
                })
                result = {
                    "content": [{"type": "text", "text": str(error)}],
                    "isError": True,
                }
        else:
            self.respond(200, {
                "jsonrpc": "2.0", "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            })
            return
        self.respond(200, {"jsonrpc": "2.0", "id": request_id, "result": result})

    def log_message(self, format_string, *args):
        if len(args) > 1 and str(args[1]).startswith(("4", "5")):
            super().log_message(format_string, *args)


if __name__ == "__main__":
    mode = os.environ.get("MCP_BACKEND", "kubernetes")
    if mode not in ("kubernetes", "runbooks"):
        raise ValueError("MCP_BACKEND must be kubernetes or runbooks")
    print(json.dumps({"phase": "ready", "backend": mode}), flush=True)
    MCPServer(("0.0.0.0", 8080), mode).serve_forever()
