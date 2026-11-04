"""A deterministic OpenAI-compatible chat backend so the demo needs no API key."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time

MAX_BODY_BYTES = 16384
AUDIT_LIMIT = 500


def completion(request):
    if not isinstance(request, dict) or not isinstance(request.get("model"), str):
        raise ValueError("model is required")
    if not isinstance(request.get("messages"), list) or not request["messages"]:
        raise ValueError("messages are required")
    if request.get("stream"):
        raise ValueError("streaming is not supported by the demo backend")
    model = request["model"]
    return {
        "id": "chatcmpl-kyverno-demo",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": f"[{model}] checkout has 0 replicas; scale it to 2 and watch readiness.",
            },
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 16, "completion_tokens": 14, "total_tokens": 30},
    }


class LLMServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address):
        super().__init__(address, Handler)
        self.audit = []
        self.lock = threading.Lock()

    def record(self, entry):
        with self.lock:
            self.audit.append(entry)
            del self.audit[:-AUDIT_LIMIT]


class Handler(BaseHTTPRequestHandler):
    server_version = "kyverno-demo-llm/1.0"

    def respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self.respond(200, {"status": "ok"})
        elif self.path == "/audit":
            with self.server.lock:
                self.respond(200, list(self.server.audit))
        else:
            self.respond(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?")[0] != "/v1/chat/completions":
            self.respond(404, {"error": {"message": "not found"}})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY_BYTES:
            self.respond(413, {"error": {"message": "request body too large"}})
            return
        try:
            request = json.loads(self.rfile.read(length))
            response = completion(request)
        except (ValueError, json.JSONDecodeError) as error:
            self.respond(400, {"error": {"message": str(error)}})
            return
        # The tenant header is set by Kyverno; any client-supplied value is overwritten.
        self.server.record({
            "demo_id": self.headers.get("x-demo-id", ""),
            "tenant": self.headers.get("x-tenant-id", ""),
            "model": request["model"],
        })
        self.respond(200, response)

    def log_message(self, format_string, *args):
        pass


if __name__ == "__main__":
    LLMServer(("0.0.0.0", 8080)).serve_forever()
