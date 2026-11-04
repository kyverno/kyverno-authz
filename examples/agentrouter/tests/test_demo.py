import importlib.util
import json
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

DEMO_DIR = Path(__file__).resolve().parent.parent
for directory in ("client", "apps/identity", "apps/mcp-server"):
    sys.path.insert(0, str(DEMO_DIR / directory))

import demo  # noqa: E402
import realm  # noqa: E402
import server  # noqa: E402

# Both backends are named server.py, so load the model backend under its own name.
_spec = importlib.util.spec_from_file_location("llm_backend", DEMO_DIR / "apps/llm-backend/server.py")
llm_backend = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(llm_backend)


class ToolTests(unittest.TestCase):
    def test_scale_validation(self):
        target = {"namespace": "team-a-dev", "name": "checkout"}
        for replicas in (1, 2, 3):
            server.validate_call("scale_deployment", {**target, "replicas": replicas}, "kubernetes")
        for replicas in (0, -1, 4, 1.5, "2", True, None):
            with self.subTest(replicas=replicas), self.assertRaises(ValueError):
                server.validate_call("scale_deployment", {**target, "replicas": replicas}, "kubernetes")

    def test_no_generic_or_unscoped_execution(self):
        for name, arguments in (
            ("shell", {}),
            ({}, {}),
            ("get_workload_status", {"namespace": "kube-system", "name": "checkout"}),
            ("get_workload_status", {"namespace": "team-a-dev", "name": "other"}),
            ("get_workload_status", {"namespace": "team-a-dev", "name": "checkout", "extra": True}),
            ("scale_deployment", {"namespace": "team-a-dev", "name": "checkout"}),
            ("get_workload_status", []),
        ):
            with self.subTest(name=name, arguments=arguments), self.assertRaises(ValueError):
                server.validate_call(name, arguments, "kubernetes")

    def test_scale_uses_named_subresource_and_resource_version(self):
        scale = {"metadata": {"resourceVersion": "123"}, "spec": {"replicas": 0}}
        with patch.object(server, "kube_request", side_effect=[scale, scale]) as request:
            result = server.execute(
                "scale_deployment",
                {"namespace": "team-a-dev", "name": "checkout", "replicas": 2},
                "kubernetes",
            )
        path = "/apis/apps/v1/namespaces/team-a-dev/deployments/checkout/scale"
        self.assertEqual(request.call_args_list[0].args, (path,))
        self.assertEqual(request.call_args_list[1].args, (path, "PUT", scale))
        self.assertEqual(scale["metadata"]["resourceVersion"], "123")
        self.assertEqual(result["replicas"], 2)

    def test_runbook_never_calls_kubernetes(self):
        with patch.object(server, "kube_request") as request:
            self.assertIn("checkout", server.execute("get_runbook", {}, "runbooks"))
        request.assert_not_called()

    def test_identity_password_is_generated(self):
        first = realm.identity_secret()
        second = realm.identity_secret()
        self.assertNotEqual(first["stringData"]["password"], second["stringData"]["password"])
        users = json.loads(first["stringData"]["realm.json"])["users"]
        self.assertEqual({user["username"] for user in users}, {"alice", "bob"})
        self.assertTrue(all(
            user["credentials"][0]["value"] == first["stringData"]["password"] for user in users
        ))

    def test_tools_list_and_discovery(self):
        client = Mock()
        client.request.return_value = {"tools": [{"name": name} for name in demo.EXPECTED_TOOLS]}
        self.assertEqual(demo.tools_list(client), demo.EXPECTED_TOOLS)
        client.request.assert_called_once_with("tools/list")
        demo.check_discovery(client, "Bob", True)
        with self.assertRaises(AssertionError):
            demo.check_discovery(client, "Alice before grant", False)
        client.request.return_value["tools"] = [
            tool for tool in client.request.return_value["tools"] if tool["name"] != demo.SCALE_TOOL
        ]
        demo.check_discovery(client, "Alice before grant", False)
        with self.assertRaises(AssertionError):
            demo.check_discovery(client, "Alice after grant", True)

    def test_json_and_sse_client_responses(self):
        response = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        self.assertEqual(demo.decode_rpc(json.dumps(response)), response)
        self.assertEqual(demo.decode_rpc("event: message\ndata: " + json.dumps(response) + "\n\n"), response)
        with self.assertRaises(AssertionError):
            demo.decode_rpc("event: ping\n\n")


class ReportingTests(unittest.TestCase):
    def test_report_redaction_and_correlation(self):
        report = {"metadata": {"name": "sample"}, "summary": {"pass": 1, "fail": 1}, "results": [
            {"policy": "agentrouter-bounded-operations", "result": "pass", "message": '{"x-demo-id":"this-run"}'},
            {"policy": "agentrouter-model-governance", "result": "fail", "properties": {"demo": "this-run"}},
        ]}
        with patch.object(demo, "REQUEST_IDS", {"this-run"}), patch.object(demo, "kubectl", return_value=json.dumps({"items": [report]})):
            demo.decision_reports(["secret-jwt"])
            report["results"][0]["message"] += " Bearer secret-jwt"
            with patch.object(demo, "kubectl", return_value=json.dumps({"items": [report]})):
                with self.assertRaisesRegex(AssertionError, "credential leaked"):
                    demo.decision_reports(["secret-jwt"])

    def test_request_adds_incident_header_and_tracks_correlation(self):
        client = demo.Client("jwt")
        client.headers["x-incident-id"] = "INC-1234"
        with patch.object(demo, "http", return_value=(200, {}, "{}")) as request:
            client.raw(b"{}", "correlated")
        self.assertEqual(request.call_args.args[2]["x-incident-id"], "INC-1234")
        self.assertIn("correlated", demo.REQUEST_IDS)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.server = server.MCPServer(("127.0.0.1", 0), "runbooks")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/mcp"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def rpc(self, method, params=None):
        body = {"jsonrpc": "2.0", "id": 1, "method": method}
        if params is not None:
            body["params"] = params
        request = Request(self.url, json.dumps(body).encode(), {"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            return response.status, json.load(response)

    def test_initialize_discover_and_call(self):
        status, response = self.rpc("initialize")
        self.assertEqual(status, 200)
        self.assertEqual(response["result"]["protocolVersion"], "2025-06-18")
        _, response = self.rpc("tools/list")
        self.assertEqual(response["result"]["tools"][0]["name"], "get_runbook")
        _, response = self.rpc("tools/call", {"name": "get_runbook", "arguments": {}})
        self.assertFalse(response["result"]["isError"])
        self.assertEqual([event["phase"] for event in self.server.audit], ["execute", "success"])

    def test_reject_malformed_and_batched_requests(self):
        for body in (b"{", b"[]", b'{"jsonrpc":"1.0"}'):
            with self.subTest(body=body), self.assertRaises(HTTPError) as error:
                urlopen(Request(self.url, body), timeout=5)
            self.assertEqual(error.exception.code, 400)

    def test_oversized_body(self):
        with self.assertRaises(HTTPError) as error:
            urlopen(Request(self.url, b"x" * 17000), timeout=5)
        self.assertEqual(error.exception.code, 413)
        self.assertEqual(self.server.audit, [])


class ModelBackendTests(unittest.TestCase):
    def setUp(self):
        self.server = llm_backend.LLMServer(("127.0.0.1", 0))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/v1/chat/completions"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def test_completion_records_verified_tenant(self):
        request = Request(self.url, json.dumps(demo.prompt("demo-mini")).encode(), {
            "Content-Type": "application/json", "x-demo-id": "abc", "x-tenant-id": "alice",
        })
        with urlopen(request, timeout=5) as response:
            body = json.load(response)
        self.assertEqual(body["model"], "demo-mini")
        self.assertEqual(body["usage"]["total_tokens"], 30)
        self.assertEqual(self.server.audit, [{"demo_id": "abc", "tenant": "alice", "model": "demo-mini"}])

    def test_rejects_invalid_requests(self):
        for body in (b"{", b"[]", b'{"model":"demo-mini"}',
                     json.dumps(demo.prompt("demo-mini", stream=True)).encode(), b"x" * 17000):
            with self.subTest(body=body[:20]), self.assertRaises(HTTPError) as error:
                urlopen(Request(self.url, body), timeout=5)
            self.assertIn(error.exception.code, (400, 413))
        self.assertEqual(self.server.audit, [])


class AdmissionCaseTests(unittest.TestCase):
    def test_every_case_declares_its_expected_denial(self):
        cases = sorted((DEMO_DIR / "policies/admission/cases").glob("*.yaml"))
        self.assertEqual(len(cases), 16)
        for path in cases:
            with self.subTest(case=path.name):
                self.assertIn("demo.kyverno.io/expected-denial:", path.read_text())


if __name__ == "__main__":
    unittest.main()
