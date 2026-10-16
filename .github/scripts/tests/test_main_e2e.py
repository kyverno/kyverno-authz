import json
import os
import sys
import unittest
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("GITHUB_REPOSITORY", "example/project")

import main_e2e_controller as controller
import aggregate_e2e_results as aggregate
from main_e2e_state import (
    StateError,
    attach_run,
    claim_commit,
    failure_issue_body,
    finish_run,
    new_state,
    status_for_pr,
    status_for_main,
    retry_claim,
    update_suite_definition,
    validate_state,
)


BASE = "1" * 40
FIRST = "2" * 40
MERGE = "3" * 40
NEXT = "4" * 40
RUN_URL = "https://github.com/example/project/actions/runs/12345"
RETRY_RUN_URL = "https://github.com/example/project/actions/runs/23456"
CLAIM = "a" * 32
SUITE_FINGERPRINT = "f" * 64


def initialized():
    return new_state(BASE, SUITE_FINGERPRINT, "2026-01-01T00:00:00+00:00")


def claimed(state, sha=FIRST, claim=CLAIM):
    state = claim_commit(state, [BASE, sha], claim, "2026-01-01T00:01:00+00:00")
    return attach_run(state, claim, 12345, RUN_URL, "2026-01-01T00:02:00+00:00")


def retried(state):
    state = retry_claim(state, claim_id=CLAIM, run_id=12345)
    return attach_run(state, CLAIM, 23456, RETRY_RUN_URL)


class MainE2EStateTests(unittest.TestCase):
    def test_missing_state_or_active_fields_raise_state_error(self):
        state = initialized()
        for key in state:
            with self.subTest(field=key):
                malformed = dict(state)
                del malformed[key]
                with self.assertRaises(StateError):
                    validate_state(malformed)
        state = claimed(state)
        for key in state["active"]:
            with self.subTest(active_field=key):
                malformed = dict(state, active=dict(state["active"]))
                del malformed["active"][key]
                with self.assertRaises(StateError):
                    validate_state(malformed)

    def test_no_commits_does_not_change_cursor_or_health(self):
        state = initialized()
        self.assertIs(claim_commit(state, [BASE], CLAIM), state)
        self.assertEqual(status_for_pr(state)[0], "pending")

    def test_multiple_first_parent_commits_are_claimed_oldest_first(self):
        state = initialized()
        history = [BASE, FIRST, MERGE, NEXT]
        state = claim_commit(state, history, CLAIM, "t1")
        self.assertEqual(state["active"]["sha"], FIRST)
        state = finish_run(
            attach_run(state, CLAIM, 11, RUN_URL),
            claim_id=CLAIM,
            run_id=11,
            conclusion="success",
            failures=[],
            run_url=RUN_URL,
            at="t2",
        )
        state = claim_commit(state, history, "b" * 32, "t3")
        self.assertEqual(state["active"]["sha"], MERGE)

    def test_duplicate_claim_does_not_replace_existing_active_commit(self):
        state = claimed(initialized())
        duplicate = claim_commit(state, [BASE, FIRST, NEXT], "b" * 32)
        self.assertIs(duplicate, state)
        self.assertEqual(duplicate["active"]["claim_id"], CLAIM)

    def test_failure_then_newer_full_pass_recovers_health(self):
        state = claimed(initialized())
        # Attempt one failure schedules a retry; only a retry completion is terminal.
        state = retry_claim(state, claim_id=CLAIM, run_id=12345, at="t3-retry")
        self.assertEqual(state["cursor_sha"], BASE)
        state = finish_run(
            state,
            claim_id=CLAIM,
            run_id=23456,
            conclusion="failure",
            failures=[{"suite": "sidecar-injector", "version": "v1.34.3"}],
            run_url=RETRY_RUN_URL,
            pr_numbers=[27],
            attempt=2,
            at="t3-terminal",
        )
        self.assertEqual(state["health"], "unhealthy")
        self.assertEqual(state["cursor_sha"], FIRST)
        self.assertEqual(status_for_pr(state)[0], "failure")

        next_claim = "b" * 32
        state = claim_commit(state, [BASE, FIRST, NEXT], next_claim, "t4")
        self.assertEqual(state["active"]["sha"], NEXT)
        state = finish_run(
            attach_run(state, next_claim, 23456, RUN_URL),
            claim_id=next_claim,
            run_id=23456,
            conclusion="success",
            failures=[],
            run_url=RUN_URL,
            at="t5",
        )
        self.assertEqual(state["health"], "healthy")
        self.assertEqual(state["last_pass_sha"], NEXT)
        self.assertIsNone(state["failure"])

    def test_canceled_attempt_retries_then_terminal_cancellation_advances_cursor(self):
        state = claimed(initialized())
        state = retry_claim(state, claim_id=CLAIM, run_id=12345)
        self.assertEqual(state["active"]["attempt"], 2)
        self.assertEqual(state["cursor_sha"], BASE)
        state = attach_run(state, CLAIM, 23456, RETRY_RUN_URL)
        state = finish_run(
            state,
            claim_id=CLAIM,
            run_id=23456,
            conclusion="cancelled",
            failures=[],
            run_url=RETRY_RUN_URL,
            attempt=2,
        )
        self.assertEqual(state["cursor_sha"], FIRST)
        self.assertEqual(state["health"], "unhealthy")
        self.assertEqual(state["failure"]["conclusion"], "cancelled")

    def test_timeout_attempt_one_is_retryable_and_not_terminal(self):
        state = claimed(initialized())
        state = retry_claim(state, claim_id=CLAIM, run_id=12345)
        self.assertEqual(state["active"]["attempt"], 2)
        self.assertEqual(state["health"], "unknown")
        self.assertEqual(state["cursor_sha"], BASE)

    def test_full_retry_success_is_healthy_after_first_attempt_failure(self):
        state = claimed(initialized())
        state = retry_claim(state, claim_id=CLAIM, run_id=12345)
        state = attach_run(state, CLAIM, 23456, RETRY_RUN_URL)
        state = finish_run(
            state,
            claim_id=CLAIM,
            run_id=23456,
            conclusion="success",
            failures=[],
            run_url=RETRY_RUN_URL,
            attempt=2,
        )
        self.assertEqual(state["health"], "healthy")
        self.assertEqual(state["cursor_sha"], FIRST)
        self.assertEqual(state["last_pass_sha"], FIRST)

    def test_stale_completion_and_duplicate_completion_are_noops(self):
        state = claimed(initialized())
        stale = finish_run(
            state,
            claim_id=CLAIM,
            run_id=777,
            conclusion="success",
            failures=[],
            run_url=RUN_URL,
        )
        self.assertIs(stale, state)
        completed = finish_run(
            state,
            claim_id=CLAIM,
            run_id=12345,
            conclusion="success",
            failures=[],
            run_url=RUN_URL,
        )
        stale_again = finish_run(
            completed,
            claim_id=CLAIM,
            run_id=12345,
            conclusion="failure",
            failures=[],
            run_url=RUN_URL,
        )
        self.assertIs(stale_again, completed)
        self.assertEqual(completed["health"], "healthy")

    def test_unknown_or_unsafe_state_metadata_is_rejected(self):
        with self.assertRaises(StateError):
            validate_state({"version": 99})
        state = claimed(initialized())
        with self.assertRaises(StateError):
            finish_run(
                retried(state),
                claim_id=CLAIM,
                run_id=23456,
                conclusion="failure",
                failures=[{"suite": "![injected](x)", "version": "v1.34.3"}],
                run_url=RETRY_RUN_URL,
                attempt=2,
            )
        bad = claimed(initialized())
        bad["active"]["run_id"] = "not-an-id"
        with self.assertRaises(StateError):
            validate_state(bad)

    def test_suite_definition_change_invalidates_green_baseline_and_active_claim(self):
        active_state = claimed(initialized())
        invalidated = update_suite_definition(active_state, "e" * 64, "t-invalidated")
        self.assertIsNone(invalidated["active"])
        self.assertEqual(invalidated["cursor_sha"], BASE)

        state = claimed(initialized())
        state = finish_run(
            state,
            claim_id=CLAIM,
            run_id=12345,
            conclusion="success",
            failures=[],
            run_url=RUN_URL,
        )
        changed = update_suite_definition(state, "e" * 64, "t-suite")
        self.assertEqual(changed["health"], "unknown")
        self.assertIsNone(changed["last_pass_sha"])
        self.assertEqual(status_for_pr(changed)[0], "pending")
        self.assertEqual(update_suite_definition(changed, "e" * 64), changed)

    def test_current_main_backlog_preserves_pr_health_but_main_baseline_is_pending(self):
        state = finish_run(
            claimed(initialized()),
            claim_id=CLAIM,
            run_id=12345,
            conclusion="success",
            failures=[],
            run_url=RUN_URL,
        )
        self.assertEqual(state["health"], "healthy")
        observed = dict(state, observed_main_sha=NEXT)
        self.assertEqual(status_for_pr(observed)[0], "success")
        self.assertEqual(status_for_main(observed)[0], "pending")
        failed = retried(claimed(initialized()))
        failed = finish_run(
            failed,
            claim_id=CLAIM,
            run_id=23456,
            conclusion="failure",
            failures=[],
            run_url=RETRY_RUN_URL,
            attempt=2,
        )
        self.assertEqual(status_for_pr(dict(failed, observed_main_sha=NEXT))[0], "failure")

    def test_failure_issue_body_has_reproduction_and_revert_guidance(self):
        state = retried(claimed(initialized()))
        state = finish_run(
            state,
            claim_id=CLAIM,
            run_id=23456,
            conclusion="failure",
            failures=[{"suite": "authz-server-http", "version": "v1.32.11"}],
            run_url=RETRY_RUN_URL,
            pr_numbers=[9],
            attempt=2,
        )
        body = failure_issue_body(state, backlog=2)
        self.assertIn(FIRST, body)
        self.assertIn("v1.32.11", body)
        self.assertIn("#9", body)
        self.assertIn("git revert", body)
        self.assertIn("root cause is not inferred", body)
        self.assertIn("remaining:** 2", body)


class ControllerTests(unittest.TestCase):
    def test_watchdog_download_preserves_terminal_artifact_directory(self):
        identity = (FIRST, CLAIM, "2", SUITE_FINGERPRINT)
        marker = {
            "commit_sha": FIRST,
            "claim_id": CLAIM,
            "attempt": "2",
            "suite_fingerprint": SUITE_FINGERPRINT,
            "trusted_sha": MERGE,
            "result": "success",
            "full_matrix_success": True,
        }
        def download(command, **kwargs):
            destination = Path(command[command.index("--dir") + 1])
            (destination / "terminal.json").write_text(json.dumps(marker))
            return mock.Mock(returncode=0)

        with tempfile.TemporaryDirectory() as directory:
            previous = Path.cwd()
            try:
                os.chdir(directory)
                with mock.patch.object(controller.subprocess, "run", side_effect=download):
                    root = controller.download_terminal_artifact(23456, CLAIM, 2)
                self.assertTrue(controller.terminal_attempt_verified(
                    [{"name": "E2E terminal outcome", "conclusion": "success"}],
                    root, {"head_sha": MERGE}, identity,
                ))
            finally:
                os.chdir(previous)

    def test_retry_aggregator_retries_full_matrix_for_any_failure_or_missing_result(self):
        from aggregate_e2e_results import SUITES, VERSIONS

        records = []
        for suite in sorted(SUITES):
            for version in sorted(VERSIONS):
                record = {"suite": suite, "version": version, "result": "success"}
                if suite == "sidecar-injector" and version == "v1.32.11":
                    record["result"] = "failure"
                item = mock.Mock()
                item.stat.return_value.st_size = 100
                item.read_text.return_value = json.dumps(record)
                records.append(item)
        with mock.patch.object(Path, "rglob", return_value=records):
            failed, candidates = aggregate.collect(Path("ignored"))
        self.assertTrue(failed)
        self.assertIn(("sidecar-injector", "v1.32.11"), candidates)

        with mock.patch.object(Path, "rglob", return_value=records[1:]):
            failed, _ = aggregate.collect(Path("ignored"))
        self.assertTrue(failed)

    def test_state_api_failure_is_reported_not_treated_as_uninitialized(self):
        with mock.patch.object(controller, "state_contents", side_effect=controller.ControllerError("API unavailable")):
            with self.assertRaisesRegex(controller.ControllerError, "API unavailable"):
                controller.mutate_state(lambda state: state)

    def test_first_attempt_failure_persists_retry_claim_before_dispatch(self):
        state = claimed(initialized())
        run = {
            "id": 12345,
            "path": ".github/workflows/e2e.yaml",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "status": "completed",
            "conclusion": "failure",
            "html_url": RUN_URL,
            "display_title": f"Main E2E {FIRST} claim {CLAIM} attempt 1 suite {SUITE_FINGERPRINT}",
        }
        stored = []
        with (
            mock.patch.object(controller, "get_run", return_value=run),
            mock.patch.object(controller, "failed_suites_from_jobs", return_value=[]),
            mock.patch.object(controller, "api_pages", return_value=[]),
            mock.patch.object(controller, "prs_for_commit") as prs,
            mock.patch.object(controller, "suite_fingerprint", return_value=SUITE_FINGERPRINT),
            mock.patch.object(controller, "state_contents", return_value=(state, "blob")),
            mock.patch.object(controller, "store_state", side_effect=lambda value, _: stored.append(value)),
            mock.patch.object(
                controller, "dispatch_claim",
                side_effect=lambda active: dict(state, active=active),
            ) as dispatch,
            mock.patch.object(controller, "synchronize_health"),
        ):
            controller.report_completed_run(12345)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["active"]["attempt"], 2)
        self.assertIsNone(stored[0]["active"]["run_id"])
        dispatch.assert_called_once_with(stored[0]["active"])
        prs.assert_not_called()

    def test_dispatch_lease_prevents_overlap_and_delayed_discovery_duplicates(self):
        state = claim_commit(initialized(), [BASE, FIRST], CLAIM)
        current = [state]
        def save(value, blob):
            current[0] = value
        with (
            mock.patch.object(controller, "state_contents", side_effect=lambda: (current[0], "blob")),
            mock.patch.object(controller, "store_state", side_effect=save),
            mock.patch.object(controller, "find_run", return_value=None),
            mock.patch.object(controller, "dispatch") as dispatch,
            mock.patch.object(controller.time, "sleep"),
        ):
            controller.dispatch_claim(state["active"])
            controller.dispatch_claim(state["active"])
        dispatch.assert_called_once_with(FIRST, CLAIM, SUITE_FINGERPRINT, 1)
        self.assertIsNotNone(current[0]["active"]["dispatch_started_at"])

    def test_dispatch_cas_loser_does_not_send_a_duplicate(self):
        state = claim_commit(initialized(), [BASE, FIRST], CLAIM)
        competing = dict(state, active=dict(
            state["active"], dispatch_started_at=datetime.now(timezone.utc).isoformat(),
        ))
        with (
            mock.patch.object(
                controller, "state_contents",
                side_effect=[(state, "blob"), (competing, "new-blob")],
            ),
            mock.patch.object(controller, "store_state", side_effect=controller.ControllerError("409 conflict")),
            mock.patch.object(controller, "find_run", return_value=None),
            mock.patch.object(controller, "dispatch") as dispatch,
        ):
            controller.dispatch_claim(state["active"])
        dispatch.assert_not_called()

    def test_ambiguous_dispatch_failure_is_leased_then_recovers(self):
        state = claim_commit(initialized(), [BASE, FIRST], CLAIM)
        current = [state]
        def save(value, blob):
            current[0] = value
        with (
            mock.patch.object(controller, "state_contents", side_effect=lambda: (current[0], "blob")),
            mock.patch.object(controller, "store_state", side_effect=save),
            mock.patch.object(controller, "find_run", return_value=None),
            mock.patch.object(
                controller, "dispatch",
                side_effect=[controller.ControllerError("API timeout"), None],
            ) as dispatch,
            mock.patch.object(controller.time, "sleep"),
        ):
            with self.assertRaisesRegex(controller.ControllerError, "API timeout"):
                controller.dispatch_claim(state["active"])
            controller.dispatch_claim(state["active"])
            self.assertEqual(dispatch.call_count, 1)
            current[0]["active"]["dispatch_started_at"] = (
                datetime.now(timezone.utc) - timedelta(minutes=16)
            ).isoformat()
            controller.dispatch_claim(state["active"])
        self.assertEqual(dispatch.call_count, 2)

    def test_duplicate_run_cannot_claim_a_matrix_after_lease_recovery(self):
        state = claim_commit(initialized(), [BASE, FIRST], CLAIM)
        current = [state]
        def save(value, blob):
            current[0] = value
        with (
            mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "12345", "GITHUB_REF": "refs/heads/main"}),
            mock.patch.object(controller, "state_contents", side_effect=lambda: (current[0], "blob")),
            mock.patch.object(controller, "store_state", side_effect=save),
        ):
            controller.start_run(FIRST, CLAIM, SUITE_FINGERPRINT, 1)
            os.environ["GITHUB_RUN_ID"] = "23456"
            with self.assertRaisesRegex(controller.ControllerError, "another workflow already owns"):
                controller.start_run(FIRST, CLAIM, SUITE_FINGERPRINT, 1)
        self.assertEqual(current[0]["active"]["run_id"], 12345)

    def test_discovery_does_not_overwrite_retry_or_existing_run_owner(self):
        first = claimed(initialized())
        retry = retried(first)
        run = {
            "id": 98765, "html_url": RUN_URL,
            "display_title": f"Main E2E {FIRST} claim {CLAIM} attempt 1 suite {SUITE_FINGERPRINT}",
        }
        self.assertIs(controller.attach_discovered_run(retry, first["active"], run), retry)
        self.assertIs(controller.attach_discovered_run(first, first["active"], run), first)

    def test_malformed_state_is_reported_as_controller_error(self):
        malformed = initialized()
        del malformed["active"]
        import base64
        contents = base64.b64encode(json.dumps(malformed).encode()).decode()
        with mock.patch.object(controller, "api", return_value={"sha": "blob", "content": contents}):
            with self.assertRaisesRegex(controller.ControllerError, "durable state JSON is invalid"):
                controller.state_contents()

    def test_pr_association_api_failure_is_recorded_and_retried(self):
        state = retried(claimed(initialized()))
        run = {
            "id": 23456,
            "path": ".github/workflows/e2e.yaml",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "status": "completed",
            "conclusion": "failure",
            "html_url": RETRY_RUN_URL,
            "display_title": f"Main E2E {FIRST} claim {CLAIM} attempt 2 suite {SUITE_FINGERPRINT}",
        }
        stored = []
        with (
            mock.patch.object(controller, "get_run", return_value=run),
            mock.patch.object(controller, "failed_suites_from_jobs", return_value=[]),
            mock.patch.object(controller, "api_pages", return_value=[]),
            mock.patch.object(
                controller,
                "prs_for_commit",
                side_effect=controller.ControllerError("API unavailable"),
            ),
            mock.patch.object(controller, "suite_fingerprint", return_value=SUITE_FINGERPRINT),
            mock.patch.object(controller, "state_contents", return_value=(state, "blob")),
            mock.patch.object(controller, "store_state", side_effect=lambda value, _: stored.append(value)),
            mock.patch.object(controller, "synchronize_health"),
        ):
            result = controller.report_completed_run(23456)
        self.assertEqual(result["health"], "unhealthy")
        self.assertTrue(stored[0]["failure"]["pr_lookup_pending"])
        self.assertIn(
            "will be retried",
            failure_issue_body(stored[0]),
        )

    def test_success_requires_trusted_full_matrix_marker_and_terminal_job(self):
        identity = (FIRST, CLAIM, "2", SUITE_FINGERPRINT)
        marker = {
            "commit_sha": FIRST,
            "claim_id": CLAIM,
            "attempt": "2",
            "suite_fingerprint": SUITE_FINGERPRINT,
            "trusted_sha": "3" * 40,
            "result": "success",
            "full_matrix_success": True,
        }
        self.assertTrue(
            controller.terminal_record_matches(
                marker,
                f"e2e-terminal-2-{CLAIM}",
                "3" * 40,
                identity,
            )
        )
        self.assertFalse(
            controller.terminal_record_matches(
                dict(marker, full_matrix_success=False),
                f"e2e-terminal-2-{CLAIM}",
                "3" * 40,
                identity,
            )
        )
        self.assertFalse(
            controller.terminal_record_matches(
                marker,
                f"e2e-terminal-2-{CLAIM}",
                FIRST,
                identity,
            )
        )

    def test_compare_and_swap_conflict_reloads_and_retries(self):
        state = initialized()
        updated = dict(state, generation=1)
        with (
            mock.patch.object(controller, "state_contents", side_effect=[(state, "blob-a"), (state, "blob-b")]),
            mock.patch.object(
                controller,
                "store_state",
                side_effect=[controller.ControllerError("HTTP 409 conflict"), None],
            ) as store,
        ):
            result = controller.mutate_state(lambda current: updated)
        self.assertEqual(result["generation"], 1)
        self.assertEqual(store.call_count, 2)

    def test_issue_upsert_deduplicates_and_refreshes_existing_failure(self):
        state = retried(claimed(initialized()))
        state = finish_run(
            state,
            claim_id=CLAIM,
            run_id=23456,
            conclusion="failure",
            failures=[],
            run_url=RETRY_RUN_URL,
            attempt=2,
        )
        issue = {"number": 77}
        with (
            mock.patch.object(controller, "ensure_main_history", return_value=[BASE, FIRST]),
            mock.patch.object(controller, "find_main_health_issue", side_effect=[None, issue]),
            mock.patch.object(controller, "api") as api,
        ):
            controller.upsert_failure_issue(state)
            controller.upsert_failure_issue(state)
        self.assertEqual(api.call_count, 2)
        self.assertEqual(api.call_args_list[0].args[:2], (f"repos/{controller.repo()}/issues",))
        self.assertEqual(api.call_args_list[0].kwargs["method"], "POST")
        self.assertEqual(api.call_args_list[1].kwargs["method"], "PATCH")

    def test_status_refresh_updates_every_open_main_pr_head(self):
        state = initialized()
        prs = [
            {"head": {"sha": FIRST}, "base": {"ref": "main"}},
            {"head": {"sha": NEXT}, "base": {"ref": "main"}},
            {"head": {"sha": MERGE}, "base": {"ref": "release"}},
        ]
        with (
            mock.patch.object(controller, "list_prs", return_value=prs),
            mock.patch.object(controller, "publish_status") as publish,
        ):
            controller.refresh_pr_statuses(state)
        self.assertEqual([call.args[0] for call in publish.call_args_list], [FIRST, NEXT])
        self.assertTrue(all(call.args[1] is state for call in publish.call_args_list))

    def test_run_identity_rejects_unsafe_or_untrusted_metadata(self):
        self.assertEqual(
            controller.parse_run_title(
                {
                    "display_title": f"Main E2E {FIRST} claim {CLAIM} attempt 1 suite {SUITE_FINGERPRINT}"
                }
            ),
            (FIRST, CLAIM, "1", SUITE_FINGERPRINT),
        )
        with self.assertRaises(controller.ControllerError):
            controller.parse_run_title(
                {"display_title": f"Main E2E {FIRST} claim ;echo attempt 1 suite {SUITE_FINGERPRINT}"}
            )
        with self.assertRaises(controller.ControllerError):
            controller.parse_run_title(
                {
                    "display_title": "Main E2E "
                    + FIRST
                    + " claim "
                    + CLAIM
                    + " attempt 1"
                    + " suite "
                    + ("A" * 64)
                }
            )

    def test_pr_status_rejects_unsafe_head_before_api_write(self):
        event = {"pull_request": {"number": 3, "head": {"sha": "not-a-sha"}}}
        with (
            mock.patch.object(Path, "read_text", return_value=json.dumps(event)),
            mock.patch.object(controller, "api") as api,
        ):
            with self.assertRaisesRegex(controller.ControllerError, "unsafe metadata"):
                controller.pull_request_status("ignored")
        api.assert_not_called()

    def test_failed_suite_artifact_metadata_is_allowlisted_and_attempt_aware(self):
        records = [
            {"suite": "sidecar-injector", "version": "v1.34.3", "attempt": "1", "result": "failure"},
            {"suite": "sidecar-injector", "version": "v1.34.3", "attempt": "2", "result": "success"},
            {"suite": "validation-webhook-http", "version": "v1.32.11", "attempt": "2", "result": "failure"},
            {"suite": "![unsafe]", "version": "v1.32.11", "attempt": "2", "result": "failure"},
        ]
        with (
            mock.patch.object(controller, "api_pages", return_value=[]),
            mock.patch.object(Path, "is_dir", return_value=True),
            mock.patch.object(Path, "rglob", return_value=[Path(f"result-{i}.json") for i in range(4)]),
            mock.patch.object(Path, "stat", return_value=mock.Mock(st_size=100)),
            mock.patch.object(Path, "read_text", side_effect=[json.dumps(item) for item in records]),
        ):
            failures = controller.failed_suites_from_jobs(12345, "unused")
        self.assertEqual(
            failures,
            [{"suite": "validation-webhook-http", "version": "v1.32.11"}],
        )


if __name__ == "__main__":
    unittest.main()
