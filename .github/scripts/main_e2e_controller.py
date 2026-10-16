#!/usr/bin/env python3
"""Trusted GitHub API controller for main E2E scheduling and health reporting."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from main_e2e_state import (
    StateError,
    attach_run,
    claim_commit,
    failure_issue_body,
    finish_run,
    new_state,
    retry_claim,
    status_for_pr,
    status_for_main,
    update_suite_definition,
    validate_state,
    valid_claim,
    valid_sha,
)
from suite_fingerprint import fingerprint as compute_suite_fingerprint

STATE_BRANCH = "ci-main-e2e-state"
STATE_PATH = ".github/main-e2e-state.json"
WORKFLOW = "e2e.yaml"
STATUS_CONTEXT = "main-health"
SUITES = {
    "authz-server-envoy",
    "authz-server-http",
    "sidecar-injector",
    "validation-webhook-envoy",
    "validation-webhook-http",
}
K8S_VERSIONS = {"v1.32.11", "v1.33.7", "v1.34.3", "v1.35.0"}
RUN_TITLE_RE = re.compile(
    r"^Main E2E ([0-9a-f]{40}) claim ([0-9a-f]{32}) attempt ([12]) suite ([0-9a-f]{64})$"
)
JOB_RE = re.compile(
    r"(authz-server-envoy|authz-server-http|sidecar-injector|"
    r"validation-webhook-envoy|validation-webhook-http)[, /]+"
    r"(v1\.32\.11|v1\.33\.7|v1\.34\.3|v1\.35\.0)"
)


class ControllerError(RuntimeError):
    pass


def repo() -> str:
    value = os.environ.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ControllerError("GITHUB_REPOSITORY is missing or invalid")
    return value


def suite_fingerprint() -> str:
    root = Path(__file__).resolve().parents[2]
    return compute_suite_fingerprint(root)


def main_head_sha() -> str:
    value = api(f"repos/{repo()}/commits/main")
    sha = value.get("sha") if isinstance(value, dict) else None
    if not valid_sha(sha):
        raise ControllerError("GitHub API returned an invalid main commit SHA")
    return sha


def api(path: str, method: str = "GET", body: dict[str, Any] | None = None) -> Any:
    cmd = ["gh", "api", "--method", method, path]
    stdin = None
    if body is not None:
        cmd += ["--input", "-"]
        stdin = json.dumps(body, separators=(",", ":"))
    result = subprocess.run(cmd, input=stdin, text=True, capture_output=True, check=False)
    if result.returncode:
        raise ControllerError(
            f"GitHub API {method} {path} failed with exit {result.returncode}: "
            f"{result.stderr.strip()[:800]}"
        )
    if not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ControllerError(f"GitHub API returned invalid JSON for {path}") from exc


def api_pages(path: str) -> list[Any]:
    cmd = ["gh", "api", "--paginate", "--slurp", path]
    result = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if result.returncode:
        raise ControllerError(
            f"GitHub API pagination failed for {path}: {result.stderr.strip()[:800]}"
        )
    try:
        pages = json.loads(result.stdout or "[]")
        return [item for page in pages for item in page] if pages else []
    except (json.JSONDecodeError, TypeError) as exc:
        raise ControllerError(f"GitHub API returned invalid page data for {path}") from exc


def state_contents() -> tuple[dict[str, Any], str] | None:
    try:
        value = api(f"repos/{repo()}/contents/{STATE_PATH}?ref={STATE_BRANCH}")
    except ControllerError as exc:
        if "HTTP 404" in str(exc) or "Not Found" in str(exc):
            return None
        raise
    if not isinstance(value, dict) or not isinstance(value.get("content"), str):
        raise ControllerError("state branch file has invalid contents metadata")
    try:
        raw = base64.b64decode(value["content"], validate=False).decode("utf-8")
        state = validate_state(json.loads(raw))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerError("durable state JSON is invalid; refusing to guess") from exc
    if not isinstance(value.get("sha"), str):
        raise ControllerError("state file has no blob SHA")
    return state, value["sha"]


def store_state(state: dict[str, Any], blob_sha: str | None) -> None:
    content = base64.b64encode(
        (json.dumps(state, sort_keys=True, indent=2) + "\n").encode("utf-8")
    ).decode("ascii")
    body: dict[str, Any] = {
        "message": "ci: update main e2e controller state",
        "content": content,
        "branch": STATE_BRANCH,
    }
    if blob_sha:
        body["sha"] = blob_sha
    api(f"repos/{repo()}/contents/{STATE_PATH}", method="PUT", body=body)


def mutate_state(mutation: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    for _ in range(6):
        current = state_contents()
        if current is None:
            raise ControllerError(
                "durable state is not initialized; an administrator must manually run "
                "main-e2e workflow_dispatch mode=bootstrap with an explicit base SHA"
            )
        state, blob_sha = current
        next_state = mutation(state)
        if next_state is state:
            return state
        try:
            store_state(next_state, blob_sha)
            return next_state
        except ControllerError as exc:
            text = str(exc).lower()
            if not any(token in text for token in ("409", "422", "conflict", "sha")):
                raise
    raise ControllerError("state update failed after concurrent CAS retries")


def ensure_main_history() -> list[str]:
    shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if shallow == "true":
        subprocess.run(
            ["git", "fetch", "--quiet", "--unshallow", "--no-tags", "origin", "main"],
            check=True,
            capture_output=True,
            text=True,
        )
    subprocess.run(
        ["git", "fetch", "--quiet", "--no-tags", "origin", "main"],
        check=True,
        capture_output=True,
        text=True,
    )
    result = subprocess.run(
        ["git", "rev-list", "--first-parent", "--reverse", "FETCH_HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    commits = result.stdout.splitlines()
    if not commits or any(not valid_sha(sha) for sha in commits):
        raise ControllerError("could not enumerate main first-parent history")
    return commits


def bootstrap(base_sha: str) -> None:
    if not valid_sha(base_sha):
        raise ControllerError("bootstrap requires an explicit full commit SHA")
    actor = os.environ.get("GITHUB_ACTOR", "")
    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", actor):
        raise ControllerError("cannot verify administrator for bootstrap")
    permission = api(f"repos/{repo()}/collaborators/{actor}/permission")
    if not isinstance(permission, dict) or permission.get("permission") != "admin":
        raise ControllerError("only a verified repository administrator may bootstrap state")
    commits = ensure_main_history()
    if base_sha not in commits:
        raise ControllerError("bootstrap SHA must be on main first-parent history")
    try:
        api(f"repos/{repo()}/git/ref/heads/{STATE_BRANCH}")
    except ControllerError as exc:
        if "HTTP 404" not in str(exc) and "Not Found" not in str(exc):
            raise
    else:
        raise ControllerError("state branch already exists; bootstrap is never an overwrite")
    api(
        f"repos/{repo()}/git/refs",
        method="POST",
        body={"ref": f"refs/heads/{STATE_BRANCH}", "sha": base_sha},
    )
    try:
        store_state(new_state(base_sha, suite_fingerprint()), None)
    except Exception:
        raise ControllerError(
            "created state branch but failed to create state file; repair the branch manually"
        )
    print(f"Initialized {STATE_BRANCH} at reviewed boundary {base_sha}; health is unknown.")


def find_run(claim_id: str, attempt: int) -> dict[str, Any] | None:
    runs = api(
        f"repos/{repo()}/actions/workflows/{WORKFLOW}/runs"
        "?branch=main&event=workflow_dispatch&per_page=100"
    )
    for run in runs.get("workflow_runs", []):
        try:
            _, run_claim, run_attempt, _ = parse_run_title(run)
        except ControllerError:
            continue
        if run_claim != claim_id or int(run_attempt) != attempt:
            continue
        if run.get("head_branch") != "main":
            continue
        return run
    return None


def dispatch(sha: str, claim_id: str, fingerprint_value: str, attempt: int) -> None:
    if (
        not valid_sha(sha)
        or not valid_claim(claim_id)
        or not re.fullmatch(r"[0-9a-f]{64}", fingerprint_value)
        or attempt not in (1, 2)
    ):
        raise ControllerError("refusing unsafe dispatch metadata")
    api(
        f"repos/{repo()}/actions/workflows/{WORKFLOW}/dispatches",
        method="POST",
        body={
            "ref": "main",
            "inputs": {
                "commit_sha": sha,
                "claim_id": claim_id,
                "suite_fingerprint": fingerprint_value,
                "attempt": str(attempt),
            },
        },
    )


def dispatch_claim(active: dict[str, Any]) -> dict[str, Any]:
    """Lease dispatch before the API call; recover ambiguous requests after 15 minutes."""
    run = find_run(active["claim_id"], active["attempt"])
    if run:
        return mutate_state(lambda current: attach_discovered_run(current, active, run))
    acquired = False

    def acquire(current: dict[str, Any]) -> dict[str, Any]:
        nonlocal acquired
        acquired = False
        current_active = current.get("active")
        if not same_attempt(current_active, active) or current_active.get("run_id"):
            return current
        now = datetime.now(timezone.utc)
        started = current_active.get("dispatch_started_at")
        if started and now - datetime.fromisoformat(started) < timedelta(minutes=15):
            return current
        result = dict(current)
        result["active"] = dict(current_active, dispatch_started_at=now.isoformat())
        result["generation"] += 1
        result["updated_at"] = now.isoformat()
        acquired = True
        return result

    state = mutate_state(acquire)
    if not acquired:
        print("Dispatch already leased or attached; awaiting run discovery.")
        return state
    dispatch(active["sha"], active["claim_id"], active["suite_fingerprint"], active["attempt"])
    time.sleep(3)
    run = find_run(active["claim_id"], active["attempt"])
    if run:
        return mutate_state(lambda current: attach_discovered_run(current, active, run))
    print("Dispatch accepted but not visible yet; durable lease prevents duplicate dispatch.")
    return state


def same_attempt(left: dict[str, Any] | None, right: dict[str, Any]) -> bool:
    return bool(left) and all(
        left.get(key) == right.get(key)
        for key in ("sha", "claim_id", "suite_fingerprint", "attempt")
    )


def attach_discovered_run(
    state: dict[str, Any], active: dict[str, Any], run: dict[str, Any]
) -> dict[str, Any]:
    if not same_attempt(state.get("active"), active):
        return state
    expected = (
        active["sha"], active["claim_id"], str(active["attempt"]), active["suite_fingerprint"]
    )
    if parse_run_title(run) != expected:
        raise ControllerError("discovered workflow does not match the active attempt")
    if state["active"].get("run_id") not in (None, run["id"]):
        return state
    return attach_run(state, active["claim_id"], run["id"], run.get("html_url", ""))


def start_run(sha: str, claim_id: str, fingerprint_value: str, attempt: int) -> None:
    """Bind one workflow run atomically before any tested code executes."""
    run_id_text = os.environ.get("GITHUB_RUN_ID", "")
    if os.environ.get("GITHUB_REF") != "refs/heads/main" or not run_id_text.isdecimal():
        raise ControllerError("run registration requires a main workflow run")
    run_id = int(run_id_text)
    expected = {
        "sha": sha, "claim_id": claim_id,
        "suite_fingerprint": fingerprint_value, "attempt": attempt,
    }

    def register(state: dict[str, Any]) -> dict[str, Any]:
        active = state.get("active")
        if not same_attempt(active, expected):
            raise ControllerError("workflow run no longer matches the active attempt")
        if active.get("run_id") not in (None, run_id):
            raise ControllerError("another workflow already owns this attempt; refusing duplicate matrix")
        return attach_run(
            state, claim_id, run_id,
            f"https://github.com/{repo()}/actions/runs/{run_id}",
        )

    mutate_state(register)


def list_prs() -> list[dict[str, Any]]:
    return api_pages(f"repos/{repo()}/pulls?state=open&per_page=100")


def publish_status(sha: str, state: dict[str, Any]) -> None:
    if not valid_sha(sha):
        raise ControllerError("refusing to publish status for invalid commit SHA")
    status, description = status_for_pr(state)
    body = {
        "state": status,
        "context": STATUS_CONTEXT,
        "description": description[:140],
    }
    target_url = failure_target(state)
    if target_url:
        body["target_url"] = target_url
    api(f"repos/{repo()}/statuses/{sha}", method="POST", body=body)


def publish_main_status(sha: str, state: dict[str, Any]) -> None:
    if not valid_sha(sha):
        raise ControllerError("refusing to publish status for invalid main SHA")
    status, description = status_for_main(state)
    body = {
        "state": status,
        "context": STATUS_CONTEXT,
        "description": description[:140],
    }
    target_url = failure_target(state)
    if target_url:
        body["target_url"] = target_url
    api(f"repos/{repo()}/statuses/{sha}", method="POST", body=body)


def failure_target(state: dict[str, Any]) -> str | None:
    failure = state.get("failure")
    if not failure:
        return None
    run_url = failure.get("run_url")
    if isinstance(run_url, str) and run_url.startswith(f"https://github.com/{repo()}/actions/runs/"):
        return run_url[:500]
    return None


def refresh_pr_statuses(state: dict[str, Any], only_sha: str | None = None) -> None:
    for pr in list_prs():
        head = pr.get("head") if isinstance(pr, dict) else None
        base = pr.get("base") if isinstance(pr, dict) else None
        if not isinstance(head, dict) or not isinstance(base, dict):
            continue
        sha = head.get("sha")
        if base.get("ref") != "main" or not valid_sha(sha):
            continue
        if only_sha is not None and sha != only_sha:
            continue
        publish_status(sha, state)


def prs_for_commit(sha: str) -> list[int]:
    values = api_pages(f"repos/{repo()}/commits/{sha}/pulls?per_page=100")
    return [
        value["number"]
        for value in values
        if isinstance(value, dict)
        and isinstance(value.get("number"), int)
        and value.get("base", {}).get("ref") == "main"
    ][:50]


def failed_suites_from_jobs(
    run_id: int,
    result_dir: str | None = None,
    jobs: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    if jobs is None:
        jobs = api_pages(f"repos/{repo()}/actions/runs/{run_id}/jobs?per_page=100")
    failures: set[tuple[str, str]] = set()
    for job in jobs:
        if not isinstance(job, dict) or job.get("conclusion") not in ("failure", "cancelled", "timed_out"):
            continue
        name = str(job.get("name", ""))[:300]
        match = JOB_RE.search(name)
        if match and match.group(1) in SUITES and match.group(2) in K8S_VERSIONS:
            failures.add((match.group(1), match.group(2)))
    if result_dir:
        root = Path(result_dir)
        if root.is_dir():
            attempt_results: dict[tuple[str, str], tuple[int, str]] = {}
            for path in list(root.rglob("result*.json"))[:100]:
                try:
                    if path.stat().st_size > 2048:
                        continue
                    record = json.loads(path.read_text(encoding="utf-8"))
                    suite, version = record.get("suite"), record.get("version")
                    attempt = record.get("attempt")
                    if (
                        record.get("result") in ("success", "failure")
                        and attempt in ("1", "2")
                        and suite in SUITES
                        and version in K8S_VERSIONS
                    ):
                        key = (suite, version)
                        previous = attempt_results.get(key)
                        rank = int(attempt)
                        if previous is None or rank >= previous[0]:
                            attempt_results[key] = (rank, record["result"])
                except (OSError, ValueError, TypeError):
                    continue
            failures.update(key for key, (_, value) in attempt_results.items() if value == "failure")
    return [{"suite": suite, "version": version} for suite, version in sorted(failures)][:20]


def terminal_record_matches(
    record: Any,
    artifact_name: str,
    trusted_sha: str,
    identity: tuple[str, str, str, str],
) -> bool:
    sha, claim_id, attempt, suite_hash = identity
    return (
        isinstance(record, dict)
        and artifact_name == f"e2e-terminal-{attempt}-{claim_id}"
        and valid_sha(trusted_sha)
        and record.get("commit_sha") == sha
        and record.get("claim_id") == claim_id
        and record.get("attempt") == attempt
        and record.get("suite_fingerprint") == suite_hash
        and record.get("trusted_sha") == trusted_sha
        and record.get("result") == "success"
        and record.get("full_matrix_success") is True
    )


def terminal_attempt_verified(
    jobs: list[dict[str, Any]],
    terminal_dir: str | None,
    run: dict[str, Any],
    identity: tuple[str, str, str, str],
) -> bool:
    conclusions = {
        str(job.get("name", "")): job.get("conclusion")
        for job in jobs
        if isinstance(job, dict)
    }
    if conclusions.get("E2E terminal outcome") != "success":
        return False
    if not terminal_dir:
        return False
    root = Path(terminal_dir)
    _, claim_id, attempt, _ = identity
    expected_name = f"e2e-terminal-{attempt}-{claim_id}"
    for marker in list(root.glob(f"{expected_name}/terminal.json"))[:2]:
        try:
            if marker.stat().st_size > 2048:
                continue
            record = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if terminal_record_matches(
            record, marker.parent.name, str(run.get("head_sha", "")), identity
        ):
            return True
    return False


def download_terminal_artifact(run_id: int, claim_id: str, attempt: int) -> str | None:
    artifact_name = f"e2e-terminal-{attempt}-{claim_id}"
    root = Path("terminal-results") / str(run_id)
    destination = root / artifact_name
    destination.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            ["gh", "run", "download", str(run_id), "--name", artifact_name, "--dir", str(destination)],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"warning: terminal artifact download failed: {exc}", file=sys.stderr)
        return None
    if result.returncode:
        print("warning: terminal artifact download was unsuccessful", file=sys.stderr)
        return None
    return str(root)


def get_run(run_id: int) -> dict[str, Any]:
    run = api(f"repos/{repo()}/actions/runs/{run_id}")
    if not isinstance(run, dict):
        raise ControllerError("workflow run metadata is invalid")
    return run


def parse_run_title(run: dict[str, Any]) -> tuple[str, str, str, str]:
    title = run.get("display_title") or run.get("name") or ""
    match = RUN_TITLE_RE.fullmatch(title)
    if not match:
        raise ControllerError("workflow run title is not a trusted claim identity")
    return match.group(1), match.group(2), match.group(3), match.group(4)


def report_completed_run(
    run_id: int,
    result_dir: str | None = None,
    terminal_dir: str | None = None,
) -> dict[str, Any]:
    run = get_run(run_id)
    if (
        run.get("path") != f".github/workflows/{WORKFLOW}"
        or run.get("event") != "workflow_dispatch"
        or run.get("head_branch") != "main"
        or run.get("status") != "completed"
    ):
        raise ControllerError("workflow run identity/status did not pass trusted checks")
    sha, claim_id, attempt_text, suite_hash = parse_run_title(run)
    attempt = int(attempt_text)
    conclusion = run.get("conclusion")
    if conclusion not in ("success", "failure", "cancelled", "timed_out", "action_required"):
        conclusion = "failure"
    terminal_dir_from_event = terminal_dir is not None
    if conclusion == "success" and terminal_dir is None:
        terminal_dir = download_terminal_artifact(run_id, claim_id, attempt)
    jobs = api_pages(f"repos/{repo()}/actions/runs/{run_id}/jobs?per_page=100")
    failures = failed_suites_from_jobs(run_id, result_dir, jobs)
    identity = (sha, claim_id, attempt_text, suite_hash)
    terminal_verified = terminal_attempt_verified(jobs, terminal_dir, run, identity)
    if conclusion == "success" and not terminal_verified and terminal_dir_from_event:
        fallback_terminal_dir = download_terminal_artifact(run_id, claim_id, attempt)
        terminal_verified = terminal_attempt_verified(
            jobs, fallback_terminal_dir, run, identity
        )
    if conclusion == "success" and not terminal_verified:
        print(
            "warning: workflow conclusion was success but trusted full-matrix terminal "
            "metadata was unavailable or invalid; treating this attempt as a failure",
            file=sys.stderr,
        )
        conclusion = "failure"
    pr_lookup_pending = False
    prs: list[int] = []
    if attempt == 2 and conclusion != "success":
        try:
            prs = prs_for_commit(sha)
        except ControllerError:
            pr_lookup_pending = True
            print(
                "warning: PR associations could not be fetched; recording the failure and "
                "retrying association lookup during reconciliation",
                file=sys.stderr,
            )

    current_fingerprint = suite_fingerprint()

    def apply(state: dict[str, Any]) -> dict[str, Any]:
        if state["suite_fingerprint"] != current_fingerprint:
            state = update_suite_definition(state, current_fingerprint)
        active = state.get("active")
        if (
            not active
            or active.get("claim_id") != claim_id
            or active.get("sha") != sha
            or active.get("suite_fingerprint") != suite_hash
            or active.get("attempt") != attempt
        ):
            return state
        if active.get("run_id") not in (None, run_id):
            return state
        with_run = (
            attach_run(state, claim_id, run_id, run["html_url"])
            if active.get("run_id") is None
            else state
        )
        if attempt == 1 and conclusion != "success":
            return retry_claim(
                with_run,
                claim_id=claim_id,
                run_id=run_id,
            )
        return finish_run(
            with_run,
            claim_id=claim_id,
            run_id=run_id,
            conclusion=conclusion,
            failures=failures,
            run_url=run.get("html_url", ""),
            pr_numbers=prs,
            pr_lookup_pending=pr_lookup_pending,
            attempt=attempt,
        )

    new_value = mutate_state(apply)
    active = new_value.get("active")
    if active and active.get("claim_id") == claim_id and active.get("attempt") == 2 and not active.get("run_id"):
        new_value = dispatch_claim(active)
    synchronize_health(new_value)
    return new_value


def find_main_health_issue() -> dict[str, Any] | None:
    issues = api_pages(f"repos/{repo()}/issues?state=open&per_page=100")
    matches = [
        item for item in issues
        if isinstance(item, dict)
        and "pull_request" not in item
        and item.get("title") == "[main-health] Main E2E unhealthy"
    ]
    return min(matches, key=lambda item: item.get("number", 0)) if matches else None


def upsert_failure_issue(state: dict[str, Any]) -> None:
    if state["health"] != "unhealthy":
        return
    existing = find_main_health_issue()
    history = ensure_main_history()
    backlog = max(0, len(history) - history.index(state["cursor_sha"]) - 1) if state["cursor_sha"] in history else 0
    body = failure_issue_body(state, backlog)
    if existing:
        api(
            f"repos/{repo()}/issues/{existing['number']}",
            method="PATCH",
            body={"body": body, "state": "open"},
        )
    else:
        api(
            f"repos/{repo()}/issues",
            method="POST",
            body={"title": "[main-health] Main E2E unhealthy", "body": body},
        )


def close_resolved_issue(state: dict[str, Any]) -> None:
    if state["health"] != "healthy":
        return
    existing = find_main_health_issue()
    if existing:
        api(
            f"repos/{repo()}/issues/{existing['number']}",
            method="PATCH",
            body={"state": "closed"},
        )


def synchronize_health(state: dict[str, Any]) -> None:
    state = update_suite_definition(state, suite_fingerprint())
    failure = state.get("failure")
    if state["health"] == "unhealthy" and failure and failure.get("pr_lookup_pending"):
        try:
            associated_prs = prs_for_commit(failure["sha"])
        except ControllerError:
            print(
                "warning: PR association lookup still unavailable; failure report explicitly "
                "records pending provenance",
                file=sys.stderr,
            )
        else:
            failure_sha = failure["sha"]
            failure_run_id = failure["run_id"]

            def attach_prs(current: dict[str, Any]) -> dict[str, Any]:
                current_failure = current.get("failure")
                if (
                    current["health"] != "unhealthy"
                    or not current_failure
                    or current_failure["sha"] != failure_sha
                    or current_failure["run_id"] != failure_run_id
                    or not current_failure["pr_lookup_pending"]
                ):
                    return current
                result = dict(current)
                result["failure"] = dict(
                    current_failure,
                    pr_numbers=associated_prs[:50],
                    pr_lookup_pending=False,
                )
                result["generation"] += 1
                result["updated_at"] = datetime.now(timezone.utc).replace(
                    microsecond=0
                ).isoformat()
                validate_state(result)
                return result

            state = mutate_state(attach_prs)
    observed = dict(state, observed_main_sha=main_head_sha())
    publish_main_status(observed["observed_main_sha"], observed)
    refresh_pr_statuses(observed)
    if state["health"] == "unhealthy":
        upsert_failure_issue(state)
    elif state["health"] == "healthy":
        close_resolved_issue(state)


def scheduler(mode: str, base_sha: str | None) -> None:
    if mode == "bootstrap":
        if not base_sha:
            raise ControllerError("bootstrap requires an explicit base SHA")
        bootstrap(base_sha)
        return
    history = ensure_main_history()
    state_value = state_contents()
    if state_value is None:
        raise ControllerError(
            "main E2E state is not initialized; run the documented administrator bootstrap"
        )
    state, _ = state_value
    state = mutate_state(
        lambda current: update_suite_definition(current, suite_fingerprint())
    )
    if state["active"]:
        active = state["active"]
        run = (
            get_run(active["run_id"])
            if active.get("run_id")
            else find_run(active["claim_id"], active["attempt"])
        )
        if run:
            if run.get("status") == "completed":
                print(f"Run {run['id']} completed; main-health reconciler will report it.")
            else:
                if active.get("run_id") != run.get("id"):
                    state = mutate_state(
                        lambda current: attach_discovered_run(current, active, run)
                    )
        else:
            dispatch_claim(active)
        return

    commits = history
    claim_id = secrets.token_hex(16)
    claimed = mutate_state(lambda current: claim_commit(current, commits, claim_id))
    active = claimed.get("active")
    if active and active["claim_id"] == claim_id:
        claimed = dispatch_claim(active)
    active = claimed.get("active")
    if active and active.get("claim_id") == claim_id:
        remaining = len(history) - history.index(active["sha"]) - 1
        print(
            f"Dispatched {active['sha']}; {remaining} newer first-parent commit(s) remain "
            "queued oldest-first for later scheduled runs."
        )
    elif claimed["cursor_sha"] == history[-1]:
        print("No new main first-parent commit; no E2E run dispatched.")


def reconcile_health() -> None:
    try:
        state_value = state_contents()
    except ControllerError as exc:
        refresh_statuses()
        raise ControllerError(
            "durable state could not be read; main and open PR heads were marked pending"
        ) from exc
    if state_value is None:
        refresh_statuses()
        raise ControllerError(
            "durable state not initialized; main and existing PR heads were marked pending"
        )
    state, _ = state_value
    state = mutate_state(
        lambda current: update_suite_definition(current, suite_fingerprint())
    )
    if state.get("active"):
        active = state["active"]
        run = (
            get_run(active["run_id"])
            if active.get("run_id")
            else find_run(active["claim_id"], active["attempt"])
        )
        if run and not active.get("run_id"):
            state = mutate_state(
                lambda current: attach_discovered_run(current, active, run)
            )
        if run and run.get("status") == "completed":
            report_completed_run(run["id"])
            return
        if not run:
            state = dispatch_claim(active)
    synchronize_health(state)


def refresh_statuses() -> None:
    head = main_head_sha()
    state_error: ControllerError | None = None
    try:
        state_value = state_contents()
    except ControllerError as exc:
        state_value = None
        state_error = exc
    if state_value is None:
        state = None
        status, description = "pending", "Main E2E baseline not established"
        target = None
    else:
        state, _ = state_value
        state = update_suite_definition(state, suite_fingerprint())
        observed = dict(state, observed_main_sha=head)
        status, description = status_for_main(observed)
        target = failure_target(observed)
    body = {
        "state": status,
        "context": STATUS_CONTEXT,
        "description": description[:140],
    }
    if target:
        body["target_url"] = target
    if state is None:
        api(f"repos/{repo()}/statuses/{head}", method="POST", body=body)
        for pr in list_prs():
            if (
                isinstance(pr, dict)
                and pr.get("base", {}).get("ref") == "main"
                and valid_sha(pr.get("head", {}).get("sha"))
            ):
                pending = {
                    "state": "pending",
                    "context": STATUS_CONTEXT,
                    "description": "Main E2E baseline not established",
                }
                api(
                    f"repos/{repo()}/statuses/{pr['head']['sha']}",
                    method="POST",
                    body=pending,
                )
        if state_error:
            raise ControllerError(
                "durable state could not be read; main and open PR heads were marked pending"
            ) from state_error
    else:
        publish_main_status(head, observed)
        observed = dict(state, observed_main_sha=head)
        refresh_pr_statuses(observed)


def pull_request_status(event_path: str) -> None:
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
        pr = event["pull_request"]
        number = pr["number"]
        event_sha = pr["head"]["sha"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ControllerError("pull request event metadata is malformed") from exc
    if not isinstance(number, int) or number <= 0 or not valid_sha(event_sha):
        raise ControllerError("pull request event has unsafe metadata")
    current = api(f"repos/{repo()}/pulls/{number}")
    if (
        current.get("state") != "open"
        or current.get("base", {}).get("ref") != "main"
        or current.get("head", {}).get("sha") != event_sha
    ):
        raise ControllerError("pull request metadata changed or is not eligible")
    try:
        state_value = state_contents()
    except ControllerError as exc:
        state_value = None
        print(
            "warning: durable health state could not be read; publishing a pending PR status",
            file=sys.stderr,
        )
    if state_value is None:
        status = "pending"
        description = "Main E2E baseline not established"
        target = None
    else:
        state, _ = state_value
        state = update_suite_definition(state, suite_fingerprint())
        state = dict(state, observed_main_sha=main_head_sha())
        status, description = status_for_pr(state)
        target = failure_target(state)
    body = {
        "state": status,
        "context": STATUS_CONTEXT,
        "description": description[:140],
    }
    if target:
        body["target_url"] = target
    api(f"repos/{repo()}/statuses/{event_sha}", method="POST", body=body)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    schedule = sub.add_parser("schedule")
    schedule.add_argument("--mode", choices=("reconcile", "bootstrap"), default="reconcile")
    schedule.add_argument("--base-sha")
    report = sub.add_parser("report")
    report.add_argument("--run-id", required=True, type=int)
    report.add_argument("--results-dir")
    report.add_argument("--terminal-dir")
    pr = sub.add_parser("pull-request-status")
    pr.add_argument("--event", required=True)
    start = sub.add_parser("start-run")
    start.add_argument("--commit-sha", required=True)
    start.add_argument("--claim-id", required=True)
    start.add_argument("--suite-fingerprint", required=True)
    start.add_argument("--attempt", type=int, choices=(1, 2), required=True)
    sub.add_parser("reconcile-health")
    sub.add_parser("refresh-statuses")
    args = parser.parse_args()
    try:
        if args.command == "schedule":
            scheduler(args.mode, args.base_sha)
        elif args.command == "report":
            report_completed_run(args.run_id, args.results_dir, args.terminal_dir)
        elif args.command == "pull-request-status":
            pull_request_status(args.event)
        elif args.command == "reconcile-health":
            reconcile_health()
        elif args.command == "refresh-statuses":
            refresh_statuses()
        elif args.command == "start-run":
            start_run(args.commit_sha, args.claim_id, args.suite_fingerprint, args.attempt)
    except (ControllerError, StateError, subprocess.CalledProcessError) as exc:
        print(f"main E2E controller error: {str(exc)[:1200]}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
