#!/usr/bin/env python3
"""Pure state transitions for the scheduled main E2E / health controller."""

from __future__ import annotations

import re
from html import escape
from datetime import datetime, timezone
from typing import Any

STATE_VERSION = 2
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CLAIM_RE = re.compile(r"^[0-9a-f]{32}$")
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


class StateError(ValueError):
    pass


def valid_sha(value: Any) -> bool:
    return isinstance(value, str) and bool(SHA_RE.fullmatch(value))


def valid_claim(value: Any) -> bool:
    return isinstance(value, str) and bool(CLAIM_RE.fullmatch(value))


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_state(
    base_sha: str, suite_fingerprint: str, at: str | None = None
) -> dict[str, Any]:
    if not valid_sha(base_sha):
        raise StateError("bootstrap base must be a full 40-character commit SHA")
    if not isinstance(suite_fingerprint, str) or not FINGERPRINT_RE.fullmatch(suite_fingerprint):
        raise StateError("suite definition fingerprint is invalid")
    return {
        "version": STATE_VERSION,
        "suite_fingerprint": suite_fingerprint,
        "bootstrap_sha": base_sha,
        "cursor_sha": base_sha,
        "health": "unknown",
        "failure": None,
        "last_pass_sha": None,
        "active": None,
        "generation": 0,
        "updated_at": at or now_iso(),
    }


def validate_state(state: Any) -> dict[str, Any]:
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        raise StateError("missing or unsupported durable state")
    required = {
        "suite_fingerprint", "bootstrap_sha", "cursor_sha", "health", "failure",
        "last_pass_sha", "active", "generation", "updated_at",
    }
    if not required.issubset(state):
        raise StateError("durable state is missing required fields")
    if not isinstance(state["updated_at"], str):
        raise StateError("invalid state update time")
    if state["last_pass_sha"] is not None and not valid_sha(state["last_pass_sha"]):
        raise StateError("invalid last passing commit")
    if not isinstance(state.get("suite_fingerprint"), str) or not FINGERPRINT_RE.fullmatch(
        state["suite_fingerprint"]
    ):
        raise StateError("invalid suite definition fingerprint")
    for field in ("bootstrap_sha", "cursor_sha"):
        if not valid_sha(state.get(field)):
            raise StateError(f"invalid {field}")
    if state["health"] not in ("unknown", "healthy", "unhealthy"):
        raise StateError("invalid health value")
    if state["health"] == "healthy" and not valid_sha(state.get("last_pass_sha")):
        raise StateError("healthy state has no passing commit")
    active = state.get("active")
    if active is not None:
        active_required = {
            "sha", "claim_id", "suite_fingerprint", "attempt",
            "created_at", "run_id", "run_url",
        }
        if not isinstance(active, dict) or not active_required.issubset(active):
            raise StateError("active claim is missing required fields")
        if not isinstance(active, dict) or not valid_sha(active.get("sha")):
            raise StateError("invalid active claim")
        if not valid_claim(active.get("claim_id")):
            raise StateError("invalid active claim id")
        if active.get("suite_fingerprint") != state["suite_fingerprint"]:
            raise StateError("active claim uses a different suite definition")
        if active.get("attempt") not in (1, 2):
            raise StateError("invalid active attempt")
        if not isinstance(active.get("created_at"), str):
            raise StateError("invalid active claim time")
        dispatch_at = active.get("dispatch_started_at")
        if dispatch_at is not None:
            try:
                parsed = datetime.fromisoformat(dispatch_at)
                if parsed.tzinfo is None:
                    raise ValueError("dispatch time has no timezone")
            except (TypeError, ValueError) as exc:
                raise StateError("invalid dispatch lease time") from exc
        if active.get("run_id") is not None and (
            not isinstance(active["run_id"], int) or active["run_id"] <= 0
        ):
            raise StateError("invalid active run id")
        if active.get("run_url") is not None and (
            not isinstance(active["run_url"], str)
            or not re.fullmatch(
                r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+",
                active["run_url"],
            )
        ):
            raise StateError("invalid active workflow URL")
    if state.get("failure") is not None and not isinstance(state["failure"], dict):
        raise StateError("invalid failure record")
    failure = state.get("failure")
    if failure is not None:
        if state["health"] != "unhealthy" or failure.get("sha") != state["cursor_sha"]:
            raise StateError("failure does not match unhealthy cursor")
        if not valid_sha(failure.get("sha")) or not valid_claim(failure.get("claim_id")):
            raise StateError("invalid failure identity")
        if failure.get("conclusion") not in ("failure", "cancelled", "timed_out", "action_required"):
            raise StateError("invalid failure conclusion")
        if failure.get("attempt") != 2:
            raise StateError("terminal failure must follow the retry attempt")
        if not isinstance(failure.get("pr_lookup_pending"), bool):
            raise StateError("invalid PR association lookup state")
        if not isinstance(failure.get("run_id"), int) or failure["run_id"] <= 0:
            raise StateError("invalid failure run id")
        if not isinstance(failure.get("run_url"), str) or not re.fullmatch(
            r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+",
            failure["run_url"],
        ):
            raise StateError("invalid failure workflow URL")
        if not isinstance(failure.get("failures"), list) or not isinstance(failure.get("pr_numbers"), list):
            raise StateError("invalid failure metadata")
        for item in failure["failures"]:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("suite"), str)
                or not re.fullmatch(r"[a-z0-9-]{1,60}", item["suite"])
                or not isinstance(item.get("version"), str)
                or not re.fullmatch(r"v[0-9.]{1,20}", item["version"])
            ):
                raise StateError("unsafe failure suite metadata")
        if any(not isinstance(number, int) or number <= 0 for number in failure["pr_numbers"]):
            raise StateError("invalid associated PR number")
    elif state["health"] == "unhealthy":
        raise StateError("unhealthy state has no failure record")
    if not isinstance(state.get("generation"), int) or state["generation"] < 0:
        raise StateError("invalid generation")
    return state


def claim_commit(
    state: dict[str, Any],
    first_parent_commits: list[str],
    claim_id: str,
    at: str | None = None,
) -> dict[str, Any]:
    """Claim only the oldest unprocessed first-parent commit."""
    validate_state(state)
    if state["active"] is not None:
        return state
    if not valid_claim(claim_id):
        raise StateError("invalid claim id")
    commits = first_parent_commits
    if any(not valid_sha(sha) for sha in commits):
        raise StateError("commit enumeration contains an invalid SHA")
    if state["cursor_sha"] not in commits:
        raise StateError("cursor is not on the enumerated first-parent history")
    cursor_index = commits.index(state["cursor_sha"])
    pending = commits[cursor_index + 1 :]
    if not pending:
        return state
    result = dict(state)
    result["active"] = {
        "sha": pending[0],
        "claim_id": claim_id,
        "suite_fingerprint": state["suite_fingerprint"],
        "attempt": 1,
        "created_at": at or now_iso(),
        "run_id": None,
        "run_url": None,
    }
    result["generation"] += 1
    result["updated_at"] = at or now_iso()
    return result


def retry_claim(
    state: dict[str, Any],
    *,
    claim_id: str,
    run_id: int,
    at: str | None = None,
) -> dict[str, Any]:
    """Persist the one allowed full retry before the controller dispatches it."""
    validate_state(state)
    active = state["active"]
    if (
        not active
        or active["claim_id"] != claim_id
        or active["attempt"] != 1
        or active.get("run_id") not in (None, run_id)
    ):
        return state
    result = dict(state)
    result["active"] = dict(
        active,
        attempt=2,
        run_id=None,
        run_url=None,
        dispatch_started_at=None,
    )
    result["generation"] += 1
    result["updated_at"] = at or now_iso()
    validate_state(result)
    return result


def update_suite_definition(
    state: dict[str, Any], suite_fingerprint: str, at: str | None = None
) -> dict[str, Any]:
    validate_state(state)
    if not isinstance(suite_fingerprint, str) or not FINGERPRINT_RE.fullmatch(suite_fingerprint):
        raise StateError("suite definition fingerprint is invalid")
    if state["suite_fingerprint"] == suite_fingerprint:
        return state
    result = dict(state)
    result["suite_fingerprint"] = suite_fingerprint
    result["active"] = None
    if result["health"] == "healthy":
        result["health"] = "unknown"
        result["last_pass_sha"] = None
    result["generation"] += 1
    result["updated_at"] = at or now_iso()
    validate_state(result)
    return result


def attach_run(
    state: dict[str, Any],
    claim_id: str,
    run_id: int,
    run_url: str,
    at: str | None = None,
) -> dict[str, Any]:
    validate_state(state)
    active = state["active"]
    if not active or active["claim_id"] != claim_id:
        return state
    if not isinstance(run_id, int) or run_id <= 0:
        raise StateError("invalid workflow run id")
    if not isinstance(run_url, str) or len(run_url) > 500:
        raise StateError("invalid workflow run URL")
    if not re.fullmatch(
        r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+",
        run_url,
    ):
        raise StateError("invalid workflow run URL")
    result = dict(state)
    result["active"] = dict(active, run_id=run_id, run_url=run_url)
    result["generation"] += 1
    result["updated_at"] = at or now_iso()
    return result


def finish_run(
    state: dict[str, Any],
    *,
    claim_id: str,
    run_id: int,
    conclusion: str,
    failures: list[dict[str, str]],
    run_url: str,
    attempt: int = 1,
    pr_numbers: list[int] | None = None,
    pr_lookup_pending: bool = False,
    at: str | None = None,
) -> dict[str, Any]:
    """Apply exactly one matching terminal run; stale completions are no-ops."""
    validate_state(state)
    active = state["active"]
    if not active or active["claim_id"] != claim_id:
        return state
    if active["attempt"] != attempt:
        return state
    if active["run_id"] is not None and active["run_id"] != run_id:
        return state
    if not isinstance(run_id, int) or run_id <= 0:
        raise StateError("invalid workflow run id")
    if conclusion not in ("success", "failure", "cancelled", "timed_out", "action_required"):
        conclusion = "failure"
    result = dict(state)
    result["active"] = None
    result["cursor_sha"] = active["sha"]
    result["generation"] += 1
    result["updated_at"] = at or now_iso()
    if conclusion == "success":
        result["health"] = "healthy"
        result["last_pass_sha"] = active["sha"]
        result["failure"] = None
        return result

    clean_failures = []
    for item in failures[:20]:
        suite = item.get("suite", "unknown")[:80]
        version = item.get("version", "unknown")[:24]
        clean_failures.append({"suite": suite, "version": version})
    result["health"] = "unhealthy"
    result["failure"] = {
        "sha": active["sha"],
        "claim_id": claim_id,
        "run_id": run_id,
        "attempt": attempt,
        "run_url": run_url[:500],
        "conclusion": conclusion,
        "failures": clean_failures,
        "pr_numbers": [n for n in (pr_numbers or [])[:50] if isinstance(n, int) and n > 0],
        "pr_lookup_pending": pr_lookup_pending,
        "at": at or now_iso(),
    }
    validate_state(result)
    return result


def status_for_pr(state: dict[str, Any]) -> tuple[str, str]:
    """PRs keep the last-known health while main has queued, untested commits."""
    validate_state(state)
    if state["health"] == "unhealthy":
        sha = state["failure"]["sha"][:12]
        return "failure", f"Main E2E unhealthy since {sha}; see the main-health issue"
    if state["health"] == "healthy":
        return "success", f"Latest full E2E passed: {state['last_pass_sha'][:12]}"
    return "pending", "Main E2E baseline not established"


def status_for_main(state: dict[str, Any]) -> tuple[str, str]:
    """The main SHA is green only when its current first-parent cursor passed."""
    validate_state(state)
    if state["health"] == "unhealthy":
        sha = state["failure"]["sha"][:12]
        return "failure", f"Main E2E unhealthy since {sha}; see the main-health issue"
    if state["health"] != "healthy":
        return "pending", "Main E2E baseline not established"
    if state["active"] or (
        state.get("observed_main_sha")
        and state.get("observed_main_sha") != state["cursor_sha"]
    ):
        return "pending", "Main E2E pending; current main commit is not fully tested"
    return "success", f"Latest full E2E passed: {state['last_pass_sha'][:12]}"


def failure_issue_body(state: dict[str, Any], backlog: int = 0) -> str:
    validate_state(state)
    failure = state["failure"]
    if state["health"] != "unhealthy" or not failure:
        raise StateError("cannot render an issue body for healthy state")
    commit = failure["sha"]
    run_url = failure.get("run_url", "")
    if not isinstance(run_url, str) or not re.fullmatch(
        r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+",
        run_url,
    ):
        run_url = ""
    suffix = f"\n\n**Queued first-parent commits remaining:** {max(0, min(backlog, 100000))}."
    failed = failure.get("failures") or []
    suite_rows = "\n".join(
        f"- `{escape(x['suite'])}` on `{escape(x['version'])}`"
        for x in failed
        if isinstance(x, dict) and isinstance(x.get("suite"), str) and isinstance(x.get("version"), str)
    )
    if not suite_rows:
        suite_rows = "- Exact failed suite is unavailable (workflow, build, cancellation, or infrastructure failure)."
    prs = failure.get("pr_numbers") or []
    pr_text = ", ".join(f"#{n}" for n in prs) if prs else "No associated open PR was identified."
    if failure.get("pr_lookup_pending"):
        pr_text += "; GitHub PR association lookup failed and will be retried during reconciliation."
    return (
        "## Main E2E health failure\n\n"
        f"- **Commit:** `{commit}`\n"
        f"- **Workflow run:** [{escape(run_url) or 'Unavailable'}]({escape(run_url)})\n"
        f"- **Attempt:** {failure.get('attempt', 2)} (full-matrix retry)\n"
        f"- **Conclusion:** `{failure.get('conclusion', 'unknown')}`\n"
        f"- **Associated PRs:** {pr_text}\n\n"
        "### Reported failed suite/version candidates\n"
        f"{suite_rows}\n\n"
        "The exact root cause is not inferred. Inspect the linked run and its bounded job logs; "
        "infrastructure failures and flaky tests may not identify a code culprit.\n\n"
        "### Reproduce\n"
        f"1. Check out `{commit}`.\n"
        "2. Build with `make ko-build && make docker-save-image`.\n"
        "3. Re-run the listed suite with the Kubernetes version shown above using the "
        "same `make` setup commands in `.github/scripts/run-e2e-suite.sh`.\n\n"
        "### Repair\n"
        "Fix the issue and merge a new commit to `main`; health clears only after a newer "
        "commit passes the full E2E matrix. If the change should be abandoned, revert the "
        f"culprit with `git revert {commit}` and merge that repair commit. Do not close this "
        "issue manually as a substitute for a green run."
        f"{suffix}\n"
    )
