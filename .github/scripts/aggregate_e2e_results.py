#!/usr/bin/env python3
"""Validate untrusted per-matrix result artifacts and publish a retry decision."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

SUITES = {
    "authz-server-envoy",
    "authz-server-http",
    "sidecar-injector",
    "validation-webhook-envoy",
    "validation-webhook-http",
}
VERSIONS = {"v1.32.11", "v1.33.7", "v1.34.3", "v1.35.0"}


def collect(root: Path) -> tuple[bool, list[tuple[str, str]]]:
    failures: set[tuple[str, str]] = set()
    found: set[tuple[str, str]] = set()
    for path in list(root.rglob("result*.json"))[:100]:
        try:
            if path.stat().st_size > 2048:
                continue
            record = json.loads(path.read_text(encoding="utf-8"))
            suite, version, result = record.get("suite"), record.get("version"), record.get("result")
            if suite not in SUITES or version not in VERSIONS or result not in ("success", "failure"):
                continue
            key = (suite, version)
            found.add(key)
            if result == "failure":
                failures.add(key)
        except (OSError, ValueError, TypeError):
            continue
    expected = {(suite, version) for suite in SUITES for version in VERSIONS}
    failures.update(expected - found)
    return bool(failures), sorted(failures)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--build-result", required=True)
    parser.add_argument("--test-result", required=True)
    args = parser.parse_args()
    if args.build_result != "success" or args.test_result != "success":
        failed, suites = True, []
    else:
        failed, suites = collect(Path(args.results_dir))
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"failed={'true' if failed else 'false'}\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            if failed:
                handle.write("Attempt failed; retrying the full 20-combination matrix once.\n")
                if suites:
                    handle.write("\nReported failed suite candidates:\n")
                    for suite, version in suites:
                        handle.write(f"- `{suite}` on `{version}`\n")
                else:
                    handle.write("No trustworthy per-suite metadata was available.\n")
            else:
                handle.write("All 20 E2E suite/version combinations passed.\n")
    print(json.dumps({"failed": failed, "candidates": suites}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
