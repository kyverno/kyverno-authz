#!/usr/bin/env python3
"""Stable identity for the trusted E2E suite definition and runner."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

SUITE_FILES = (
    ".github/workflows/e2e.yaml",
    ".github/workflows/e2e-attempt.yaml",
    ".github/scripts/aggregate_e2e_results.py",
    ".github/scripts/run-e2e-suite.sh",
    ".github/scripts/suite_fingerprint.py",
)


def fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for relative in SUITE_FILES:
        path = root / relative
        if not path.is_file():
            raise FileNotFoundError(f"missing suite definition file: {relative}")
        data = path.read_bytes()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


if __name__ == "__main__":
    try:
        print(fingerprint(Path(sys.argv[1] if len(sys.argv) > 1 else ".")))
    except OSError as exc:
        print(f"suite fingerprint error: {exc}", file=sys.stderr)
        raise SystemExit(1)
