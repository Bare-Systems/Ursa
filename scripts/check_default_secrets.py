#!/usr/bin/env python3
"""Fail if known Ursa development secrets leak into release-facing files."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

DEFAULT_SECRET_MARKERS = {
    "ursa-dev-session-secret-change-me",
    "change-me-now",
    "ursa-dev-approval-signing-key",
    "your-shared-bearclaw-token",
    "rotate-this-32-byte-signing-secret",
}

ALLOWLIST = {
    "major/config.py",
    "tests/major/test_config.py",
    "scripts/check_default_secrets.py",
}


def _tracked_files() -> list[Path]:
    output = subprocess.check_output(["git", "ls-files"], text=True)
    return [Path(line) for line in output.splitlines() if line]


def main() -> int:
    leaks: list[str] = []
    for path in _tracked_files():
        path_text = path.as_posix()
        if path_text in ALLOWLIST:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for marker in DEFAULT_SECRET_MARKERS:
            if marker in text:
                leaks.append(f"{path_text}: contains default secret marker {marker!r}")

    if leaks:
        print("Default secret scan failed:", file=sys.stderr)
        for leak in leaks:
            print(f"- {leak}", file=sys.stderr)
        return 1

    print("Default secret scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
