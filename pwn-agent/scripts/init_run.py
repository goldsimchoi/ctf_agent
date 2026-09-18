#!/usr/bin/env python3
"""Compatibility entry point for a pwn session in the shared workspace."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


COMMON_SCRIPTS = Path(__file__).resolve().parents[2] / "ctf-common" / "scripts"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("challenge", type=Path)
    parser.add_argument("--event-root", type=Path)
    parser.add_argument("--session-id")
    # Legacy names map without changing their meaning when the old root is runs/.
    parser.add_argument("--runs-root", type=Path)
    parser.add_argument("--run-id")
    args = parser.parse_args()

    event_root = args.event_root
    if args.runs_root is not None:
        if args.runs_root.name != "runs":
            parser.error("--runs-root must name an event's runs directory")
        legacy_root = args.runs_root.parent
        if event_root is not None and event_root.resolve() != legacy_root.resolve():
            parser.error("--event-root conflicts with --runs-root")
        event_root = legacy_root

    session_id = args.session_id
    if args.run_id is not None:
        if session_id is not None and session_id != args.run_id:
            parser.error("--session-id conflicts with --run-id")
        session_id = args.run_id

    command = [
        sys.executable,
        str(COMMON_SCRIPTS / "init_session.py"),
        str(args.challenge),
        "--category",
        "pwn",
    ]
    if event_root is not None:
        command.extend(("--event-root", str(event_root)))
    if session_id is not None:
        command.extend(("--session-id", session_id))
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
