#!/usr/bin/env python3
"""Verify flags only from recorded, authorized web response provenance."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from init_web_state import WebStateError, analysis_gaps, session_workspace
from web_provenance import is_local_origin, manifest_origin, validate_response_provenance


COMMON = Path(__file__).resolve().parents[2] / "ctf-common" / "scripts" / "verify_flag.py"
sys.path.insert(0, str(COMMON.parent))
from ctf_workspace import DEFAULT_PATTERNS  # noqa: E402

MAX_LAB_BYTES = 64 * 1024 * 1024


def lab_candidates(workspace: Path) -> set[str]:
    """Flag-shaped strings observed in the local lab, which are placeholders."""
    found: set[str] = set()
    budget = MAX_LAB_BYTES
    lab = workspace / "web" / "lab"
    if not lab.is_dir() or lab.is_symlink():
        return found
    for path in sorted(lab.rglob("*")):
        if budget <= 0:
            break
        if path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()[:budget]
        budget -= len(data)
        for pattern in DEFAULT_PATTERNS:
            found.update(item.decode("utf-8", errors="replace") for item in re.findall(pattern, data))
    return found


def result(status: str, reason: str, **extra: object) -> int:
    print(json.dumps({"status": status, "reason": reason, "flag": None, **extra}, ensure_ascii=False))
    return 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, action="append", required=True)
    parser.add_argument("--strict", action="store_true")
    try:
        args = parser.parse_args()
        workspace = session_workspace(args.workspace)
        origin = manifest_origin(workspace)
        if is_local_origin(origin):
            # A local Docker copy only ever holds the placeholder flag.
            return result("lab_only", "target_origin_is_local", origin=origin,
                          next="rerun the same exploit against the remote challenge origin")
        gaps = analysis_gaps(workspace)
        if gaps:
            return result("unverified", "analysis_incomplete", missing_sections=gaps,
                          analysis=str(workspace / "analysis.md"))
        records = [validate_response_provenance(workspace, output) for output in args.output]
        captures = [record.get("capture") for record in records]
        if not all(isinstance(capture, dict) for capture in captures):
            raise WebStateError("every response requires a capture-time attestation")
        request_ids = [str(record["request_id"]) for record in records]
        if args.strict and (
            len(records) < 2
            or len(set(request_ids)) != len(request_ids)
            or len({str(capture["capture_id"]) for capture in captures}) != len(captures)
        ):
            raise WebStateError("strict mode requires two distinct authorized web requests")
        command = [sys.executable, str(COMMON), "--workspace", str(workspace), "--reject-supplied"]
        for capture in captures:
            command.extend((
                "--output", str(capture["output"]),
                "--sent", str(capture["sent"]),
                "--attestation", str(capture["attestation"]),
            ))
        for placeholder in sorted(lab_candidates(workspace)):
            command.extend(("--exclude", placeholder))
        if args.strict:
            command.append("--strict")
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        sys.stdout.write(completed.stdout)
        return completed.returncode
    except (WebStateError, OSError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
