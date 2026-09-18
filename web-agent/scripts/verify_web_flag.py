#!/usr/bin/env python3
"""Verify flags only from recorded, authorized web response provenance."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from init_web_state import WebStateError, session_workspace
from web_provenance import validate_response_provenance


COMMON = Path(__file__).resolve().parents[2] / "ctf-common" / "scripts" / "verify_flag.py"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, action="append", required=True)
    parser.add_argument("--strict", action="store_true")
    try:
        args = parser.parse_args()
        workspace = session_workspace(args.workspace)
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
        command = [sys.executable, str(COMMON), "--workspace", str(workspace)]
        for capture in captures:
            command.extend((
                "--output", str(capture["output"]),
                "--sent", str(capture["sent"]),
                "--attestation", str(capture["attestation"]),
            ))
        if args.strict:
            command.append("--strict")
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        sys.stdout.write(result.stdout)
        return result.returncode
    except WebStateError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
