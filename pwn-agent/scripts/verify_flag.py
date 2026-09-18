#!/usr/bin/env python3
"""Compatibility entry point for common race/strict flag verification."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


COMMON_SCRIPTS = Path(__file__).resolve().parents[2] / "ctf-common" / "scripts"


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, action="append", required=True)
    parser.add_argument("--sent", type=Path, action="append", default=[])
    parser.add_argument("--attestation", type=Path, action="append", default=[])
    parser.add_argument("--pattern", action="append", default=[])
    parser.add_argument("--strict", action="store_true")
    # The old adapter wrote the JSON response to this optional file.
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()

    command = [
        sys.executable,
        str(COMMON_SCRIPTS / "verify_flag.py"),
        "--workspace",
        str(args.workspace),
    ]
    for output in args.output:
        command.extend(("--output", str(output)))
    for sent in args.sent:
        command.extend(("--sent", str(sent)))
    for attestation in args.attestation:
        command.extend(("--attestation", str(attestation)))
    for pattern in args.pattern:
        command.extend(("--pattern", pattern))
    if args.strict:
        command.append("--strict")

    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if args.result is not None and completed.stdout:
        write_atomic(args.result, completed.stdout)
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
