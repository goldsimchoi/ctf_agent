#!/usr/bin/env python3
"""Run a candidate against a local challenge binary and save oracle evidence."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path


def reversing_workspace(workspace: Path) -> Path:
    workspace = workspace.expanduser().resolve()
    try:
        session = json.loads((workspace / "session.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"not a session workspace: {workspace}") from exc
    if not isinstance(session, dict) or session.get("category") != "rev":
        raise ValueError(f"not a reversing session workspace: {workspace}")
    oracle = workspace / "rev" / "oracle"
    oracle.mkdir(parents=True, exist_ok=True)
    return workspace


def under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def run_oracle(
    workspace: Path,
    binary: Path,
    candidate: str,
    output: Path | None = None,
    timeout: float = 5.0,
) -> dict[str, object]:
    """Feed one candidate to the target binary and preserve its combined output."""
    workspace = reversing_workspace(workspace)
    binary = binary.expanduser().resolve()
    if not binary.is_file() or not binary.stat().st_mode & 0o111:
        raise ValueError(f"binary is not executable: {binary}")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    oracle = workspace / "rev" / "oracle"
    if output is None:
        output = oracle / f"oracle-{time.time_ns()}.out"
    output = output.expanduser().resolve()
    if not under(output, oracle):
        raise ValueError("oracle output must be inside this session's rev/oracle directory")
    try:
        result = subprocess.run(
            [str(binary)],
            input=candidate + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        transcript = result.stdout
        returncode = result.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        transcript = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        returncode = None
        timed_out = True
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(transcript, encoding="utf-8")
    return {
        "workspace": str(workspace),
        "binary": str(binary),
        "output": str(output),
        "returncode": returncode,
        "timed_out": timed_out,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=float, default=5.0)
    try:
        args = parser.parse_args()
        result = run_oracle(
            args.workspace, args.binary, args.candidate, args.output, args.timeout
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
