#!/usr/bin/env python3
"""Create session-local state for an authorized CTF reversing challenge."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any


class RevStateError(ValueError):
    """Raised when a path is not a reversing session workspace."""


def _atomic_create_json(path: Path, payload: dict[str, Any]) -> None:
    """Create initial state without replacing a concurrent writer's state."""
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            pass
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def session_workspace(workspace: Path) -> Path:
    """Validate and return one common reversing session workspace."""
    workspace = workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise RevStateError(f"workspace is not a directory: {workspace}")
    try:
        session = json.loads((workspace / "session.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RevStateError(f"not a session workspace: {workspace}") from exc
    if not isinstance(session, dict) or session.get("category") != "rev":
        raise RevStateError(f"not a reversing session workspace: {workspace}")
    return workspace


def init_rev_state(workspace: Path) -> dict[str, str]:
    """Initialize session-owned analysis ledgers and debugger work directories."""
    workspace = session_workspace(workspace)
    rev = workspace / "rev"
    ida = rev / "ida"
    gdb = rev / "gdb"
    oracle = rev / "oracle"
    for directory in (ida, gdb, oracle):
        directory.mkdir(parents=True, exist_ok=True)
    clues = rev / "clues.json"
    hypotheses = rev / "hypotheses.json"
    contradictions = rev / "contradictions.json"
    _atomic_create_json(clues, {"schema_version": 1, "clues": []})
    _atomic_create_json(hypotheses, {"schema_version": 1, "hypotheses": []})
    _atomic_create_json(contradictions, {"schema_version": 1, "contradictions": []})
    return {
        "workspace": str(workspace),
        "rev_root": str(rev),
        "ida_dir": str(ida),
        "gdb_dir": str(gdb),
        "oracle_dir": str(oracle),
        "clues": str(clues),
        "hypotheses": str(hypotheses),
        "contradictions": str(contradictions),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    try:
        result = init_rev_state(parser.parse_args().workspace)
    except RevStateError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
