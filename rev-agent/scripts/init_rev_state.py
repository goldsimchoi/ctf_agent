#!/usr/bin/env python3
"""Create contained session-local state for authorized reversing work."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


COMMON_SCRIPTS = Path(__file__).resolve().parents[2] / "ctf-common" / "scripts"
sys.path.insert(0, str(COMMON_SCRIPTS))
from ctf_workspace import (  # noqa: E402
    InvalidInput,
    _read_regular_under,
    _safe_directory,
    _workspace_root,
    _write_new_json,
)


class RevStateError(ValueError):
    """Raised when a path is not a safe reversing session workspace."""


def session_workspace(workspace: Path) -> Path:
    """Validate one canonical reversing session through common safe readers."""
    try:
        workspace, _ = _workspace_root(workspace)
        session = json.loads(
            _read_regular_under(workspace, workspace / "session.json", "reversing session").data
        )
    except (InvalidInput, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RevStateError("not a session workspace") from exc
    if not isinstance(session, dict) or session.get("category") != "rev":
        raise RevStateError("not a reversing session workspace")
    return workspace


def rev_directory(workspace: Path, *parts: str) -> Path:
    """Return a no-follow reversing work directory below a valid session."""
    try:
        return _safe_directory(session_workspace(workspace), "rev", *parts)
    except InvalidInput as exc:
        raise RevStateError("unsafe reversing state directory") from exc


def _write_initial(workspace: Path, path: Path, payload: dict[str, Any]) -> None:
    try:
        _write_new_json(path, payload)
    except FileExistsError:
        try:
            _read_regular_under(workspace, path, "reversing state")
        except InvalidInput as exc:
            raise RevStateError("unsafe reversing state file") from exc
    except (InvalidInput, OSError) as exc:
        raise RevStateError("unsafe reversing state write") from exc


def init_rev_state(workspace: Path) -> dict[str, str]:
    """Initialize contained analysis ledgers and debugger work directories."""
    workspace = session_workspace(workspace)
    rev = rev_directory(workspace)
    ida = rev_directory(workspace, "ida")
    gdb = rev_directory(workspace, "gdb")
    oracle = rev_directory(workspace, "oracle")
    files = {
        "clues.json": {"schema_version": 1, "clues": []},
        "hypotheses.json": {"schema_version": 1, "hypotheses": []},
        "contradictions.json": {"schema_version": 1, "contradictions": []},
    }
    for name, payload in files.items():
        _write_initial(workspace, rev / name, payload)
    return {
        "workspace": str(workspace),
        "rev_root": str(rev),
        "ida_dir": str(ida),
        "gdb_dir": str(gdb),
        "oracle_dir": str(oracle),
        "clues": str(rev / "clues.json"),
        "hypotheses": str(rev / "hypotheses.json"),
        "contradictions": str(rev / "contradictions.json"),
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
