#!/usr/bin/env python3
"""Create session-local state for an authorized CTF web challenge."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any


class WebStateError(ValueError):
    """Raised for invalid or non-web session state."""


def _atomic_create_json(path: Path, payload: dict[str, Any]) -> None:
    """Publish an initial JSON file without replacing a concurrent writer."""
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
    workspace = workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise WebStateError(f"workspace is not a directory: {workspace}")
    try:
        session = json.loads((workspace / "session.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WebStateError(f"not a session workspace: {workspace}") from exc
    if not isinstance(session, dict) or session.get("category") != "web":
        raise WebStateError(f"not a web session workspace: {workspace}")
    return workspace


def init_web_state(workspace: Path) -> dict[str, str]:
    """Initialize immutable paths and empty session-local browser/coverage state."""
    workspace = session_workspace(workspace)
    web = workspace / "web"
    requests_dir = web / "requests"
    responses_dir = web / "responses"
    provenance_dir = web / "provenance"
    profile = web / "browser-profile"
    for directory in (requests_dir, responses_dir, provenance_dir, profile):
        directory.mkdir(parents=True, exist_ok=True)
    cookies = web / "cookies.json"
    coverage = web / "coverage.json"
    capabilities = web / "capabilities.json"
    _atomic_create_json(cookies, {"cookies": [], "schema_version": 1})
    _atomic_create_json(coverage, {"entries": [], "schema_version": 1})
    _atomic_create_json(capabilities, {"capabilities": [], "schema_version": 1})
    return {
        "workspace": str(workspace),
        "web_root": str(web),
        "cookie_jar": str(cookies),
        "browser_profile": str(profile),
        "coverage": str(coverage),
        "requests_dir": str(requests_dir),
        "responses_dir": str(responses_dir),
        "provenance_dir": str(provenance_dir),
        "capabilities": str(capabilities),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    try:
        result = init_web_state(parser.parse_args().workspace)
    except WebStateError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
