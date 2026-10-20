#!/usr/bin/env python3
"""Create and access contained session-local state for web challenges."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


COMMON_SCRIPTS = Path(__file__).resolve().parents[2] / "ctf-common" / "scripts"
sys.path.insert(0, str(COMMON_SCRIPTS))
from ctf_workspace import (  # noqa: E402
    InvalidInput,
    _atomic_json,
    _open_directory_nofollow,
    _read_regular_under,
    _safe_directory,
    _workspace_root,
    _write_new_bytes,
    _write_new_json,
)


class WebStateError(ValueError):
    """Raised for invalid or non-web session state."""


ANALYSIS_SECTIONS = ("Flag location", "Attack surface", "Vulnerability", "Exploit path")
ANALYSIS_TEMPLATE = """# Analysis

Fill every section from evidence before claiming a solve. Cite file:line for
source, or a web/responses/ path for black-box observations.

## Flag location
<!-- Where the real flag lives on the remote target (env, file, DB row, admin
page) and which condition normally prevents an ordinary user from reading it. -->

## Attack surface
<!-- Routes, methods, and every input location (query, form, JSON, headers,
cookies, path, storage, WebSocket). Note middleware/handler mismatches. -->

## Vulnerability
<!-- The flaw, the exact source or response evidence for it, and why the
filters or checks in front of it do not stop it. -->

## Exploit path
<!-- Ordered steps from an unauthenticated session to the flag, and which
capability each step earns. -->
"""


def session_workspace(workspace: Path) -> Path:
    """Validate a canonical web session without following workspace links."""
    try:
        workspace, _ = _workspace_root(workspace)
        session = json.loads(_read_regular_under(workspace, workspace / "session.json", "web session").data)
    except (InvalidInput, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebStateError("not a session workspace") from exc
    if not isinstance(session, dict) or session.get("category") != "web":
        raise WebStateError("not a web session workspace")
    return workspace


def web_directory(workspace: Path, *parts: str) -> Path:
    """Return a created, no-follow web state directory beneath this session."""
    try:
        return _safe_directory(session_workspace(workspace), "web", *parts)
    except InvalidInput as exc:
        raise WebStateError("unsafe web state directory") from exc


@contextmanager
def web_lock(workspace: Path, name: str) -> Iterator[None]:
    """Lock one web-state file through a no-follow directory descriptor."""
    web = web_directory(workspace)
    directory = _open_directory_nofollow(web)
    try:
        try:
            descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        except OSError as exc:
            raise WebStateError("unsafe web state lock") from exc
        try:
            stream = os.fdopen(descriptor, "a+", encoding="utf-8")
        except OSError as exc:
            os.close(descriptor)
            raise WebStateError("unsafe web state lock") from exc
        with stream:
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            except OSError as exc:
                raise WebStateError("unsafe web state lock") from exc
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    finally:
        os.close(directory)


def analysis_gaps(workspace: Path) -> list[str]:
    """Return analysis sections that are missing or still only template comments."""
    try:
        text = _read_regular_under(workspace, workspace / "analysis.md", "analysis").data.decode("utf-8")
    except (InvalidInput, UnicodeDecodeError):
        return list(ANALYSIS_SECTIONS)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    bodies: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        heading = re.match(r"^##\s+(.+?)\s*$", line)
        if heading:
            current = heading.group(1).strip().lower()
            bodies.setdefault(current, "")
        elif current is not None:
            bodies[current] += line.strip()
    return [name for name in ANALYSIS_SECTIONS if len(bodies.get(name.lower(), "")) < 20]


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    try:
        _atomic_json(path, payload)
    except (InvalidInput, OSError) as exc:
        raise WebStateError("unsafe web state write") from exc


def write_new_json(path: Path, payload: dict[str, Any]) -> None:
    try:
        _write_new_json(path, payload)
    except FileExistsError:
        raise
    except (InvalidInput, OSError) as exc:
        raise WebStateError("unsafe web state write") from exc


def init_web_state(workspace: Path) -> dict[str, str]:
    """Initialize contained browser, evidence, coverage, and history state."""
    workspace = session_workspace(workspace)
    web = web_directory(workspace)
    requests_dir = web_directory(workspace, "requests")
    responses_dir = web_directory(workspace, "responses")
    provenance_dir = web_directory(workspace, "provenance")
    captures_dir = web_directory(workspace, "captures")
    lab_dir = web_directory(workspace, "lab")
    runs_dir = web_directory(workspace, "runs")
    profile = web_directory(workspace, "browser-profile")
    files = {
        "cookies.json": {"cookies": [], "schema_version": 1},
        "coverage.json": {"entries": [], "schema_version": 1},
        "capabilities.json": {"capabilities": [], "schema_version": 1},
        "history.json": {"requests": [], "schema_version": 1},
    }
    for name, payload in files.items():
        try:
            write_new_json(web / name, payload)
        except FileExistsError:
            pass
    try:
        _write_new_bytes(workspace / "analysis.md", ANALYSIS_TEMPLATE.encode("utf-8"))
    except FileExistsError:
        pass
    except (InvalidInput, OSError) as exc:
        raise WebStateError("unsafe analysis write") from exc
    return {
        "workspace": str(workspace), "web_root": str(web), "cookie_jar": str(web / "cookies.json"),
        "browser_profile": str(profile), "coverage": str(web / "coverage.json"),
        "requests_dir": str(requests_dir), "responses_dir": str(responses_dir),
        "provenance_dir": str(provenance_dir), "captures_dir": str(captures_dir),
        "history": str(web / "history.json"), "capabilities": str(web / "capabilities.json"),
        "analysis": str(workspace / "analysis.md"), "lab_dir": str(lab_dir), "runs_dir": str(runs_dir),
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
