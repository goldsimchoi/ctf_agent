#!/usr/bin/env python3
"""Atomically update the web endpoint/input/technique coverage ledger."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from init_web_state import WebStateError, init_web_state, session_workspace


STATES = {"untested", "tested", "promising", "confirmed", "discarded"}
NEXT = {
    "untested": {"tested", "discarded"},
    "tested": {"promising", "discarded"},
    "promising": {"confirmed", "discarded"},
    "confirmed": set(),
    "discarded": set(),
}
KEY_FIELDS = ("endpoint", "method", "location", "parameter", "technique")


@contextmanager
def _lock(path: Path) -> Iterator[None]:
    with path.open("a+", encoding="utf-8") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _normal(value: str, field: str) -> str:
    normalized = " ".join(value.split())
    if not normalized:
        raise WebStateError(f"{field} must not be empty")
    return normalized


def _tuple(endpoint: str, method: str, location: str, parameter: str, technique: str) -> dict[str, str]:
    endpoint = _normal(endpoint, "endpoint")
    if not endpoint.startswith("/"):
        raise WebStateError("endpoint must be an origin-relative path")
    return {
        "endpoint": endpoint,
        "method": _normal(method, "method").upper(),
        "location": _normal(location, "location").lower(),
        "parameter": _normal(parameter, "parameter"),
        "technique": _normal(technique, "technique").lower(),
    }


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _evidence_path(evidence: Path | None, workspace: Path) -> str:
    if evidence is None:
        raise WebStateError("confirmed coverage requires an evidence path")
    resolved = evidence.expanduser().resolve()
    if not resolved.is_file() or not _under(resolved, workspace / "web" / "responses"):
        raise WebStateError("confirmed evidence must be a response file in this web session")
    return str(resolved)


def record_coverage(
    workspace: Path,
    endpoint: str,
    method: str,
    location: str,
    parameter: str,
    technique: str,
    status: str,
    evidence: Path | None = None,
) -> dict[str, Any]:
    """Move one full coverage tuple forward, never replacing a terminal result."""
    paths = init_web_state(workspace)
    workspace = session_workspace(workspace)
    status = _normal(status, "status").lower()
    if status not in STATES or status == "untested":
        raise WebStateError(f"invalid target status: {status!r}")
    key = _tuple(endpoint, method, location, parameter, technique)
    coverage_path = Path(paths["coverage"])
    with _lock(coverage_path.with_suffix(".lock")):
        try:
            coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
            entries = coverage["entries"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise WebStateError(f"invalid coverage ledger: {coverage_path}") from exc
        if not isinstance(entries, list):
            raise WebStateError(f"invalid coverage ledger: {coverage_path}")
        entry = next((row for row in entries if all(row.get(name) == key[name] for name in KEY_FIELDS)), None)
        previous = "untested" if entry is None else str(entry.get("status", "untested"))
        if status not in NEXT.get(previous, set()):
            raise WebStateError(f"cannot transition coverage from {previous} to {status}")
        evidence_value = _evidence_path(evidence, workspace) if status == "confirmed" else None
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        if entry is None:
            entry = {**key, "created_at": now}
            entries.append(entry)
        entry["status"] = status
        entry["updated_at"] = now
        if evidence_value is not None:
            entry["evidence"] = evidence_value
        coverage["entries"] = sorted(entries, key=lambda row: tuple(str(row.get(field, "")) for field in KEY_FIELDS))
        _atomic_json(coverage_path, coverage)
    return {"previous_status": previous, "entry": entry}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--method", required=True)
    parser.add_argument("--location", required=True)
    parser.add_argument("--parameter", required=True)
    parser.add_argument("--technique", required=True)
    parser.add_argument("--status", required=True)
    parser.add_argument("--evidence", type=Path)
    try:
        args = parser.parse_args()
        result = record_coverage(
            args.workspace, args.endpoint, args.method, args.location, args.parameter,
            args.technique, args.status, args.evidence,
        )
    except WebStateError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
