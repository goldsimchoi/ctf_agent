#!/usr/bin/env python3
"""Maintain evidence-backed, falsifiable reversing analysis state."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import os
import re
import secrets
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from init_rev_state import RevStateError, init_rev_state, rev_directory, session_workspace


COMMON_SCRIPTS = Path(__file__).resolve().parents[2] / "ctf-common" / "scripts"
sys.path.insert(0, str(COMMON_SCRIPTS))
from ctf_workspace import InvalidInput, _open_directory_nofollow, _read_regular_under  # noqa: E402


@contextmanager
def _lock(workspace: Path, name: str) -> Iterator[tuple[Path, int]]:
    """Hold a no-follow lock and its validated reversing directory descriptor."""
    directory: int | None = None
    descriptor: int | None = None
    try:
        rev = rev_directory(workspace)
        directory = _open_directory_nofollow(rev)
        descriptor = os.open(
            name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
        with os.fdopen(descriptor, "a+", encoding="utf-8") as stream:
            descriptor = None
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield rev, directory
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    except (InvalidInput, OSError) as exc:
        raise RevStateError("unsafe reversing state lock") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _atomic_json(directory: int, name: str, payload: dict[str, Any]) -> None:
    """Atomically replace one ledger through an already-held no-follow directory FD."""
    temporary = f".{name}.{secrets.token_hex(8)}.tmp"
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
            dir_fd=directory,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_json_bytes(payload))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except OSError as exc:
        raise RevStateError("unsafe reversing state write") from exc
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _write_new_json(directory: int, name: str, payload: dict[str, Any]) -> None:
    """Create a transaction record through the validated directory descriptor."""
    try:
        descriptor = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
            dir_fd=directory,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_json_bytes(payload))
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(directory)
    except OSError as exc:
        raise RevStateError("unsafe reversing transaction write") from exc


def _remove(directory: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=directory)
        os.fsync(directory)
    except OSError as exc:
        raise RevStateError("unsafe reversing transaction removal") from exc


def _transaction_exists(directory: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise RevStateError("unsafe reversing transaction") from exc


def _safe_id(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value))


def _validate_transaction_snapshots(hypotheses: object, contradictions: object) -> None:
    if (
        not isinstance(hypotheses, dict)
        or set(hypotheses) != {"schema_version", "hypotheses"}
        or hypotheses.get("schema_version") != 1
        or not isinstance(hypotheses["hypotheses"], list)
        or not isinstance(contradictions, dict)
        or set(contradictions) != {"schema_version", "contradictions"}
        or contradictions.get("schema_version") != 1
        or not isinstance(contradictions["contradictions"], list)
    ):
        raise ValueError("invalid transaction ledger shape")
    hypothesis_ids: set[str] = set()
    for entry in hypotheses["hypotheses"]:
        required = {"id", "statement", "falsifying_test", "status", "no_progress", "experiments", "contradiction_ids", "created_at"}
        if not isinstance(entry, dict) or not required.issubset(entry) or not _safe_id(entry.get("id")):
            raise ValueError("invalid transaction hypothesis")
        if entry["id"] in hypothesis_ids or not all(isinstance(entry[field], str) and entry[field].strip() for field in ("statement", "falsifying_test", "created_at")):
            raise ValueError("invalid transaction hypothesis")
        if entry["status"] not in {"active", "rejected"} or isinstance(entry["no_progress"], bool) or not isinstance(entry["no_progress"], int) or entry["no_progress"] < 0:
            raise ValueError("invalid transaction hypothesis")
        if not isinstance(entry["experiments"], list) or not isinstance(entry["contradiction_ids"], list) or len(set(entry["contradiction_ids"])) != len(entry["contradiction_ids"]):
            raise ValueError("invalid transaction hypothesis")
        if not all(_safe_id(value) for value in entry["contradiction_ids"]):
            raise ValueError("invalid transaction hypothesis")
        for experiment in entry["experiments"]:
            if not isinstance(experiment, dict) or not all(isinstance(experiment.get(field), str) and experiment[field].strip() for field in ("evidence", "result", "recorded_at")) or not isinstance(experiment.get("progress"), bool):
                raise ValueError("invalid transaction experiment")
        hypothesis_ids.add(entry["id"])
    contradiction_ids: set[str] = set()
    links: dict[str, str] = {}
    for entry in contradictions["contradictions"]:
        required = {"id", "hypothesis_id", "evidence", "summary", "recorded_at"}
        if not isinstance(entry, dict) or not required.issubset(entry) or not _safe_id(entry.get("id")) or not _safe_id(entry.get("hypothesis_id")):
            raise ValueError("invalid transaction contradiction")
        if entry["id"] in contradiction_ids or entry["hypothesis_id"] not in hypothesis_ids or not all(isinstance(entry[field], str) and entry[field].strip() for field in ("evidence", "summary", "recorded_at")):
            raise ValueError("invalid transaction contradiction")
        contradiction_ids.add(entry["id"])
        links[entry["id"]] = entry["hypothesis_id"]
    for entry in hypotheses["hypotheses"]:
        for contradiction_id in entry["contradiction_ids"]:
            if links.get(contradiction_id) != entry["id"]:
                raise ValueError("inconsistent transaction contradiction link")
    for contradiction_id, hypothesis_id in links.items():
        hypothesis = next(entry for entry in hypotheses["hypotheses"] if entry["id"] == hypothesis_id)
        if contradiction_id not in hypothesis["contradiction_ids"]:
            raise ValueError("inconsistent transaction contradiction link")


def _load(workspace: Path, rev: Path, name: str, key: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = rev / name
    try:
        payload = json.loads(_read_regular_under(workspace, path, "reversing state").data.decode("utf-8"))
        entries = payload[key]
    except (InvalidInput, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RevStateError(f"invalid reversing state: {path}") from exc
    if not isinstance(payload, dict) or not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        raise RevStateError(f"invalid reversing state: {path}")
    return payload, entries


def _recover_transaction(workspace: Path, rev: Path, directory: int) -> None:
    name = ".state.transaction.json"
    if not _transaction_exists(directory, name):
        return
    try:
        transaction = json.loads(
            _read_regular_under(workspace, rev / name, "reversing transaction").data.decode("utf-8")
        )
        hypotheses = transaction["hypotheses"]
        contradictions = transaction["contradictions"]
        if set(transaction) != {"schema_version", "hypotheses", "contradictions"} or transaction.get("schema_version") != 1:
            raise ValueError
        _validate_transaction_snapshots(hypotheses, contradictions)
    except (InvalidInput, UnicodeDecodeError, ValueError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RevStateError(f"invalid pending reversing transaction: {rev / name}") from exc
    _atomic_json(directory, "hypotheses.json", hypotheses)
    _atomic_json(directory, "contradictions.json", contradictions)
    _remove(directory, name)


def _commit_transaction(
    directory: int, hypotheses: dict[str, Any], contradictions: dict[str, Any]
) -> None:
    name = ".state.transaction.json"
    _write_new_json(
        directory, name,
        {"schema_version": 1, "hypotheses": hypotheses, "contradictions": contradictions},
    )
    _atomic_json(directory, "hypotheses.json", hypotheses)
    _atomic_json(directory, "contradictions.json", contradictions)
    _remove(directory, name)


def _text(value: str, field: str) -> str:
    normalized = " ".join(value.split())
    if not normalized:
        raise RevStateError(f"{field} must not be empty")
    return normalized


def _texts(values: Sequence[str] | None, field: str) -> list[str]:
    if values is None:
        return []
    return [_text(value, field) for value in values]


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def record_clue(
    workspace: Path,
    evidence: str,
    summary: str,
    xrefs: Sequence[str] | None = None,
    functions: Sequence[str] | None = None,
    next_action: str | None = None,
) -> dict[str, Any]:
    """Append one evidence-backed clue and its cheapest discriminating action."""
    workspace = session_workspace(workspace)
    init_rev_state(workspace)
    evidence = _text(evidence, "evidence")
    summary = _text(summary, "summary")
    action = _text(next_action or "", "next action")
    with _lock(workspace, ".clues.lock") as (rev, directory):
        payload, entries = _load(workspace, rev, "clues.json", "clues")
        entry = {
            "id": f"clue-{len(entries) + 1:04d}",
            "evidence": evidence,
            "summary": summary,
            "xrefs": _texts(xrefs, "xref"),
            "functions": _texts(functions, "function"),
            "next_action": action,
            "recorded_at": _now(),
        }
        entries.append(entry)
        payload["clues"] = entries
        _atomic_json(directory, "clues.json", payload)
    return entry


def record_hypothesis(workspace: Path, statement: str, falsifying_test: str) -> dict[str, Any]:
    """Register an active analysis hypothesis with its required disproof test."""
    workspace = session_workspace(workspace)
    init_rev_state(workspace)
    statement = _text(statement, "hypothesis")
    falsifying_test = _text(falsifying_test, "falsifying test")
    with _lock(workspace, ".state.lock") as (rev, directory):
        _recover_transaction(workspace, rev, directory)
        payload, entries = _load(workspace, rev, "hypotheses.json", "hypotheses")
        contradictions, _ = _load(workspace, rev, "contradictions.json", "contradictions")
        entry = {
            "id": f"hypothesis-{len(entries) + 1:04d}",
            "statement": statement,
            "falsifying_test": falsifying_test,
            "status": "active",
            "no_progress": 0,
            "experiments": [],
            "contradiction_ids": [],
            "created_at": _now(),
        }
        entries.append(entry)
        payload["hypotheses"] = entries
        _commit_transaction(directory, payload, contradictions)
    return entry


def record_experiment(
    workspace: Path,
    hypothesis_id: str,
    evidence: str,
    result: str,
    progress: bool = False,
) -> dict[str, Any]:
    """Record a falsification attempt; two no-progress attempts reject it."""
    workspace = session_workspace(workspace)
    init_rev_state(workspace)
    hypothesis_id = _text(hypothesis_id, "hypothesis id")
    evidence = _text(evidence, "evidence")
    result = _text(result, "result")
    with _lock(workspace, ".state.lock") as (rev, directory):
        _recover_transaction(workspace, rev, directory)
        payload, entries = _load(workspace, rev, "hypotheses.json", "hypotheses")
        contradictions, _ = _load(workspace, rev, "contradictions.json", "contradictions")
        hypothesis = next((entry for entry in entries if entry.get("id") == hypothesis_id), None)
        if hypothesis is None:
            raise RevStateError(f"unknown hypothesis: {hypothesis_id}")
        if hypothesis.get("status") != "active":
            raise RevStateError(f"hypothesis is not active: {hypothesis_id}")
        experiments = hypothesis.setdefault("experiments", [])
        if not isinstance(experiments, list):
            raise RevStateError(f"invalid experiments for hypothesis: {hypothesis_id}")
        no_progress = 0 if progress else int(hypothesis.get("no_progress", 0)) + 1
        experiments.append({
            "evidence": evidence,
            "result": result,
            "progress": bool(progress),
            "recorded_at": _now(),
        })
        hypothesis["no_progress"] = no_progress
        if no_progress >= 2:
            hypothesis["status"] = "rejected"
            hypothesis["rejection_reason"] = "two no-progress experiments require a new approach"
        _commit_transaction(directory, payload, contradictions)
    return hypothesis


def record_contradiction(
    workspace: Path, hypothesis_id: str, evidence: str, summary: str
) -> dict[str, Any]:
    """Preserve evidence that conflicts with a live hypothesis without erasing it."""
    workspace = session_workspace(workspace)
    init_rev_state(workspace)
    hypothesis_id = _text(hypothesis_id, "hypothesis id")
    evidence = _text(evidence, "evidence")
    summary = _text(summary, "contradiction summary")
    with _lock(workspace, ".state.lock") as (rev, directory):
        _recover_transaction(workspace, rev, directory)
        hypotheses, entries = _load(workspace, rev, "hypotheses.json", "hypotheses")
        hypothesis = next((entry for entry in entries if entry.get("id") == hypothesis_id), None)
        if hypothesis is None:
            raise RevStateError(f"unknown hypothesis: {hypothesis_id}")
        contradictions, records = _load(workspace, rev, "contradictions.json", "contradictions")
        record = {
            "id": f"contradiction-{len(records) + 1:04d}",
            "hypothesis_id": hypothesis_id,
            "evidence": evidence,
            "summary": summary,
            "recorded_at": _now(),
        }
        records.append(record)
        hypothesis.setdefault("contradiction_ids", []).append(record["id"])
        _commit_transaction(directory, hypotheses, contradictions)
    return record


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    clue = commands.add_parser("clue")
    clue.add_argument("--workspace", type=Path, required=True)
    clue.add_argument("--evidence", required=True)
    clue.add_argument("--summary", required=True)
    clue.add_argument("--xref", action="append", default=[])
    clue.add_argument("--function", dest="functions", action="append", default=[])
    clue.add_argument("--next-action", required=True)
    hypothesis = commands.add_parser("hypothesis")
    hypothesis.add_argument("--workspace", type=Path, required=True)
    hypothesis.add_argument("--statement", required=True)
    hypothesis.add_argument("--falsifying-test", required=True)
    experiment = commands.add_parser("experiment")
    experiment.add_argument("--workspace", type=Path, required=True)
    experiment.add_argument("--hypothesis-id", required=True)
    experiment.add_argument("--evidence", required=True)
    experiment.add_argument("--result", required=True)
    experiment.add_argument("--progress", action="store_true")
    contradiction = commands.add_parser("contradiction")
    contradiction.add_argument("--workspace", type=Path, required=True)
    contradiction.add_argument("--hypothesis-id", required=True)
    contradiction.add_argument("--evidence", required=True)
    contradiction.add_argument("--summary", required=True)
    try:
        args = parser.parse_args()
        if args.command == "clue":
            result = record_clue(
                args.workspace, args.evidence, args.summary,
                args.xref, args.functions, args.next_action,
            )
        elif args.command == "hypothesis":
            result = record_hypothesis(args.workspace, args.statement, args.falsifying_test)
        elif args.command == "experiment":
            result = record_experiment(
                args.workspace, args.hypothesis_id, args.evidence, args.result, args.progress
            )
        else:
            result = record_contradiction(
                args.workspace, args.hypothesis_id, args.evidence, args.summary
            )
    except RevStateError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
