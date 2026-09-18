#!/usr/bin/env python3
"""Maintain evidence-backed, falsifiable reversing analysis state."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Sequence

from init_rev_state import RevStateError, init_rev_state, session_workspace


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
            json.dump(payload, stream, indent=2, sort_keys=True, ensure_ascii=False)
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


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _transaction_path(paths: dict[str, str]) -> Path:
    return Path(paths["rev_root"]) / ".state.transaction.json"


def _recover_transaction(paths: dict[str, str]) -> None:
    journal = _transaction_path(paths)
    if not journal.exists():
        return
    try:
        transaction = json.loads(journal.read_text(encoding="utf-8"))
        hypotheses = transaction["hypotheses"]
        contradictions = transaction["contradictions"]
        if transaction.get("schema_version") != 1 or not isinstance(hypotheses, dict) or not isinstance(contradictions, dict):
            raise ValueError
    except (OSError, ValueError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RevStateError(f"invalid pending reversing transaction: {journal}") from exc
    _atomic_json(Path(paths["hypotheses"]), hypotheses)
    _atomic_json(Path(paths["contradictions"]), contradictions)
    _fsync_directory(Path(paths["rev_root"]))
    journal.unlink()
    _fsync_directory(Path(paths["rev_root"]))


def _commit_transaction(paths: dict[str, str], hypotheses: dict[str, Any], contradictions: dict[str, Any]) -> None:
    journal = _transaction_path(paths)
    _atomic_json(journal, {"schema_version": 1, "hypotheses": hypotheses, "contradictions": contradictions})
    _fsync_directory(Path(paths["rev_root"]))
    _atomic_json(Path(paths["hypotheses"]), hypotheses)
    _atomic_json(Path(paths["contradictions"]), contradictions)
    _fsync_directory(Path(paths["rev_root"]))
    journal.unlink()
    _fsync_directory(Path(paths["rev_root"]))


def _text(value: str, field: str) -> str:
    normalized = " ".join(value.split())
    if not normalized:
        raise RevStateError(f"{field} must not be empty")
    return normalized


def _texts(values: Sequence[str] | None, field: str) -> list[str]:
    if values is None:
        return []
    return [_text(value, field) for value in values]


def _load(path: Path, key: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        entries = payload[key]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise RevStateError(f"invalid reversing state: {path}") from exc
    if not isinstance(payload, dict) or not isinstance(entries, list):
        raise RevStateError(f"invalid reversing state: {path}")
    if not all(isinstance(entry, dict) for entry in entries):
        raise RevStateError(f"invalid reversing state: {path}")
    return payload, entries


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
    paths = init_rev_state(workspace)
    evidence = _text(evidence, "evidence")
    summary = _text(summary, "summary")
    action = _text(next_action or "", "next action")
    path = Path(paths["clues"])
    with _lock(path.with_suffix(".lock")):
        payload, entries = _load(path, "clues")
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
        _atomic_json(path, payload)
    return entry


def record_hypothesis(workspace: Path, statement: str, falsifying_test: str) -> dict[str, Any]:
    """Register an active analysis hypothesis with its required disproof test."""
    paths = init_rev_state(workspace)
    statement = _text(statement, "hypothesis")
    falsifying_test = _text(falsifying_test, "falsifying test")
    path = Path(paths["hypotheses"])
    with _lock(Path(paths["rev_root"]) / ".state.lock"):
        _recover_transaction(paths)
        payload, entries = _load(path, "hypotheses")
        contradictions, _ = _load(Path(paths["contradictions"]), "contradictions")
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
        _commit_transaction(paths, payload, contradictions)
    return entry


def record_experiment(
    workspace: Path,
    hypothesis_id: str,
    evidence: str,
    result: str,
    progress: bool = False,
) -> dict[str, Any]:
    """Record a falsification attempt; two no-progress attempts reject it."""
    paths = init_rev_state(workspace)
    hypothesis_id = _text(hypothesis_id, "hypothesis id")
    evidence = _text(evidence, "evidence")
    result = _text(result, "result")
    path = Path(paths["hypotheses"])
    with _lock(Path(paths["rev_root"]) / ".state.lock"):
        _recover_transaction(paths)
        payload, entries = _load(path, "hypotheses")
        contradictions, _ = _load(Path(paths["contradictions"]), "contradictions")
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
        _commit_transaction(paths, payload, contradictions)
    return hypothesis


def record_contradiction(
    workspace: Path, hypothesis_id: str, evidence: str, summary: str
) -> dict[str, Any]:
    """Preserve evidence that conflicts with a live hypothesis without erasing it."""
    paths = init_rev_state(workspace)
    hypothesis_id = _text(hypothesis_id, "hypothesis id")
    evidence = _text(evidence, "evidence")
    summary = _text(summary, "contradiction summary")
    hypotheses_path = Path(paths["hypotheses"])
    contradictions_path = Path(paths["contradictions"])
    # A shared lock makes the cross-ledger link consistent for concurrent sessions.
    with _lock(Path(paths["rev_root"]) / ".state.lock"):
        _recover_transaction(paths)
        hypotheses, entries = _load(hypotheses_path, "hypotheses")
        hypothesis = next((entry for entry in entries if entry.get("id") == hypothesis_id), None)
        if hypothesis is None:
            raise RevStateError(f"unknown hypothesis: {hypothesis_id}")
        contradictions, records = _load(contradictions_path, "contradictions")
        record = {
            "id": f"contradiction-{len(records) + 1:04d}",
            "hypothesis_id": hypothesis_id,
            "evidence": evidence,
            "summary": summary,
            "recorded_at": _now(),
        }
        records.append(record)
        hypothesis.setdefault("contradiction_ids", []).append(record["id"])
        _commit_transaction(paths, hypotheses, contradictions)
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
