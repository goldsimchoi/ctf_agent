"""Collision-safe, category-neutral CTF session helpers."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


CATEGORIES = {"pwn", "web", "rev"}
DEFAULT_PATTERNS = (
    rb"FLAG\{[^}\r\n]+\}",
    rb"flag\{[^}\r\n]+\}",
    rb"[A-Za-z0-9_]{2,32}\{[^}\r\n]+\}",
)


class InvalidInput(ValueError):
    """Raised when a caller supplies an unsafe or unusable value."""


class CollisionError(FileExistsError):
    """Raised when an explicitly requested session already exists."""


class BudgetExhausted(RuntimeError):
    """Raised after state has been saved with an exhausted budget."""


class JsonArgumentParser(argparse.ArgumentParser):
    """Turn invalid command-line input into a caller-owned JSON error."""

    def error(self, message: str) -> None:
        raise InvalidInput(message)


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _timestamp() -> str:
    return _utc_now().strftime("%Y%m%dT%H%M%S.%fZ")


def safe_slug(value: str) -> str:
    """Return a filesystem-safe slug for challenge-derived names."""
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip(".-")
    if not slug or slug in {".", ".."}:
        raise InvalidInput(f"unsafe identifier: {value!r}")
    return slug


def _validate_explicit_id(value: str) -> str:
    if value != safe_slug(value) or "/" in value or "\\" in value:
        raise InvalidInput(f"unsafe identifier: {value!r}")
    return value


def new_session_id(category: str) -> str:
    stamp = _timestamp()
    return f"{category}-{stamp}-{os.getpid()}-{secrets.token_hex(4)}"


def _resolve_directory(path: Path, description: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_dir():
        raise InvalidInput(f"{description} is not a directory: {resolved}")
    return resolved


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _event_root_for(challenge: Path, event_root: Path | None) -> Path:
    if event_root is not None:
        root = _resolve_directory(event_root, "event root")
    elif challenge.parent.name == "challenges":
        root = challenge.parent.parent
    else:
        root = challenge.parent
    if not _under(challenge, root):
        raise InvalidInput(f"challenge is outside event root: {challenge}")
    return root


def _manifest_scalars(challenge: Path) -> dict[str, str]:
    manifest = next(
        (path for path in (challenge / "challenge.yaml", challenge / "challenge.yml") if path.is_file()),
        None,
    )
    if manifest is None:
        return {}
    values: dict[str, str] = {}
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^\s*([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*?)\s*(?:#.*)?$", line)
        if not match:
            continue
        key, value = match.groups()
        value = value.strip().strip("'\"")
        if value and not value.startswith(("[", "{", "|", ">")):
            values[key] = value
    return values


def challenge_fingerprint(challenge: Path) -> str:
    """Hash the sorted relative names and bytes of immutable challenge inputs."""
    digest = hashlib.sha256()
    files = sorted(path for path in challenge.rglob("*") if path.is_file())
    for path in files:
        relative = path.relative_to(challenge).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def _atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _write_new_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically publish a new file without allowing a replacement."""
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    except FileExistsError:
        raise
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _write_new_bytes(path: Path, content: bytes) -> None:
    """Atomically publish immutable binary evidence without replacement."""
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    except FileExistsError:
        raise
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _json_path(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidInput(f"invalid state file: {path}") from exc
    if not isinstance(payload, dict):
        raise InvalidInput(f"invalid state file: {path}")
    return payload


def _workspace_root(workspace: Path) -> tuple[Path, Path]:
    workspace = _resolve_directory(workspace, "workspace")
    if workspace.parent.name != "sessions" or not (workspace / "state.json").is_file():
        raise InvalidInput(f"not a session workspace: {workspace}")
    return workspace, workspace.parent.parent


def _finding_paths(common_root: Path) -> list[Path]:
    root = common_root / "shared" / "findings"
    if not root.is_dir():
        return []
    findings: list[Path] = []
    for path in sorted(root.glob("*/*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and payload.get("evidence") and payload.get("summary"):
            findings.append(path)
    return findings


def create_session(
    challenge: Path,
    category: str,
    event_root: Path | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Create one isolated workspace and return its resolved metadata."""
    if category not in CATEGORIES:
        raise InvalidInput(f"unsupported category: {category!r}")
    challenge = _resolve_directory(challenge, "challenge")
    root = _event_root_for(challenge, event_root)
    manifest = _manifest_scalars(challenge)
    slug = safe_slug(manifest.get("id", challenge.name))
    fingerprint = challenge_fingerprint(challenge)
    common_root = root / "runs" / category / f"{slug}-{fingerprint[:12]}"
    sessions = common_root / "sessions"
    shared_findings = common_root / "shared" / "findings"
    sessions.mkdir(parents=True, exist_ok=True)
    shared_findings.mkdir(parents=True, exist_ok=True)

    explicit = session_id is not None
    for _ in range(16):
        identifier = _validate_explicit_id(session_id) if explicit else new_session_id(category)
        workspace = sessions / identifier
        try:
            workspace.mkdir()
        except FileExistsError:
            if explicit:
                raise CollisionError(f"session already exists: {workspace}") from None
            continue
        break
    else:
        raise CollisionError("could not allocate a unique session ID")

    try:
        for name in ("artifacts", "logs", "transcripts"):
            (workspace / name).mkdir()
        started_at = _utc_now().isoformat()
        try:
            wall_time = int(manifest.get("wall_time_seconds", "0"))
        except ValueError as exc:
            raise InvalidInput("wall_time_seconds must be an integer") from exc
        if wall_time < 0:
            raise InvalidInput("wall_time_seconds must be non-negative")
        session = {
            "schema_version": 1,
            "category": category,
            "challenge": str(challenge),
            "event_root": str(root),
            "fingerprint": fingerprint,
            "session_id": identifier,
            "started_at": started_at,
        }
        state = {
            "attempts": [],
            "max_no_progress": 2,
            "no_progress": 0,
            "started_at": started_at,
            "wall_time_seconds": wall_time,
        }
        _atomic_json(workspace / "session.json", session)
        _atomic_json(workspace / "state.json", state)
        resolved = challenge / "challenge.yaml"
        if resolved.is_file():
            _atomic_text(
                workspace / "challenge.resolved.yaml",
                resolved.read_text(encoding="utf-8", errors="replace"),
            )
        else:
            _atomic_text(
                workspace / "challenge.resolved.yaml", f"id: {slug}\ncategory: {category}\n"
            )
        _atomic_text(workspace / "notes.md", f"# {slug}\n\n## Facts\n\n## Attempts\n")
    except BaseException:
        # A partially initialized session is never a usable collision target.
        for path in sorted(workspace.rglob("*"), reverse=True):
            if path.is_file() or path.is_symlink():
                path.unlink(missing_ok=True)
            elif path.is_dir():
                path.rmdir()
        workspace.rmdir()
        raise

    return {
        "workspace": workspace,
        "category": category,
        "challenge_id": slug,
        "fingerprint": fingerprint,
        "session_id": identifier,
        "findings": _finding_paths(common_root),
    }


def publish_finding(workspace: Path, kind: str, evidence: Path, summary: str) -> Path:
    """Publish immutable evidence visible to later sessions in this category."""
    workspace, common_root = _workspace_root(workspace)
    kind = _validate_explicit_id(kind)
    if not summary.strip():
        raise InvalidInput("finding summary must not be empty")
    evidence = evidence.expanduser().resolve()
    if not evidence.is_file() or not _under(evidence, workspace):
        raise InvalidInput("finding evidence must be a file inside its workspace")
    session = _json_path(workspace / "session.json")
    destination = common_root / "shared" / "findings" / str(session["session_id"])
    destination.mkdir(parents=True, exist_ok=True)
    content = evidence.read_bytes()
    for _ in range(16):
        stem = f"{_timestamp()}-{secrets.token_hex(4)}"
        evidence_path = destination / f"{stem}-{safe_slug(evidence.name)}"
        try:
            _write_new_bytes(evidence_path, content)
        except FileExistsError:
            continue
        payload = {
            "created_at": _utc_now().isoformat(),
            "evidence": str(evidence_path),
            "evidence_sha256": hashlib.sha256(content).hexdigest(),
            "kind": kind,
            "session_id": session["session_id"],
            "summary": summary.strip(),
        }
        path = destination / f"{stem}.json"
        try:
            _write_new_json(path, payload)
            return path
        except FileExistsError:
            evidence_path.unlink(missing_ok=True)
            continue
    raise CollisionError("could not publish unique finding")


@contextmanager
def _state_lock(workspace: Path) -> Iterator[None]:
    import fcntl

    lock_path = workspace / ".state.lock"
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _normal_signature(signature: str) -> str:
    normalized = " ".join(signature.lower().split())
    if not normalized:
        raise InvalidInput("attempt signature must not be empty")
    return normalized


def _new_fact(progress: str | None) -> bool:
    if progress is None:
        return False
    if not re.fullmatch(
        r"\s*(?:new\s+)?(?:fact|primitive|endpoint|clue|flag(?:\s+candidate)?)\b(?:\s*[:=-]\s*|\s+)\S(?:.*\S)?\s*",
        progress,
        re.IGNORECASE,
    ):
        raise InvalidInput(
            "progress requires a fact, primitive, endpoint, clue, or flag candidate with detail"
        )
    return True


def record_attempt(workspace: Path, signature: str, progress: str | None = None) -> dict[str, Any]:
    """Record an attempt and stop a session after two unproductive attempts."""
    workspace, _ = _workspace_root(workspace)
    normalized = _normal_signature(signature)
    meaningful_progress = _new_fact(progress)
    with _state_lock(workspace):
        state_path = workspace / "state.json"
        state = _json_path(state_path)
        started = dt.datetime.fromisoformat(str(state["started_at"]))
        wall_time = int(state.get("wall_time_seconds", 0))
        if wall_time and (_utc_now() - started).total_seconds() >= wall_time:
            raise BudgetExhausted("wall-time budget exhausted")
        previous = {str(attempt.get("signature", "")) for attempt in state.get("attempts", [])}
        if normalized in previous and not meaningful_progress:
            raise InvalidInput("unchanged attempt requires a new fact, primitive, endpoint, clue, or flag candidate")
        state.setdefault("attempts", []).append(
            {"at": _utc_now().isoformat(), "signature": normalized, "progress": progress}
        )
        state["no_progress"] = 0 if meaningful_progress else int(state.get("no_progress", 0)) + 1
        _atomic_json(state_path, state)
        if state["no_progress"] >= int(state.get("max_no_progress", 2)):
            raise BudgetExhausted("no-progress budget exhausted")
        return state


def _candidates(data: bytes, patterns: tuple[bytes, ...]) -> set[bytes]:
    found: set[bytes] = set()
    for pattern in patterns:
        found.update(re.findall(pattern, data))
    return found


def verify_outputs(
    outputs: list[Path], sent: list[Path], patterns: tuple[bytes, ...], strict: bool
) -> dict[str, Any]:
    """Verify attributable candidates once (race) or twice (strict), never echoes."""
    if not outputs:
        raise InvalidInput("at least one output is required")
    try:
        output_data = [path.expanduser().resolve().read_bytes() for path in outputs]
        sent_data = b"\n".join(path.expanduser().resolve().read_bytes() for path in sent)
        per_output = [_candidates(data, patterns) for data in output_data]
    except (OSError, re.error) as exc:
        raise InvalidInput(str(exc)) from exc
    if strict and len(outputs) < 2:
        return {"status": "unverified", "reason": "requires_two_clean_reproductions", "flag": None, "reproductions": 0}
    candidates = set().union(*per_output)
    if not candidates:
        return {
            "status": "unverified",
            "reason": "no_candidate" if not any(per_output) else "candidate_not_reproduced",
            "flag": None,
            "reproductions": 0,
        }
    reproductions = {item: sum(item in found for found in per_output) for item in candidates}
    independent = sorted(
        (
            item
            for item in candidates
            if item not in sent_data and (not strict or reproductions[item] >= 2)
        ),
        key=lambda item: (len(item), item),
    )
    if not independent:
        if strict and any(item not in sent_data for item in candidates):
            return {
                "status": "unverified",
                "reason": "candidate_not_reproduced",
                "flag": None,
                "reproductions": 0,
            }
        return {"status": "unverified", "reason": "candidate_was_user_input", "flag": None, "reproductions": 0}
    return {
        "status": "verified",
        "reason": "reproduced_in_clean_sessions" if strict else "attributable_target_result",
        "flag": independent[0].decode("utf-8", errors="replace"),
        "reproductions": reproductions[independent[0]],
    }
