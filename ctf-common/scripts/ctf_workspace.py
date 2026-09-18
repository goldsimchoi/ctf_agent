"""Collision-safe, category-neutral CTF session helpers."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import stat
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
    raw = path.expanduser().absolute()
    _reject_symlink_components(raw)
    if not raw.is_dir():
        raise InvalidInput(f"{description} is not a directory: {raw}")
    return raw


def _reject_symlink_components(path: Path) -> None:
    """Reject a path containing a symlink before using it as a write root."""
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            if current.is_symlink():
                raise InvalidInput(f"symlinked path component: {current}")
        except OSError as exc:
            raise InvalidInput(f"unusable path component: {current}") from exc


def _safe_file(path: Path, description: str) -> Path:
    raw = path.expanduser().absolute()
    _reject_symlink_components(raw)
    try:
        mode = raw.stat().st_mode
    except OSError as exc:
        raise InvalidInput(f"{description} is not readable: {raw}") from exc
    if not stat.S_ISREG(mode):
        raise InvalidInput(f"{description} is not a regular file: {raw}")
    return raw


def _open_directory_nofollow(path: Path) -> int:
    """Open every directory component through directory FDs without following links."""
    raw = _resolve_directory(path, "workspace directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(raw.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in raw.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _safe_directory(root: Path, *parts: str) -> Path:
    """Create/check directory components without following a symlink component."""
    current = _resolve_directory(root, "workspace root")
    descriptor = _open_directory_nofollow(current)
    try:
        for part in parts:
            _validate_explicit_id(part)
            candidate = current / part
            try:
                os.mkdir(part, dir_fd=descriptor)
            except FileExistsError:
                pass
            except OSError as exc:
                raise InvalidInput(f"cannot create workspace component: {candidate}") from exc
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            except OSError as exc:
                raise InvalidInput(f"workspace component is not a directory: {candidate}") from exc
            os.close(descriptor)
            descriptor = child
            current = candidate
    finally:
        os.close(descriptor)
    return current


def _create_session_directory(sessions: Path, identifier: str) -> Path:
    _reject_symlink_components(sessions)
    if not sessions.is_dir():
        raise InvalidInput(f"sessions path is not a directory: {sessions}")
    destination = sessions / identifier
    descriptor = _open_directory_nofollow(sessions)
    try:
        os.mkdir(identifier, dir_fd=descriptor)
    except FileExistsError as exc:
        raise CollisionError(f"session already exists: {destination}") from exc
    finally:
        os.close(descriptor)
    _reject_symlink_components(destination)
    return destination


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


def _atomic_replace(path: Path, content: bytes) -> None:
    """Atomically replace a file through a no-follow directory descriptor."""
    descriptor = _open_directory_nofollow(path.parent)
    temporary = f".{path.name}.{secrets.token_hex(8)}.tmp"
    try:
        file_descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=descriptor,
        )
        with os.fdopen(file_descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(descriptor)


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    _atomic_replace(
        path,
        (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
    )


def _atomic_text(path: Path, content: str) -> None:
    _atomic_replace(path, content.encode("utf-8"))


def _write_new_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically publish a new file without allowing a replacement."""
    _write_new_bytes(
        path,
        (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"),
    )


def _write_new_bytes(path: Path, content: bytes) -> None:
    """Atomically publish immutable binary evidence without replacement."""
    descriptor = _open_directory_nofollow(path.parent)
    temporary = f".{path.name}.{secrets.token_hex(8)}.tmp"
    try:
        file_descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=descriptor,
        )
        with os.fdopen(file_descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path.name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
    except FileExistsError:
        raise
    finally:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        os.close(descriptor)


def _json_path(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(_safe_file(path, "JSON file").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InvalidInput(f"invalid state file: {path}") from exc
    if not isinstance(payload, dict):
        raise InvalidInput(f"invalid state file: {path}")
    return payload


def _workspace_root(workspace: Path) -> tuple[Path, Path]:
    workspace = _resolve_directory(workspace, "workspace")
    if workspace.parent.name != "sessions" or not (workspace / "state.json").is_file():
        raise InvalidInput(f"not a session workspace: {workspace}")
    common_root = workspace.parent.parent
    category_root = common_root.parent
    runs_root = category_root.parent
    if category_root.name not in CATEGORIES or runs_root.name != "runs":
        raise InvalidInput(f"not a canonical session workspace: {workspace}")
    session = _json_path(workspace / "session.json")
    expected = {
        "workspace": str(workspace),
        "session_id": workspace.name,
        "category": category_root.name,
        "event_root": str(runs_root.parent),
    }
    if any(session.get(key) != value for key, value in expected.items()):
        raise InvalidInput(f"session identity does not match workspace path: {workspace}")
    return workspace, common_root


def _finding_paths(common_root: Path) -> tuple[list[Path], dict[str, Any]]:
    root = common_root / "shared" / "findings"
    if not root.is_dir():
        return [], {"count": 0, "reasons": {}}
    findings: list[Path] = []
    reasons: dict[str, int] = {}

    def skip(reason: str) -> None:
        reasons[reason] = reasons.get(reason, 0) + 1

    for path in sorted(root.glob("*/*.json")):
        try:
            payload = json.loads(_safe_file(path, "finding record").read_text(encoding="utf-8"))
        except (InvalidInput, OSError, json.JSONDecodeError):
            skip("malformed_record")
            continue
        required = {"schema_version", "created_at", "evidence", "evidence_sha256", "kind", "session_id", "summary"}
        if (
            not isinstance(payload, dict)
            or not required.issubset(payload)
            or payload.get("schema_version") != 1
        ):
            skip("malformed_record")
            continue
        owner = path.parent
        if not isinstance(payload["session_id"], str) or payload["session_id"] != owner.name:
            skip("invalid_finding_owner")
            continue
        try:
            _workspace_root(common_root / "sessions" / owner.name)
        except InvalidInput:
            skip("invalid_finding_owner")
            continue
        try:
            evidence = _safe_file(Path(str(payload["evidence"])), "finding evidence")
        except InvalidInput:
            skip("evidence_missing")
            continue
        if not _under(evidence, owner):
            skip("evidence_outside_finding")
            continue
        if not isinstance(payload["evidence_sha256"], str) or hashlib.sha256(evidence.read_bytes()).hexdigest() != payload["evidence_sha256"]:
            skip("evidence_digest_mismatch")
            continue
        findings.append(path)
    return findings, {"count": sum(reasons.values()), "reasons": reasons}


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
    common_root = _safe_directory(root, "runs", category, f"{slug}-{fingerprint[:12]}")
    sessions = _safe_directory(common_root, "sessions")
    _safe_directory(common_root, "shared", "findings")

    explicit = session_id is not None
    for _ in range(16):
        identifier = _validate_explicit_id(session_id) if explicit else new_session_id(category)
        try:
            workspace = _create_session_directory(sessions, identifier)
        except CollisionError:
            if explicit:
                raise
            continue
        break
    else:
        raise CollisionError("could not allocate a unique session ID")

    try:
        for name in ("artifacts", "logs", "transcripts"):
            _safe_directory(workspace, name)
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
            "workspace": str(workspace),
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

    findings, skipped_findings = _finding_paths(common_root)
    return {
        "workspace": workspace,
        "category": category,
        "challenge_id": slug,
        "fingerprint": fingerprint,
        "session_id": identifier,
        "findings": findings,
        "skipped_findings": skipped_findings,
    }


def publish_finding(workspace: Path, kind: str, evidence: Path, summary: str) -> Path:
    """Publish immutable evidence visible to later sessions in this category."""
    workspace, common_root = _workspace_root(workspace)
    kind = _validate_explicit_id(kind)
    if not summary.strip():
        raise InvalidInput("finding summary must not be empty")
    evidence = _safe_file(evidence, "finding evidence")
    if not _under(evidence, workspace):
        raise InvalidInput("finding evidence must be a file inside its workspace")
    destination = _safe_directory(common_root, "shared", "findings", workspace.name)
    content = evidence.read_bytes()
    for _ in range(16):
        stem = f"{_timestamp()}-{secrets.token_hex(4)}"
        evidence_path = destination / f"{stem}-{safe_slug(evidence.name)}"
        try:
            _write_new_bytes(evidence_path, content)
        except FileExistsError:
            continue
        payload = {
            "schema_version": 1,
            "created_at": _utc_now().isoformat(),
            "evidence": str(evidence_path),
            "evidence_sha256": hashlib.sha256(content).hexdigest(),
            "kind": kind,
            "session_id": workspace.name,
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


def _candidate_only(reason: str, candidates: set[bytes]) -> dict[str, Any]:
    candidate = min(candidates, key=lambda item: (len(item), item)) if candidates else None
    return {
        "status": "candidate_only",
        "reason": reason,
        "candidate": candidate.decode("utf-8", errors="replace") if candidate else None,
        "flag": None,
        "reproductions": 0,
    }


def _validate_capture_attestations(
    workspace: Path | None,
    outputs: list[Path],
    sent: list[Path],
    attestations: list[dict[str, Any]] | None,
) -> tuple[list[Path], list[Path], str | None]:
    """Validate capture provenance before a candidate can become a flag."""
    if workspace is None or attestations is None:
        return [], [], "missing_capture_attestation"
    try:
        workspace, _ = _workspace_root(workspace)
        session = _json_path(workspace / "session.json")
    except InvalidInput:
        return [], [], "invalid_capture_attestation"
    if not sent:
        return [], [], "missing_sent_evidence"
    if len(outputs) != len(attestations):
        return [], [], "invalid_capture_attestation"
    try:
        safe_sent = [_safe_file(path, "sent evidence") for path in sent]
        safe_outputs = [_safe_file(path, "capture output") for path in outputs]
    except InvalidInput:
        return [], [], "invalid_capture_attestation"
    if any(not _under(path, workspace) for path in safe_sent + safe_outputs):
        return [], [], "invalid_capture_attestation"
    sent_by_path = {str(path): path for path in safe_sent}
    seen_paths: set[str] = set()
    seen_ids: set[str] = set()
    seen_attestations: set[str] = set()
    source_targets: set[str] = set()
    for output, attestation in zip(safe_outputs, attestations, strict=True):
        if not isinstance(attestation, dict):
            return [], [], "invalid_capture_attestation"
        try:
            capture_id = _validate_explicit_id(str(attestation["capture_id"]))
            output_record = attestation["output"]
            sent_record = attestation["sent"]
            if not isinstance(output_record, dict) or not isinstance(sent_record, dict):
                raise InvalidInput("capture record must describe output and sent evidence")
            target = attestation["source_target"]
            if not isinstance(target, str) or not target.strip():
                raise InvalidInput("capture attestation needs source target")
            if (
                attestation.get("schema_version") != 1
                or attestation.get("workspace") != str(workspace)
                or attestation.get("session_id") != session["session_id"]
                or attestation.get("category") != session["category"]
                or output_record.get("path") != str(output)
                or output_record.get("sha256") != hashlib.sha256(output.read_bytes()).hexdigest()
            ):
                raise InvalidInput("capture attestation does not match output")
            sent_path = _safe_file(Path(str(sent_record["path"])), "attested sent evidence")
            if (
                str(sent_path) not in sent_by_path
                or not _under(sent_path, workspace)
                or sent_record.get("sha256") != hashlib.sha256(sent_path.read_bytes()).hexdigest()
            ):
                raise InvalidInput("capture attestation does not match sent evidence")
        except (InvalidInput, KeyError, TypeError):
            return [], [], "invalid_capture_attestation"
        attestation_key = json.dumps(attestation, sort_keys=True, separators=(",", ":"))
        if str(output) in seen_paths or capture_id in seen_ids or attestation_key in seen_attestations:
            return [], [], "duplicate_capture_attestation"
        seen_paths.add(str(output))
        seen_ids.add(capture_id)
        seen_attestations.add(attestation_key)
        source_targets.add(target.strip())
    if len(source_targets) != 1:
        return [], [], "capture_source_target_mismatch"
    return safe_outputs, safe_sent, None


def verify_outputs(
    outputs: list[Path],
    sent: list[Path],
    patterns: tuple[bytes, ...],
    strict: bool,
    workspace: Path | None = None,
    attestations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Verify attested target captures once (race) or twice (strict), never echoes."""
    if not outputs:
        raise InvalidInput("at least one output is required")
    try:
        output_data = [_safe_file(path, "output").read_bytes() for path in outputs]
        per_output = [_candidates(data, patterns) for data in output_data]
    except (OSError, re.error) as exc:
        raise InvalidInput(str(exc)) from exc
    candidates = set().union(*per_output)
    safe_outputs, safe_sent, attestation_error = _validate_capture_attestations(
        workspace, outputs, sent, attestations
    )
    if attestation_error:
        return _candidate_only(attestation_error, candidates)
    sent_data = b"\n".join(path.read_bytes() for path in safe_sent)
    if strict and len(outputs) < 2:
        return {"status": "unverified", "reason": "requires_two_clean_reproductions", "flag": None, "reproductions": 0}
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
