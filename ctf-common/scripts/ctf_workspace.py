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
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from ctf_intake import (
    IntakeRequest,
    render_resolved_manifest,
    resolve_intake,
)


CATEGORIES = {"pwn", "web", "rev"}
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_VERIFICATION_ARTIFACTS = 16
MAX_VERIFICATION_BYTES = 8 * 1024 * 1024
MAX_SUPPLIED_MEMBER_BYTES = 32 * 1024 * 1024
MAX_SUPPLIED_SCAN_BYTES = 256 * 1024 * 1024
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


class ArtifactTooLarge(InvalidInput):
    """Raised when an artifact exceeds the bounded common-reader contract."""


class VerificationBudgetExceeded(InvalidInput):
    """Raised when a verification request exceeds its aggregate read budget."""


class JsonArgumentParser(argparse.ArgumentParser):
    """Turn invalid command-line input into a caller-owned JSON error."""

    def error(self, message: str) -> None:
        raise InvalidInput(message)


@dataclass(frozen=True)
class OpenedArtifact:
    path: Path
    data: bytes
    device: int
    inode: int


class VerificationReadBudget:
    """Bound and reuse descriptor-read bytes for one verification request."""

    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self.total = 0
        self._data_by_identity: dict[tuple[int, int], bytes] = {}

    def cached(self, device: int, inode: int) -> bytes | None:
        return self._data_by_identity.get((device, inode))

    def remaining(self) -> int:
        return self.maximum - self.total

    def store(self, device: int, inode: int, data: bytes) -> None:
        identity = (device, inode)
        if identity in self._data_by_identity:
            return
        if len(data) > self.remaining():
            raise VerificationBudgetExceeded("verification request exceeds aggregate artifact budget")
        self._data_by_identity[identity] = data
        self.total += len(data)


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
    if ".." in raw.parts:
        raise InvalidInput(f"{description} path must not contain traversal components: {raw}")
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
    descriptor: int | None = None
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


def _read_regular_under(
    root: Path,
    path: Path,
    description: str,
    budget: VerificationReadBudget | None = None,
) -> OpenedArtifact:
    """Read one contained regular file via no-follow directory descriptors."""
    root = _resolve_directory(root, "artifact root")
    raw = path.expanduser().absolute()
    if not _under(raw, root):
        raise InvalidInput(f"{description} is outside artifact root: {raw}")
    parts = raw.relative_to(root).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise InvalidInput(f"invalid {description} path: {raw}")
    descriptor = _open_directory_nofollow(root)
    file_descriptor: int | None = None
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file_descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=descriptor
        )
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InvalidInput(f"{description} is not a regular file: {raw}")
        if metadata.st_size > MAX_ARTIFACT_BYTES:
            raise ArtifactTooLarge(f"{description} exceeds {MAX_ARTIFACT_BYTES} bytes: {raw}")
        if budget is not None:
            cached = budget.cached(metadata.st_dev, metadata.st_ino)
            if cached is not None:
                return OpenedArtifact(raw, cached, metadata.st_dev, metadata.st_ino)
            if metadata.st_size > budget.remaining():
                raise VerificationBudgetExceeded("verification request exceeds aggregate artifact budget")
        chunks: list[bytes] = []
        total = 0
        while block := os.read(file_descriptor, 1024 * 1024):
            total += len(block)
            if total > MAX_ARTIFACT_BYTES:
                raise ArtifactTooLarge(f"{description} exceeds {MAX_ARTIFACT_BYTES} bytes: {raw}")
            if budget is not None and total > budget.remaining():
                raise VerificationBudgetExceeded("verification request exceeds aggregate artifact budget")
            chunks.append(block)
        data = b"".join(chunks)
        if budget is not None:
            budget.store(metadata.st_dev, metadata.st_ino, data)
        return OpenedArtifact(raw, data, metadata.st_dev, metadata.st_ino)
    except OSError as exc:
        raise InvalidInput(f"{description} is unreadable: {raw}") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        os.close(descriptor)


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
    if ".." in path.parts or ".." in root.parts:
        return False
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
    if challenge == root:
        raise InvalidInput(f"challenge must be below event root: {root}")
    if not _under(challenge, root):
        raise InvalidInput(f"challenge is outside event root: {challenge}")
    return root


def _quoted_manifest_scalar(value: str, line_number: int) -> str:
    if value.startswith('"'):
        try:
            parsed, end = json.JSONDecoder().raw_decode(value)
        except json.JSONDecodeError as exc:
            raise InvalidInput(
                f"invalid double-quoted manifest scalar on line {line_number}"
            ) from exc
        if not isinstance(parsed, str):
            raise InvalidInput(f"manifest scalar must be a string on line {line_number}")
    else:
        characters: list[str] = []
        index = 1
        end = -1
        while index < len(value):
            if value[index] != "'":
                characters.append(value[index])
                index += 1
                continue
            if index + 1 < len(value) and value[index + 1] == "'":
                characters.append("'")
                index += 2
                continue
            end = index + 1
            break
        if end < 0:
            raise InvalidInput(
                f"unterminated single-quoted manifest scalar on line {line_number}"
            )
        parsed = "".join(characters)
    remainder = value[end:]
    if remainder.strip() and not (
        remainder[0] in " \t" and remainder.lstrip().startswith("#")
    ):
        raise InvalidInput(f"unsupported manifest syntax on line {line_number}")
    return parsed


def _plain_manifest_scalar(value: str, line_number: int) -> str:
    comment_at: int | None = None
    for index, character in enumerate(value):
        if character == "#" and (index == 0 or value[index - 1].isspace()):
            comment_at = index
            break
    scalar = value[:comment_at].rstrip() if comment_at is not None else value.rstrip()
    if not scalar:
        raise InvalidInput(f"manifest value is missing on line {line_number}")
    if scalar.startswith(("[", "{", "|", ">", "&", "*", "!", "%", "@", "`")):
        raise InvalidInput(f"unsupported manifest structure on line {line_number}")
    if re.search(r":\s", scalar):
        raise InvalidInput(f"unsupported manifest mapping on line {line_number}")
    return scalar


def _parse_manifest_scalars(content: bytes) -> dict[str, str]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidInput("legacy manifest is not valid UTF-8") from exc
    values: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0].isspace():
            raise InvalidInput(f"nested manifest structure on line {line_number}")
        match = re.fullmatch(r"([A-Za-z][A-Za-z0-9_-]*):[ \t]*(.*)", line)
        if match is None:
            raise InvalidInput(f"unsupported manifest syntax on line {line_number}")
        key, encoded = match.groups()
        if key in values:
            raise InvalidInput(f"duplicate manifest key on line {line_number}: {key}")
        if encoded.startswith(("'", '"')):
            value = _quoted_manifest_scalar(encoded, line_number)
        else:
            value = _plain_manifest_scalar(encoded, line_number)
        values[key] = value
    return values


def _manifest_scalars(challenge: Path) -> dict[str, str]:
    content: bytes | None = None
    descriptor = _open_directory_nofollow(challenge)
    try:
        for name in ("challenge.yaml", "challenge.yml"):
            file_descriptor: int | None = None
            try:
                file_descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise InvalidInput(
                    f"legacy manifest is unreadable: {challenge / name}"
                ) from exc
            try:
                metadata = os.fstat(file_descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise InvalidInput(
                        f"legacy manifest is not a regular file: {challenge / name}"
                    )
                if metadata.st_size > MAX_MANIFEST_BYTES:
                    raise InvalidInput(f"legacy manifest exceeds {MAX_MANIFEST_BYTES} bytes")
                chunks: list[bytes] = []
                total = 0
                while block := os.read(
                    file_descriptor, min(64 * 1024, MAX_MANIFEST_BYTES - total + 1)
                ):
                    total += len(block)
                    if total > MAX_MANIFEST_BYTES:
                        raise InvalidInput(f"legacy manifest exceeds {MAX_MANIFEST_BYTES} bytes")
                    chunks.append(block)
                content = b"".join(chunks)
            except OSError as exc:
                raise InvalidInput(f"legacy manifest is unreadable: {challenge / name}") from exc
            finally:
                os.close(file_descriptor)
            break
    finally:
        os.close(descriptor)
    if content is None:
        return {}
    return _parse_manifest_scalars(content)


def _validate_selected_binary(challenge: Path, value: str) -> str:
    """Bind a challenge-relative regular file without following or reading it."""
    relative = Path(value)
    if relative.is_absolute() or not relative.parts:
        raise InvalidInput("binary must be a challenge-relative path")
    parts = relative.parts
    if any(part in {"", ".", ".."} for part in parts):
        raise InvalidInput("binary path must not contain dot components")
    descriptor = _open_directory_nofollow(challenge)
    file_descriptor: int | None = None
    try:
        for part in parts[:-1]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK
        file_descriptor = os.open(parts[-1], flags, dir_fd=descriptor)
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InvalidInput(f"binary is not a regular file: {value}")
    except OSError as exc:
        raise InvalidInput(f"binary is not a contained regular file: {value}") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        os.close(descriptor)
    return Path(*parts).as_posix()


def challenge_fingerprint(challenge: Path) -> str:
    """Hash versioned name/content-digest records through no-follow descriptors."""
    records: list[tuple[bytes, bytes]] = []

    def visit(directory: int, prefix: Path) -> None:
        for name in sorted(os.listdir(directory)):
            relative = prefix / name
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=directory,
                )
                try:
                    visit(child, relative)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise InvalidInput(f"challenge artifact is not a regular file: {relative}")
            descriptor = os.open(
                name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory,
            )
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise InvalidInput(f"challenge artifact is not a regular file: {relative}")
                content = hashlib.sha256()
                while block := os.read(descriptor, 1024 * 1024):
                    content.update(block)
                records.append((os.fsencode(relative.as_posix()), content.digest()))
            finally:
                os.close(descriptor)

    descriptor: int | None = None
    try:
        descriptor = _open_directory_nofollow(challenge)
        visit(descriptor, Path())
    except OSError as exc:
        raise InvalidInput(f"challenge artifact is unreadable: {challenge}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    # Each record has one length-prefixed name and one fixed-width SHA-256.
    digest = hashlib.sha256(b"ctf-challenge-fingerprint-v2\0")
    for relative, content_digest in sorted(records):
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(content_digest)
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
    descriptor: int | None = None
    try:
        descriptor = _open_directory_nofollow(root)
        owners = sorted(os.listdir(descriptor))
    except InvalidInput:
        return [], {"count": 0, "reasons": {}}
    finally:
        if descriptor is not None:
            os.close(descriptor)
    findings: list[Path] = []
    reasons: dict[str, int] = {}

    def skip(reason: str) -> None:
        reasons[reason] = reasons.get(reason, 0) + 1

    for owner_name in owners:
        owner = root / owner_name
        owner_fd: int | None = None
        try:
            owner_fd = _open_directory_nofollow(owner)
            records = sorted(name for name in os.listdir(owner_fd) if name.endswith(".json"))
        except (InvalidInput, OSError):
            skip("malformed_record")
            continue
        finally:
            if owner_fd is not None:
                os.close(owner_fd)
        for record_name in records:
            path = owner / record_name
            try:
                record = _read_regular_under(root, path, "finding record")
                payload = json.loads(record.data.decode("utf-8"))
            except ArtifactTooLarge:
                skip("oversized_record")
                continue
            except (UnicodeDecodeError, InvalidInput, json.JSONDecodeError):
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
            if not isinstance(payload["session_id"], str) or payload["session_id"] != owner_name:
                skip("invalid_finding_owner")
                continue
            try:
                _workspace_root(common_root / "sessions" / owner_name)
            except InvalidInput:
                skip("invalid_finding_owner")
                continue
            try:
                evidence_path = Path(str(payload["evidence"])).expanduser().absolute()
                if not _under(evidence_path, owner):
                    skip("evidence_outside_finding")
                    continue
                evidence = _read_regular_under(owner, evidence_path, "finding evidence")
            except ArtifactTooLarge:
                skip("evidence_oversized")
                continue
            except InvalidInput:
                skip("evidence_missing")
                continue
            if not isinstance(payload["evidence_sha256"], str) or hashlib.sha256(evidence.data).hexdigest() != payload["evidence_sha256"]:
                skip("evidence_digest_mismatch")
                continue
            findings.append(path)
    return findings, {"count": sum(reasons.values()), "reasons": reasons}


def create_session(
    challenge: Path,
    category: str,
    event_root: Path | None = None,
    session_id: str | None = None,
    *,
    intake: IntakeRequest | None = None,
) -> dict[str, Any]:
    """Create one isolated workspace and return its resolved metadata."""
    if category not in CATEGORIES:
        raise InvalidInput(f"unsupported category: {category!r}")
    challenge = _resolve_directory(challenge, "challenge")
    root = _event_root_for(challenge, event_root)
    manifest = _manifest_scalars(challenge)
    slug = safe_slug(manifest.get("id", challenge.name))
    resolved_intake = resolve_intake(category, intake or IntakeRequest(), manifest)
    effective_manifest = resolved_intake["manifest"]
    if "binary" in effective_manifest:
        effective_manifest["binary"] = _validate_selected_binary(
            challenge, effective_manifest["binary"]
        )
    file_fingerprint = challenge_fingerprint(challenge)
    fingerprint_fields = {
        "category": category,
        "statement": resolved_intake["statement"],
        "normalized": resolved_intake["normalized"],
        "binary": effective_manifest.get("binary"),
        "flag_pattern": effective_manifest.get("flag_pattern"),
        "manifest": effective_manifest,
    }
    intake_bytes = json.dumps(
        fingerprint_fields,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    fingerprint = hashlib.sha256(
        bytes.fromhex(file_fingerprint) + intake_bytes
    ).hexdigest()
    request_record = dict(resolved_intake)
    request_record["file_fingerprint"] = file_fingerprint
    request_record["fingerprint"] = fingerprint
    rendered_manifest = render_resolved_manifest(slug, category, resolved_intake)
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
            wall_time = int(effective_manifest.get("wall_time_seconds", "0"))
        except ValueError as exc:
            raise InvalidInput("wall_time_seconds must be an integer") from exc
        if wall_time < 0:
            raise InvalidInput("wall_time_seconds must be non-negative")
        session = {
            "schema_version": 1,
            "category": category,
            "challenge": str(challenge),
            "event_root": str(root),
            "file_fingerprint": file_fingerprint,
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
        _atomic_json(workspace / "challenge-request.json", request_record)
        _atomic_text(workspace / "challenge.resolved.yaml", rendered_manifest)
        _atomic_json(workspace / "session.json", session)
        _atomic_json(workspace / "state.json", state)
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
        "file_fingerprint": file_fingerprint,
        "fingerprint": fingerprint,
        "session_id": identifier,
        "intake": {
            "source": resolved_intake["source"],
            "target_status": resolved_intake["target_status"],
            "request_path": str((workspace / "challenge-request.json").resolve()),
            "resolved_manifest_path": str(
                (workspace / "challenge.resolved.yaml").resolve()
            ),
        },
        "findings": findings,
        "skipped_findings": skipped_findings,
    }


def publish_finding(workspace: Path, kind: str, evidence: Path, summary: str) -> Path:
    """Publish immutable evidence visible to later sessions in this category."""
    workspace, common_root = _workspace_root(workspace)
    kind = _validate_explicit_id(kind)
    if not summary.strip():
        raise InvalidInput("finding summary must not be empty")
    evidence_snapshot = _read_regular_under(workspace, evidence, "finding evidence")
    destination = _safe_directory(common_root, "shared", "findings", workspace.name)
    content = evidence_snapshot.data
    for _ in range(16):
        stem = f"{_timestamp()}-{secrets.token_hex(4)}"
        evidence_path = destination / f"{stem}-{safe_slug(evidence_snapshot.path.name)}"
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


def publish_capture_attestation(workspace: Path, attestation: dict[str, Any]) -> Path:
    """Atomically publish one adapter-authored capture record for verification."""
    workspace, _ = _workspace_root(workspace)
    if not isinstance(attestation, dict):
        raise InvalidInput("capture attestation must be an object")
    try:
        capture_id = _validate_explicit_id(str(attestation["capture_id"]))
    except (InvalidInput, KeyError, TypeError) as exc:
        raise InvalidInput("capture attestation needs a safe capture_id") from exc
    destination = _safe_directory(workspace, "artifacts", "captures")
    path = destination / f"{capture_id}.json"
    try:
        _write_new_json(path, attestation)
    except FileExistsError as exc:
        raise CollisionError(f"capture attestation already exists: {path}") from exc
    return path


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


def _archive_members(data: bytes) -> Iterator[bytes]:
    """Yield bounded member contents of one zip, tar, or gzip blob."""
    import gzip
    import io
    import tarfile
    import zipfile

    stream = io.BytesIO(data)
    if zipfile.is_zipfile(stream):
        try:
            with zipfile.ZipFile(stream) as archive:
                for info in archive.infolist():
                    if not info.is_dir() and info.file_size <= MAX_SUPPLIED_MEMBER_BYTES:
                        try:
                            yield archive.read(info)
                        except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError):
                            continue
        except zipfile.BadZipFile:
            pass
        return
    stream.seek(0)
    try:
        with tarfile.open(fileobj=stream, mode="r:*") as archive:
            for member in archive:
                if member.isfile() and member.size <= MAX_SUPPLIED_MEMBER_BYTES:
                    extracted = archive.extractfile(member)
                    if extracted is not None:
                        yield extracted.read()
        return
    except (tarfile.TarError, OSError, EOFError):
        pass
    if data[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as single:
                yield single.read(MAX_SUPPLIED_MEMBER_BYTES)
        except (OSError, EOFError):
            pass


def supplied_candidates(challenge: Path, patterns: tuple[bytes, ...]) -> set[bytes]:
    """Collect flag-shaped strings already present in the supplied challenge files.

    A placeholder flag shipped with source or a Dockerfile is never a solve, so
    any candidate found here, including inside one level of nested archives, is
    rejected by verification.
    """
    found: set[bytes] = set()
    budget = [MAX_SUPPLIED_SCAN_BYTES]

    def scan(data: bytes, depth: int) -> None:
        if budget[0] <= 0:
            return
        budget[0] -= len(data)
        found.update(_candidates(data, patterns))
        if depth < 2:
            for member in _archive_members(data):
                scan(member, depth + 1)

    try:
        root = _resolve_directory(challenge, "challenge")
    except InvalidInput:
        return found
    for path in sorted(root.rglob("*")):
        if budget[0] <= 0:
            break
        try:
            if path.is_symlink() or not path.is_file():
                continue
            if path.stat().st_size > MAX_SUPPLIED_MEMBER_BYTES:
                continue
            scan(path.read_bytes(), 0)
        except OSError:
            continue
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
    attestations: list[Path] | None,
) -> tuple[list[OpenedArtifact], list[OpenedArtifact], str | None]:
    """Validate capture provenance before a candidate can become a flag."""
    if (
        len(outputs) > MAX_VERIFICATION_ARTIFACTS
        or len(sent) > MAX_VERIFICATION_ARTIFACTS
        or (attestations is not None and len(attestations) > MAX_VERIFICATION_ARTIFACTS)
    ):
        return [], [], "verification_request_exceeds_budget"
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
    budget = VerificationReadBudget(MAX_VERIFICATION_BYTES)
    try:
        safe_sent = [_read_regular_under(workspace, path, "sent evidence", budget) for path in sent]
        safe_outputs = [_read_regular_under(workspace, path, "capture output", budget) for path in outputs]
    except VerificationBudgetExceeded:
        return [], [], "verification_request_exceeds_budget"
    except InvalidInput:
        return [], [], "invalid_capture_attestation"
    sent_by_path = {str(item.path): item for item in safe_sent}
    seen_paths: set[str] = set()
    seen_output_files: set[tuple[int, int]] = set()
    seen_ids: set[str] = set()
    seen_records: set[tuple[int, int]] = set()
    source_targets: set[str] = set()
    capture_root = workspace / "artifacts" / "captures"
    for output, attestation_path in zip(safe_outputs, attestations, strict=True):
        try:
            record = _read_regular_under(capture_root, attestation_path, "capture attestation", budget)
            if record.path.parent != capture_root or record.path.suffix != ".json":
                raise InvalidInput("capture attestation is not a capture artifact")
            attestation = json.loads(record.data.decode("utf-8"))
            if not isinstance(attestation, dict):
                raise InvalidInput("capture attestation must be an object")
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
                or record.path.name != f"{capture_id}.json"
                or output_record.get("path") != str(output.path)
                or output_record.get("sha256") != hashlib.sha256(output.data).hexdigest()
            ):
                raise InvalidInput("capture attestation does not match output")
            sent_item = sent_by_path.get(str(Path(str(sent_record["path"])).expanduser().absolute()))
            if (
                sent_item is None
                or sent_record.get("sha256") != hashlib.sha256(sent_item.data).hexdigest()
            ):
                raise InvalidInput("capture attestation does not match sent evidence")
        except VerificationBudgetExceeded:
            return safe_outputs, safe_sent, "verification_request_exceeds_budget"
        except (UnicodeDecodeError, InvalidInput, KeyError, TypeError, json.JSONDecodeError):
            return safe_outputs, safe_sent, "invalid_capture_attestation"
        relative_output = str(output.path.relative_to(workspace))
        output_identity = (output.device, output.inode)
        record_identity = (record.device, record.inode)
        if (
            relative_output in seen_paths
            or output_identity in seen_output_files
            or capture_id in seen_ids
            or record_identity in seen_records
        ):
            return [], [], "duplicate_capture_attestation"
        seen_paths.add(relative_output)
        seen_output_files.add(output_identity)
        seen_ids.add(capture_id)
        seen_records.add(record_identity)
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
    attestations: list[Path] | None = None,
    excluded: set[bytes] | None = None,
    reject_supplied: bool = False,
) -> dict[str, Any]:
    """Verify attested target captures once (race) or twice (strict), never echoes."""
    if not outputs:
        raise InvalidInput("at least one output is required")
    safe_outputs, safe_sent, attestation_error = _validate_capture_attestations(
        workspace, outputs, sent, attestations
    )
    try:
        per_output = [_candidates(item.data, patterns) for item in safe_outputs]
    except re.error as exc:
        raise InvalidInput(str(exc)) from exc
    candidates = set().union(*per_output)
    if attestation_error:
        return _candidate_only(attestation_error, candidates)
    sent_data = b"\n".join(item.data for item in safe_sent)
    if strict and len(safe_outputs) < 2:
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
    # Placeholders shipped with the challenge or seen in a local lab are not solves.
    # Reversing flags legitimately live inside the supplied binary, so callers opt in.
    supplied: set[bytes] = set()
    if reject_supplied and workspace is not None:
        try:
            session = _json_path(_workspace_root(workspace)[0] / "session.json")
            supplied = supplied_candidates(Path(str(session["challenge"])), patterns)
        except (InvalidInput, KeyError, TypeError):
            supplied = set()
    lab = excluded or set()
    remaining = [item for item in independent if item not in supplied and item not in lab]
    if not remaining:
        rejected = independent[0]
        return {
            "status": "unverified",
            "reason": "candidate_in_supplied_files" if rejected in supplied else "candidate_matches_lab_flag",
            "candidate": rejected.decode("utf-8", errors="replace"),
            "flag": None,
            "reproductions": 0,
        }
    independent = remaining
    return {
        "status": "verified",
        "reason": "reproduced_in_clean_sessions" if strict else "attributable_target_result",
        "flag": independent[0].decode("utf-8", errors="replace"),
        "reproductions": reproductions[independent[0]],
    }
