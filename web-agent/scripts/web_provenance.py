"""Validate session-local HTTP artifacts captured by the web request helper."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from init_web_state import WebStateError, session_workspace


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise WebStateError("origin must be an exact http(s) origin")
    return f"{parsed.scheme}://{parsed.netloc}".lower()


def _url_origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise WebStateError("recorded request URL has no http(s) origin")
    return f"{parsed.scheme}://{parsed.netloc}".lower()


def manifest_origin(workspace: Path) -> str:
    workspace = session_workspace(workspace)
    values: dict[str, str] = {}
    try:
        lines = (workspace / "challenge.resolved.yaml").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise WebStateError("web session has no resolved manifest") from exc
    for line in lines:
        if ":" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip().strip("'\"")
    if values.get("authorized", "").lower() != "true":
        raise WebStateError("manifest does not authorize target traffic")
    if values.get("network_access") != "agent_allowed":
        raise WebStateError("manifest does not allow agent network access")
    if not values.get("origin"):
        raise WebStateError("manifest requires an exact origin")
    return _origin(values["origin"])


def atomic_json(path: Path, payload: dict) -> None:
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


def validate_response_provenance(workspace: Path, evidence: Path) -> dict:
    """Return the recorded provenance for one unchanged captured response body."""
    workspace = session_workspace(workspace)
    origin = manifest_origin(workspace)
    responses = workspace / "web" / "responses"
    requests = workspace / "web" / "requests"
    evidence = evidence.expanduser().resolve()
    if not evidence.is_file() or evidence.parent != responses.resolve() or evidence.suffix != ".raw":
        raise WebStateError("evidence must be a recorded raw response in this web session")
    matches: list[dict] = []
    for path in (workspace / "web" / "provenance").glob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and payload.get("response") == str(evidence):
            matches.append(payload)
    if len(matches) != 1:
        raise WebStateError("response has no unique recorded web provenance")
    record = matches[0]
    request = Path(str(record.get("request", ""))).expanduser().resolve()
    if (
        record.get("kind") != "web-http-response-v1"
        or record.get("authorized") is not True
        or record.get("authorized_origin") != origin
        or not request.is_file()
        or request.parent != requests.resolve()
        or record.get("response_sha256") != _digest(evidence)
        or record.get("request_sha256") != _digest(request)
        or _url_origin(str(record.get("request_url", ""))) != origin
    ):
        raise WebStateError("response provenance is invalid for this authorized web session")
    return record
