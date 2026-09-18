"""Validate session-local HTTP artifacts captured by the web request helper."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import sys
import tempfile
import zlib
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

from init_web_state import WebStateError, session_workspace


COMMON_SCRIPTS = Path(__file__).resolve().parents[2] / "ctf-common" / "scripts"
sys.path.insert(0, str(COMMON_SCRIPTS))
from ctf_workspace import MAX_ARTIFACT_BYTES, InvalidInput, _read_regular_under  # noqa: E402


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


def atomic_bytes(path: Path, payload: bytes) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def decode_entity_body(body: bytes, encoding: str | None) -> bytes | None:
    try:
        normalized = (encoding or "").lower()
        if normalized == "gzip":
            decoded = gzip.decompress(body)
        elif normalized == "deflate":
            decoded = zlib.decompress(body)
        elif normalized in {"", "identity"}:
            decoded = body
        else:
            return None
    except (OSError, zlib.error):
        return None
    return decoded if len(decoded) <= MAX_ARTIFACT_BYTES else None


def prepared_sent_evidence(prepared_bytes: bytes) -> bytes:
    """Keep prepared bytes and bounded semantic echo values for supported inputs."""
    try:
        prepared = json.loads(prepared_bytes.decode("utf-8"))
        headers = prepared.get("headers", [])
        body = base64.b64decode(prepared.get("body_base64", ""), validate=True)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebStateError("invalid recorded request evidence") from exc
    url = urlsplit(str(prepared.get("url", "")))
    semantic = [f"path={unquote(url.path)}"]
    semantic.extend(f"query:{name}={value}" for name, value in parse_qsl(url.query, keep_blank_values=True))
    content_type = next((str(value) for name, value in headers if str(name).lower() == "content-type"), "")
    mime = content_type.split(";", 1)[0].strip().lower()
    if mime == "application/x-www-form-urlencoded":
        try:
            form = body.decode("utf-8")
        except UnicodeDecodeError:
            form = ""
        semantic.extend(f"form:{name}={value}" for name, value in parse_qsl(form, keep_blank_values=True))
    elif mime == "application/json":
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None

        def scalars(value: object) -> list[str]:
            if isinstance(value, dict):
                return [item for nested in value.values() for item in scalars(nested)]
            if isinstance(value, list):
                return [item for nested in value for item in scalars(nested)]
            if value is None:
                return ["null"]
            if isinstance(value, (str, int, float, bool)):
                return [str(value)]
            return []

        semantic.extend(f"json:{value}" for value in scalars(payload))
    return b"prepared-record:\n" + prepared_bytes + b"\n\nsemantic-inputs:\n" + "\n".join(semantic).encode("utf-8", errors="replace")


def sent_history(workspace: Path, prepared_paths: list[Path]) -> bytes | None:
    chunks: list[bytes] = []
    try:
        for path in prepared_paths:
            snapshot = _read_regular_under(workspace, path, "prepared request evidence")
            chunks.append(prepared_sent_evidence(snapshot.data))
            if sum(len(item) for item in chunks) > MAX_ARTIFACT_BYTES:
                return None
    except (InvalidInput, WebStateError):
        return None
    return b"\n\n--- request boundary ---\n\n".join(chunks)


def validate_response_provenance(workspace: Path, evidence: Path) -> dict:
    """Return the recorded provenance for one unchanged captured response body."""
    workspace = session_workspace(workspace)
    origin = manifest_origin(workspace)
    responses = workspace / "web" / "responses"
    requests = workspace / "web" / "requests"
    evidence = evidence.expanduser().absolute()
    if evidence.parent != responses.absolute() or evidence.suffix != ".body":
        raise WebStateError("evidence must be a recorded response entity body in this web session")
    provenance_path = workspace / "web" / "provenance" / f"{evidence.stem}.json"
    try:
        record = json.loads(_read_regular_under(workspace, provenance_path, "web provenance").data.decode("utf-8"))
    except (InvalidInput, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebStateError("response has no recorded web provenance") from exc
    if not isinstance(record, dict) or record.get("response_entity_body") != str(evidence):
        raise WebStateError("response has no unique recorded web provenance")
    request = Path(str(record.get("request", ""))).expanduser().absolute()
    capture = record.get("capture")
    if (
        record.get("kind") != "web-http-response-v1"
        or record.get("authorized") is not True
        or record.get("authorized_origin") != origin
        or request.parent != requests.absolute()
        or _url_origin(str(record.get("request_url", ""))) != origin
    ):
        raise WebStateError("response provenance is invalid for this authorized web session")
    try:
        evidence_snapshot = _read_regular_under(workspace, evidence, "response entity body")
        request_snapshot = _read_regular_under(workspace, request, "prepared request evidence")
    except InvalidInput as exc:
        raise WebStateError("response provenance evidence is invalid") from exc
    if (
        record.get("entity_body_sha256") != hashlib.sha256(evidence_snapshot.data).hexdigest()
        or record.get("request_sha256") != hashlib.sha256(request_snapshot.data).hexdigest()
    ):
        raise WebStateError("response provenance is invalid for this authorized web session")
    if not isinstance(capture, dict):
        raise WebStateError("response has no capture-time attestation")
    try:
        output_path = Path(str(capture["output"])).absolute()
        sent_path = Path(str(capture["sent"])).absolute()
        attestation_path = Path(str(capture["attestation"])).absolute()
        if (
            output_path.parent != (workspace / "web" / "captures")
            or sent_path.parent != (workspace / "web" / "captures")
            or attestation_path.parent != (workspace / "artifacts" / "captures")
        ):
            raise InvalidInput("capture artifact path is outside its session location")
        output = _read_regular_under(workspace, output_path, "capture output")
        sent = _read_regular_under(workspace, sent_path, "capture sent evidence")
        attestation = _read_regular_under(workspace, attestation_path, "capture attestation")
    except (InvalidInput, KeyError) as exc:
        raise WebStateError("response capture artifacts are invalid") from exc
    if (
        capture.get("output_sha256") != hashlib.sha256(output.data).hexdigest()
        or capture.get("sent_sha256") != hashlib.sha256(sent.data).hexdigest()
        or capture.get("attestation_sha256") != hashlib.sha256(attestation.data).hexdigest()
    ):
        raise WebStateError("response capture artifacts no longer match provenance")
    return record
