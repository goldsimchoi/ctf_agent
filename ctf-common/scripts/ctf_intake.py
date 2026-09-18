"""Deterministic validation and normalization for common CTF intake."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, BinaryIO, Mapping
from urllib.parse import SplitResult, urlsplit, urlunsplit


MAX_STATEMENT_BYTES = 256 * 1024
MAX_FIELD_BYTES = 4 * 1024
# JSON escaping can expand one valid UTF-8 byte to three wire bytes (for
# example, U+0080 becomes ``\u0080`` under ensure_ascii JSON encoding).
MAX_REQUEST_BYTES = 3 * (MAX_STATEMENT_BYTES + (3 * MAX_FIELD_BYTES)) + 1024
REQUEST_FIELDS = frozenset({"statement", "target", "binary", "flag_pattern"})
CATEGORIES = frozenset({"pwn", "web", "rev"})


class IntakeError(ValueError):
    """Raised when intake cannot be safely and deterministically resolved."""


@dataclass(frozen=True)
class IntakeRequest:
    statement: str = ""
    target: str | None = None
    binary: str | None = None
    flag_pattern: str | None = None


def _validate_text(name: str, value: str, maximum: int, *, multiline: bool) -> str:
    if not isinstance(value, str):
        raise IntakeError(f"{name} must be a string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise IntakeError(f"{name} contains invalid Unicode") from exc
    if len(encoded) > maximum:
        raise IntakeError(f"{name} exceeds {maximum} bytes")
    allowed_controls = {"\t", "\n", "\r"} if multiline else set()
    if any(
        (ord(character) < 32 and character not in allowed_controls)
        or ord(character) == 127
        for character in value
    ):
        raise IntakeError(f"{name} contains a control character")
    return value


def _validate_request(request: IntakeRequest) -> IntakeRequest:
    if not isinstance(request, IntakeRequest):
        raise IntakeError("intake must be an IntakeRequest")
    statement = _validate_text(
        "statement", request.statement, MAX_STATEMENT_BYTES, multiline=True
    )
    fields: dict[str, str | None] = {}
    for name in ("target", "binary", "flag_pattern"):
        value = getattr(request, name)
        fields[name] = (
            None
            if value is None
            else _validate_text(name, value, MAX_FIELD_BYTES, multiline=False)
        )
    return IntakeRequest(statement=statement, **fields)


def read_request_json(stream: BinaryIO) -> IntakeRequest:
    """Read exactly one bounded JSON request object from a binary stream."""
    raw = stream.read(MAX_REQUEST_BYTES + 1)
    if not isinstance(raw, bytes):
        raise IntakeError("request JSON stream must be binary")
    if len(raw) > MAX_REQUEST_BYTES:
        raise IntakeError(f"request JSON exceeds {MAX_REQUEST_BYTES} bytes")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntakeError("request JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise IntakeError("request JSON must be an object")
    unknown = sorted(set(payload) - REQUEST_FIELDS)
    if unknown:
        raise IntakeError(f"request JSON has unknown keys: {', '.join(unknown)}")
    if any(not isinstance(key, str) for key in payload):
        raise IntakeError("request JSON keys must be strings")
    for key, value in payload.items():
        if not isinstance(value, str):
            raise IntakeError(f"request JSON field {key!r} must be a string")
    return _validate_request(IntakeRequest(**payload))


def _render_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _url_port(parts: SplitResult, description: str) -> int | None:
    try:
        return parts.port
    except ValueError as exc:
        raise IntakeError(f"invalid {description} port") from exc


def _normalize_web_target(target: str) -> dict[str, Any]:
    if any(character.isspace() for character in target):
        raise IntakeError("web target must not contain whitespace")
    try:
        parts = urlsplit(target)
    except ValueError as exc:
        raise IntakeError("invalid web target") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise IntakeError("web target must use http or https")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise IntakeError("web target must not contain credentials")
    if "#" in target:
        raise IntakeError("web target must not contain a fragment")
    host = parts.hostname
    if not host:
        raise IntakeError("web target must contain a host")
    host = host.lower()
    port = _url_port(parts, "web target")
    if port is not None and not 1 <= port <= 65535:
        raise IntakeError("web target port is out of range")
    if (scheme, port) in {("http", 80), ("https", 443)}:
        port = None
    rendered_host = _render_host(host)
    netloc = rendered_host if port is None else f"{rendered_host}:{port}"
    origin = urlunsplit((scheme, netloc, "", "", ""))
    start_url = urlunsplit((scheme, netloc, parts.path, parts.query, ""))
    return {"origin": origin, "start_url": start_url}


def _host_and_port(parts: SplitResult, description: str) -> tuple[str, int]:
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise IntakeError(f"{description} must not contain credentials")
    host = parts.hostname
    port = _url_port(parts, description)
    if not host or port is None:
        raise IntakeError(f"{description} must contain one host and port")
    if not 1 <= port <= 65535:
        raise IntakeError(f"{description} port is out of range")
    host = host.lower()
    if any(character.isspace() for character in host):
        raise IntakeError(f"{description} host is invalid")
    return host, port


def _normalize_pwn_target(target: str) -> dict[str, Any]:
    value = target.strip()
    match = re.fullmatch(r"(?i)nc\s+(\S+)\s+(\d+)", value)
    if match:
        host_text, port_text = match.groups()
        if host_text.startswith("[") and host_text.endswith("]"):
            host_text = host_text[1:-1]
        if any(character in host_text for character in "/?#@"):
            raise IntakeError("pwn target host is invalid")
        host, port = host_text.lower(), int(port_text)
        if not host or not 1 <= port <= 65535:
            raise IntakeError("pwn target port is out of range")
    else:
        if value.lower().startswith("tcp://"):
            try:
                parts = urlsplit(value)
            except ValueError as exc:
                raise IntakeError("invalid pwn target") from exc
            if parts.scheme.lower() != "tcp":
                raise IntakeError("pwn target must use tcp")
        else:
            if "://" in value:
                raise IntakeError("pwn target must use tcp")
            try:
                parts = urlsplit(f"//{value}")
            except ValueError as exc:
                raise IntakeError("invalid pwn target") from exc
        if parts.path or "?" in value or "#" in value:
            raise IntakeError("pwn target must not contain a path, query, or fragment")
        host, port = _host_and_port(parts, "pwn target")
    rendered_host = _render_host(host)
    return {
        "host": host,
        "port": port,
        "target": f"tcp://{rendered_host}:{port}",
    }


def _legacy_web_target(legacy: Mapping[str, str]) -> dict[str, Any] | None:
    candidate = legacy.get("start_url") or legacy.get("origin") or legacy.get("target")
    if candidate is None:
        return None
    normalized = _normalize_web_target(candidate)
    if "origin" in legacy:
        declared_origin = _normalize_web_target(legacy["origin"])["origin"]
        if declared_origin != normalized["origin"]:
            raise IntakeError("legacy web origin conflicts with its start URL")
    return normalized


def _legacy_pwn_target(legacy: Mapping[str, str]) -> dict[str, Any] | None:
    if "target" in legacy:
        return _normalize_pwn_target(legacy["target"])
    has_host = "host" in legacy
    has_port = "port" in legacy
    if has_host != has_port:
        raise IntakeError("legacy pwn target needs both host and port")
    if not has_host:
        return None
    if legacy.get("protocol", "tcp").lower() != "tcp":
        raise IntakeError("legacy pwn target must use tcp")
    return _normalize_pwn_target(f"nc {legacy['host']} {legacy['port']}")


def _reject_authorization_conflict(manifest: Mapping[str, str]) -> None:
    if "authorized" in manifest and manifest["authorized"].lower() != "true":
        raise IntakeError("prompt target conflicts with legacy authorization policy")
    if "network_access" in manifest and manifest["network_access"] != "agent_allowed":
        raise IntakeError("prompt target conflicts with legacy network policy")


def _reject_local_authorization_conflict(manifest: Mapping[str, str]) -> None:
    if "authorized" in manifest and manifest["authorized"].lower() != "true":
        raise IntakeError("prompt binary conflicts with legacy authorization policy")


def resolve_intake(
    category: str,
    request: IntakeRequest,
    legacy: Mapping[str, str],
) -> dict[str, Any]:
    """Validate request and legacy scalars into one deterministic intake record."""
    if category not in CATEGORIES:
        raise IntakeError(f"unsupported category: {category!r}")
    request = _validate_request(request)
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in legacy.items()
    ):
        raise IntakeError("legacy manifest values must be strings")
    legacy_values = dict(legacy)
    if "category" in legacy_values and legacy_values["category"] != category:
        raise IntakeError("prompt category conflicts with legacy manifest category")

    prompt_present = bool(
        request.statement
        or request.target is not None
        or request.binary is not None
        or request.flag_pattern is not None
    )
    legacy_present = bool(legacy_values)
    source = (
        "prompt_and_manifest"
        if prompt_present and legacy_present
        else "prompt"
        if prompt_present
        else "legacy_manifest"
        if legacy_present
        else "minimal"
    )

    manifest = dict(legacy_values)
    manifest.pop("statement", None)
    manifest["category"] = category
    manifest.setdefault("mode", "race")
    normalized: dict[str, Any] = {}

    legacy_binary = legacy_values.get("binary")
    if category == "web" and (request.binary is not None or legacy_binary is not None):
        raise IntakeError("web intake does not accept a binary")
    if (
        request.binary is not None
        and legacy_binary is not None
        and request.binary != legacy_binary
    ):
        raise IntakeError("prompt binary conflicts with legacy manifest binary")
    selected_binary = request.binary if request.binary is not None else legacy_binary
    if selected_binary is not None:
        manifest["binary"] = selected_binary

    legacy_pattern = legacy_values.get("flag_pattern")
    if (
        request.flag_pattern is not None
        and legacy_pattern is not None
        and request.flag_pattern != legacy_pattern
    ):
        raise IntakeError("prompt flag pattern conflicts with legacy manifest")
    selected_pattern = (
        request.flag_pattern if request.flag_pattern is not None else legacy_pattern
    )
    if selected_pattern is not None:
        manifest["flag_pattern"] = selected_pattern

    if category == "web":
        legacy_target = _legacy_web_target(legacy_values)
        prompt_target = (
            None if request.target is None else _normalize_web_target(request.target)
        )
        if prompt_target is not None and legacy_target is not None:
            if prompt_target["origin"] != legacy_target["origin"]:
                raise IntakeError("prompt target conflicts with legacy manifest target")
            if (
                {"start_url", "target"}.intersection(legacy_values)
                and prompt_target["start_url"] != legacy_target["start_url"]
            ):
                raise IntakeError("prompt target conflicts with legacy manifest start URL")
        selected_target = prompt_target or legacy_target
        if selected_target is not None:
            normalized.update(selected_target)
            manifest.update(selected_target)
        if prompt_target is not None:
            _reject_authorization_conflict(legacy_values)
            manifest["authorized"] = "true"
            manifest["network_access"] = "agent_allowed"
        target_status = "bound" if selected_target is not None else "needs_selection"
    elif category == "pwn":
        legacy_target = _legacy_pwn_target(legacy_values)
        prompt_target = (
            None if request.target is None else _normalize_pwn_target(request.target)
        )
        if (
            prompt_target is not None
            and legacy_target is not None
            and prompt_target["target"] != legacy_target["target"]
        ):
            raise IntakeError("prompt target conflicts with legacy manifest target")
        selected_target = prompt_target or legacy_target
        if selected_target is not None:
            normalized.update(selected_target)
            manifest.update(
                {
                    "protocol": "tcp",
                    "host": _render_host(selected_target["host"]),
                    "port": str(selected_target["port"]),
                }
            )
        if prompt_target is not None:
            _reject_authorization_conflict(legacy_values)
            manifest["authorized"] = "true"
            manifest["network_access"] = "agent_allowed"
        if request.binary is not None:
            _reject_local_authorization_conflict(legacy_values)
            manifest["authorized"] = "true"
        target_status = (
            "bound"
            if selected_target is not None or selected_binary is not None
            else "local_only"
        )
    else:
        network_keys = {"target", "origin", "start_url", "host", "port", "protocol"}
        if request.target is not None or network_keys.intersection(legacy_values):
            raise IntakeError("rev intake does not accept a network target")
        if request.binary is not None:
            _reject_local_authorization_conflict(legacy_values)
            manifest["authorized"] = "true"
        target_status = "bound" if selected_binary is not None else "needs_selection"

    return {
        "source": source,
        "target_status": target_status,
        "statement": request.statement,
        "target_input": request.target,
        "binary": request.binary,
        "flag_pattern": request.flag_pattern,
        "normalized": normalized,
        "manifest": manifest,
    }


_PLAIN_YAML = re.compile(r"^[A-Za-z0-9_./:@?&=%+\-]+$")
_YAML_AMBIGUOUS = frozenset(
    {"null", "~", "true", "false", "yes", "no", "on", "off", ".nan", ".inf", "-.inf"}
)


def _yaml_scalar(value: str) -> str:
    lowered = value.lower()
    if (
        value
        and _PLAIN_YAML.fullmatch(value)
        and lowered not in _YAML_AMBIGUOUS
        and not re.fullmatch(r"[-+]?\d+(?:\.\d+)?", value)
    ):
        return value
    return json.dumps(value, ensure_ascii=False)


def render_resolved_manifest(
    slug: str,
    category: str,
    intake: Mapping[str, Any],
) -> str:
    """Render the effective scalar manifest without embedding free-form prose."""
    manifest = intake.get("manifest")
    if not isinstance(manifest, Mapping):
        raise IntakeError("resolved intake has no manifest")
    scalars: dict[str, str] = {"id": slug, "category": category}
    for key, value in manifest.items():
        if key in {"id", "category", "statement"}:
            continue
        if not isinstance(key, str) or not isinstance(value, str):
            raise IntakeError("resolved manifest must contain only string scalars")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", key):
            raise IntakeError(f"invalid manifest key: {key!r}")
        scalars[key] = value
    lines = [f"id: {_yaml_scalar(scalars.pop('id'))}"]
    lines.append(f"category: {_yaml_scalar(scalars.pop('category'))}")
    lines.extend(f"{key}: {_yaml_scalar(scalars[key])}" for key in sorted(scalars))
    return "\n".join(lines) + "\n"
