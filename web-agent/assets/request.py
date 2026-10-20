#!/usr/bin/env python3
"""Capture one authorized HTTP exchange with bounded transport provenance."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests
import urllib3


SKILL = Path(__file__).resolve().parents[1]
COMMON = SKILL.parent / "ctf-common" / "scripts"
sys.path.insert(0, str(SKILL / "scripts"))
sys.path.insert(0, str(COMMON))
from init_web_state import WebStateError, atomic_json, session_workspace, web_directory, web_lock  # noqa: E402
from web_provenance import atomic_bytes, decode_entity_body, manifest_origin, manifest_values, sent_history, write_new_json  # noqa: E402
from ctf_workspace import (  # noqa: E402
    MAX_ARTIFACT_BYTES,
    CollisionError,
    InvalidInput,
    _read_regular_under,
    publish_capture_attestation,
)


def origin_of(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must include an http(s) origin")
    return f"{parsed.scheme}://{parsed.netloc}".lower()


def authorized_url(workspace: Path, url: str) -> str:
    origin = manifest_origin(workspace)
    callback = manifest_values(workspace).get("callback_origin")
    if origin_of(url) == origin:
        return origin
    # The user-owned out-of-band receiver may be polled for delivered results.
    if callback and origin_of(url) == callback.lower():
        return callback.lower()
    raise ValueError("URL origin is outside the authorized manifest origin")


def loopback_proxy(url: str) -> str:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.port is None
    ):
        raise ValueError("proxy must be a loopback HTTP listener with an explicit port")
    return url


def load_session(workspace: Path, cookie_file: Path) -> requests.Session:
    session = requests.Session()
    try:
        payload = json.loads(_read_regular_under(workspace, cookie_file, "web cookies").data.decode("utf-8"))
    except (InvalidInput, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebStateError("invalid web cookie state") from exc
    for cookie in payload.get("cookies", []):
        session.cookies.set(cookie["name"], cookie["value"], domain=cookie.get("domain"), path=cookie.get("path", "/"))
    return session


def save_session(session: requests.Session, cookie_file: Path) -> None:
    cookies = [
        {"name": item.name, "value": item.value, "domain": item.domain, "path": item.path, "secure": item.secure}
        for item in session.cookies
    ]
    atomic_json(cookie_file, {"schema_version": 1, "cookies": cookies})


def pairs(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"expected NAME=VALUE, got {value!r}")
        name, item = value.split("=", 1)
        if not name:
            raise ValueError("empty input name")
        result[name] = item
    return result


def parse_burp_request(raw: bytes, origin: str) -> tuple[str, str, dict[str, str], bytes]:
    separator = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
    if separator not in raw:
        raise ValueError("Burp request is missing the header/body separator")
    head, body = raw.split(separator, 1)
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    try:
        method, target, version = lines[0].decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Burp request has an invalid request line") from exc
    if not method.isascii() or not method.isalpha() or version not in {"HTTP/1.0", "HTTP/1.1", "HTTP/2"}:
        raise ValueError("Burp request has an unsupported request line")
    if target.startswith("/") and not target.startswith("//"):
        url = origin + target
    elif target.startswith(("http://", "https://")):
        url = target
    else:
        raise ValueError("Burp request target must be an absolute path or URL")
    if "#" in target or origin_of(url) != origin:
        raise ValueError("Burp request URL is outside the authorized manifest origin")
    headers: dict[str, str] = {}
    seen: set[str] = set()
    host: str | None = None
    for line in lines[1:]:
        if b":" not in line or line[:1] in {b" ", b"\t"}:
            raise ValueError("Burp request has a malformed header")
        name, value = line.split(b":", 1)
        try:
            key, item = name.decode("ascii"), value.strip().decode("latin-1")
        except UnicodeDecodeError as exc:
            raise ValueError("Burp request has a malformed header") from exc
        folded = key.lower()
        if not key or folded in seen:
            raise ValueError("Burp request has a duplicate or empty header")
        seen.add(folded)
        if folded == "host":
            host = item
        elif folded == "transfer-encoding":
            raise ValueError("Burp request with transfer encoding is unsupported")
        elif folded not in {"content-length", "connection", "proxy-connection"}:
            headers[key] = item
    if host is None or host.lower() != urlsplit(origin).netloc.lower():
        raise ValueError("Burp request Host is outside the authorized manifest origin")
    if method.upper() in {"GET", "HEAD"} and body:
        raise ValueError("Burp GET/HEAD request body is unsupported")
    return method.upper(), url, headers, body


def record_attempt(workspace: Path, signature: str, progress: str | None) -> None:
    command = [sys.executable, str(COMMON / "record_attempt.py"), "--workspace", str(workspace), "--signature", signature]
    if progress:
        command.extend(("--progress", progress))
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode:
        raise ValueError(f"request rejected by attempt ledger: {result.stdout.strip()}")


def _body(value: object) -> bytes:
    if value is None:
        return b""
    return value.encode() if isinstance(value, str) else bytes(value)


def _headers(response: requests.Response) -> list[list[str]]:
    raw_headers = response.raw.headers
    values = raw_headers.iteritems() if hasattr(raw_headers, "iteritems") else raw_headers.items()
    return [[str(name), str(value)] for name, value in values]


def prepared_record(prepared: requests.PreparedRequest) -> dict[str, object]:
    return {
        "method": prepared.method,
        "url": prepared.url,
        "headers": [[str(name), str(value)] for name, value in prepared.headers.items()],
        "body_base64": base64.b64encode(_body(prepared.body)).decode("ascii"),
        "wire_exact": False,
    }


def stage_prepared(web: Path, request_id: str, hop: int, prepared: requests.PreparedRequest) -> Path:
    path = web / "requests" / f"{request_id}-{hop}.prepared.json"
    payload = prepared_record(prepared)
    if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > MAX_ARTIFACT_BYTES:
        raise WebStateError("prepared request evidence exceeds the common artifact limit")
    write_new_json(path, payload)
    return path


def _history_entries(workspace: Path, history_file: Path) -> list[dict[str, object]]:
    try:
        history = json.loads(_read_regular_under(workspace, history_file, "web capture history").data.decode("utf-8"))
        raw_entries = history["requests"]
        if not isinstance(raw_entries, list):
            raise ValueError
        entries = []
        for item in raw_entries:
            if isinstance(item, str):
                entries.append({"request": item, "complete": True})
            elif isinstance(item, dict) and isinstance(item.get("request"), str):
                entries.append(dict(item))
            else:
                raise ValueError
        return entries
    except (InvalidInput, ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebStateError("invalid web capture history") from exc


def _write_history(history_file: Path, entries: list[dict[str, object]]) -> None:
    atomic_json(history_file, {"schema_version": 1, "requests": entries})


def capture_hop(
    workspace: Path,
    session_record: dict,
    request_id: str,
    hop: int,
    response: requests.Response,
    origin: str,
    prior_requests: list[Path],
    request_file: Path,
) -> tuple[Path, Path, Path | None]:
    """Save an undecoded entity body and a capture-time bounded attestation."""
    web = web_directory(workspace)
    response_file = web_directory(workspace, "responses") / f"{request_id}-{hop}.body"
    provenance_file = web_directory(workspace, "provenance") / f"{request_id}-{hop}.json"
    entity_body = response.raw.read(MAX_ARTIFACT_BYTES + 1, decode_content=False)
    complete_body = len(entity_body) <= MAX_ARTIFACT_BYTES
    if not complete_body:
        entity_body = entity_body[:MAX_ARTIFACT_BYTES]
    atomic_bytes(response_file, entity_body)
    history = sent_history(workspace, [*prior_requests, request_file])
    capture_id = f"web-{request_id}-{hop}"
    capture: dict[str, str] | None = None
    if complete_body and history is not None:
        candidate = decode_entity_body(entity_body, response.headers.get("Content-Encoding"))
        if candidate is not None:
            captures = web_directory(workspace, "captures")
            output_file = captures / f"{capture_id}.output"
            sent_file = captures / f"{capture_id}.sent"
            atomic_bytes(output_file, candidate)
            atomic_bytes(sent_file, history)
            attestation_record = {
                "schema_version": 1, "workspace": str(workspace), "session_id": session_record["session_id"],
                "category": "web", "capture_id": capture_id, "source_target": response.request.url,
                "output": {"path": str(output_file), "sha256": hashlib.sha256(candidate).hexdigest()},
                "sent": {"path": str(sent_file), "sha256": hashlib.sha256(history).hexdigest()},
            }
            attestation = publish_capture_attestation(workspace, attestation_record)
            snapshot = _read_regular_under(workspace, attestation, "capture attestation")
            capture = {
                "capture_id": capture_id, "attestation": str(attestation),
                "attestation_sha256": hashlib.sha256(snapshot.data).hexdigest(), "output": str(output_file),
                "output_sha256": hashlib.sha256(candidate).hexdigest(), "sent": str(sent_file),
                "sent_sha256": hashlib.sha256(history).hexdigest(),
            }
    request_snapshot = _read_regular_under(workspace, request_file, "prepared request evidence")
    provenance = {
        "schema_version": 1, "kind": "web-http-response-v1", "request_id": request_id, "hop": hop,
        "authorized": True, "authorized_origin": origin, "request_url": response.request.url,
        "request": str(request_file), "request_sha256": hashlib.sha256(request_snapshot.data).hexdigest(),
        "response_entity_body": str(response_file), "entity_body_sha256": hashlib.sha256(entity_body).hexdigest(),
        "status": response.status_code, "reason": response.reason, "headers": _headers(response),
        "body_capture": {
            "kind": "urllib3_undecoded_entity_body", "wire_exact": False,
            "content_encoding": response.headers.get("Content-Encoding"), "content_encoding_decoded": False,
            "complete": complete_body,
            "transport_limitations": "HTTP framing and original header wire serialization are unavailable through requests.",
        },
        "request_capture": {"kind": "requests_prepared_request", "wire_exact": False},
    }
    if capture is not None:
        provenance["capture"] = capture
    write_new_json(provenance_file, provenance)
    return response_file, provenance_file, Path(capture["attestation"]) if capture else None


def _error_evidence(workspace: Path, error: str) -> str | None:
    try:
        path = web_directory(workspace, "responses") / f"{time.time_ns()}.error.json"
        write_new_json(path, {"error": error})
        return str(path)
    except (FileExistsError, WebStateError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--url")
    target.add_argument("--burp-request-file", type=Path)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--form", action="append", default=[])
    parser.add_argument("--json", dest="json_body")
    parser.add_argument("--data")
    parser.add_argument("--data-file", type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--proxy", help="local HTTP proxy listener, such as http://127.0.0.1:8080")
    parser.add_argument("--insecure-tls", action="store_true", help="allow an untrusted certificate for this request")
    parser.add_argument("--progress")
    args = parser.parse_args()
    try:
        workspace = session_workspace(args.workspace)
        if args.burp_request_file:
            if args.method != "GET" or args.header or args.form or args.json_body is not None or args.data is not None or args.data_file is not None:
                raise ValueError("Burp request file cannot be combined with request content options")
            snapshot = _read_regular_under(workspace, args.burp_request_file, "Burp request")
            method, url, headers, data = parse_burp_request(snapshot.data, manifest_origin(workspace))
            json_body, form = None, None
        else:
            method, url, headers = args.method.upper(), args.url, pairs(args.header)
            data = args.data
            if args.data_file is not None:
                data = _read_regular_under(workspace, args.data_file, "request data file").data
            json_body = json.loads(args.json_body) if args.json_body is not None else None
            form = pairs(args.form) if args.form else None
        origin = authorized_url(workspace, url)
        proxy = loopback_proxy(args.proxy) if args.proxy else None
        if args.timeout <= 0 or (args.data is not None and args.data_file is not None):
            raise ValueError("timeout must be positive and data inputs must not conflict")
        signature_body = hashlib.sha256(_body(data) if data is not None else (args.json_body or "&".join(sorted(args.form))).encode()).hexdigest()
        record_attempt(workspace, " | ".join((method, url, json.dumps(headers, sort_keys=True), signature_body)), args.progress)
        web = web_directory(workspace)
        with web_lock(workspace, ".history.lock"):
            session = load_session(workspace, web / "cookies.json")
            session_record = json.loads(_read_regular_under(workspace, workspace / "session.json", "web session").data.decode("utf-8"))
            history_file = web / "history.json"
            entries = _history_entries(workspace, history_file)
            prior_requests = [Path(str(entry["request"])) for entry in entries]
            request_id = secrets.token_hex(12)
            captures = []
            started = time.monotonic()
            for hop in range(6):
                request_kwargs: dict[str, object] = {"headers": headers}
                if method not in {"GET", "HEAD"}:
                    if data is not None:
                        request_kwargs["data"] = data
                    elif json_body is not None:
                        request_kwargs["json"] = json_body
                    elif form is not None:
                        request_kwargs["data"] = form
                prepared = session.prepare_request(requests.Request(method, url, **request_kwargs))
                request_file = stage_prepared(web, request_id, hop, prepared)
                entry: dict[str, object] = {"request": str(request_file), "complete": False, "request_id": request_id, "hop": hop}
                entries.append(entry)
                _write_history(history_file, entries)
                send_options: dict[str, object] = {"timeout": args.timeout, "allow_redirects": False, "stream": True}
                if proxy:
                    send_options["proxies"] = {"http": proxy, "https": proxy}
                if args.insecure_tls:
                    send_options["verify"] = False
                response = session.send(prepared, **send_options)
                response_file, provenance_file, attestation = capture_hop(
                    workspace, session_record, request_id, hop, response, origin, prior_requests, request_file
                )
                entry.update({"complete": True, "response": str(response_file), "provenance": str(provenance_file)})
                _write_history(history_file, entries)
                captures.append((request_file, response_file, provenance_file, response, attestation))
                prior_requests.append(request_file)
                location = response.headers.get("Location") if response.is_redirect else None
                if not location:
                    break
                url = urljoin(url, location)
                if authorized_url(workspace, url) != origin:
                    raise ValueError("redirect leaves the origin of the original request")
                if response.status_code == 303 or (response.status_code in {301, 302} and method not in {"GET", "HEAD"}):
                    method, data, json_body, form = "GET", None, None, None
            else:
                raise ValueError("redirect limit reached")
            elapsed_ms = round((time.monotonic() - started) * 1000, 3)
            final_request, final_response, final_provenance, final, final_attestation = captures[-1]
            summary = web_directory(workspace, "responses") / f"{request_id}.summary.json"
            atomic_json(summary, {
                "request_id": request_id, "requests": [str(item[0]) for item in captures],
                "response_entity_bodies": [str(item[1]) for item in captures], "provenance": [str(item[2]) for item in captures],
                "status": final.status_code, "length": len(_read_regular_under(workspace, final_response, "response entity body").data),
                "elapsed_ms": elapsed_ms, "redirects": [{"url": item[3].url, "status": item[3].status_code} for item in captures[:-1]],
                "set_cookie": final.headers.get("Set-Cookie"),
            })
            save_session(session, web / "cookies.json")
            for _, _, _, response, _ in captures:
                response.close()
            print(json.dumps({"prepared_request": str(final_request), "response_entity_body": str(final_response), "provenance": str(final_provenance), "attestation": str(final_attestation) if final_attestation else None, "summary": str(summary)}))
            return 0
    except (OSError, ValueError, WebStateError, InvalidInput, CollisionError, json.JSONDecodeError, requests.RequestException, urllib3.exceptions.HTTPError) as exc:
        evidence = _error_evidence(args.workspace, str(exc))
        print(json.dumps({"status": "error", "error": str(exc), "evidence": evidence}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
