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


SKILL = Path(__file__).resolve().parents[1]
COMMON = SKILL.parent / "ctf-common" / "scripts"
sys.path.insert(0, str(SKILL / "scripts"))
from init_web_state import WebStateError, session_workspace  # noqa: E402
from web_provenance import atomic_json, manifest_origin  # noqa: E402


def origin_of(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must include an http(s) origin")
    return f"{parsed.scheme}://{parsed.netloc}".lower()


def authorized_url(workspace: Path, url: str) -> str:
    origin = manifest_origin(workspace)
    if origin_of(url) != origin:
        raise ValueError("URL origin is outside the authorized manifest origin")
    return origin


def load_session(cookie_file: Path) -> requests.Session:
    session = requests.Session()
    payload = json.loads(cookie_file.read_text(encoding="utf-8"))
    for cookie in payload.get("cookies", []):
        session.cookies.set(cookie["name"], cookie["value"], domain=cookie.get("domain"), path=cookie.get("path", "/"))
    return session


def save_session(session: requests.Session, cookie_file: Path) -> None:
    cookies = [{"name": item.name, "value": item.value, "domain": item.domain, "path": item.path, "secure": item.secure} for item in session.cookies]
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


def capture_hop(workspace: Path, request_id: str, hop: int, response: requests.Response, origin: str) -> tuple[Path, Path, Path]:
    """Save undecoded entity bytes plus parsed protocol facts and request provenance.

    urllib3 exposes the entity body after HTTP framing but before content-encoding
    decompression. Requests does not expose original request wire bytes or exact
    header serialization, so the saved request is explicitly prepared evidence.
    """
    web = workspace / "web"
    prepared = response.request
    prepared_body = _body(prepared.body)
    request_file = web / "requests" / f"{request_id}-{hop}.prepared.json"
    response_file = web / "responses" / f"{request_id}-{hop}.body"
    provenance_file = web / "provenance" / f"{request_id}-{hop}.json"
    entity_body = response.raw.read(decode_content=False)
    atomic_json(request_file, {
        "method": prepared.method, "url": prepared.url,
        "headers": [[str(name), str(value)] for name, value in prepared.headers.items()],
        "body_base64": base64.b64encode(prepared_body).decode("ascii"), "wire_exact": False,
    })
    response_file.write_bytes(entity_body)
    atomic_json(provenance_file, {
        "schema_version": 1, "kind": "web-http-response-v1", "request_id": request_id, "hop": hop,
        "authorized": True, "authorized_origin": origin, "request_url": prepared.url,
        "request": str(request_file), "request_sha256": hashlib.sha256(request_file.read_bytes()).hexdigest(),
        "response_entity_body": str(response_file), "entity_body_sha256": hashlib.sha256(entity_body).hexdigest(),
        "status": response.status_code, "reason": response.reason, "headers": _headers(response),
        "body_capture": {
            "kind": "urllib3_undecoded_entity_body", "wire_exact": False,
            "content_encoding": response.headers.get("Content-Encoding"),
            "content_encoding_decoded": False,
            "transport_limitations": "HTTP framing and original header wire serialization are unavailable through requests.",
        },
        "request_capture": {"kind": "requests_prepared_request", "wire_exact": False},
    })
    return request_file, response_file, provenance_file


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", default="GET")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--form", action="append", default=[])
    parser.add_argument("--json", dest="json_body")
    parser.add_argument("--data")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--progress")
    args = parser.parse_args()
    try:
        workspace = session_workspace(args.workspace)
        origin = authorized_url(workspace, args.url)
        if args.timeout <= 0:
            raise ValueError("timeout must be positive")
        body = args.data if args.data is not None else args.json_body or "&".join(sorted(args.form))
        signature = " | ".join((args.method.upper(), args.url, json.dumps(pairs(args.header), sort_keys=True), body))
        record_attempt(workspace, signature, args.progress)
        web = workspace / "web"
        session = load_session(web / "cookies.json")
        request_args: dict[str, object] = {"headers": pairs(args.header), "timeout": args.timeout, "allow_redirects": False, "stream": True}
        if args.data is not None:
            request_args["data"] = args.data
        elif args.json_body is not None:
            request_args["json"] = json.loads(args.json_body)
        elif args.form:
            request_args["data"] = pairs(args.form)
        request_id = secrets.token_hex(12)
        method, url, captures = args.method.upper(), args.url, []
        started = time.monotonic()
        for hop in range(6):
            response = session.request(method, url, **request_args)
            request_file, response_file, provenance_file = capture_hop(workspace, request_id, hop, response, origin)
            captures.append((request_file, response_file, provenance_file, response))
            location = response.headers.get("Location") if response.is_redirect else None
            if not location:
                break
            url = urljoin(url, location)
            authorized_url(workspace, url)  # Validate before the next outbound request.
            if response.status_code == 303 or (response.status_code in {301, 302} and method not in {"GET", "HEAD"}):
                method = "GET"
                request_args.pop("data", None)
                request_args.pop("json", None)
        else:
            raise ValueError("redirect limit reached")
        elapsed_ms = round((time.monotonic() - started) * 1000, 3)
        final_request, final_response, final_provenance, final = captures[-1]
        summary_file = web / "responses" / f"{request_id}.summary.json"
        atomic_json(summary_file, {
            "request_id": request_id, "requests": [str(item[0]) for item in captures],
            "response_entity_bodies": [str(item[1]) for item in captures], "provenance": [str(item[2]) for item in captures],
            "status": final.status_code, "length": final_response.stat().st_size, "elapsed_ms": elapsed_ms,
            "redirects": [{"url": item[3].url, "status": item[3].status_code} for item in captures[:-1]],
            "set_cookie": final.headers.get("Set-Cookie"),
        })
        save_session(session, web / "cookies.json")
        for _, _, _, response in captures:
            response.close()
        print(json.dumps({"prepared_request": str(final_request), "response_entity_body": str(final_response), "provenance": str(final_provenance), "summary": str(summary_file)}))
        return 0
    except (OSError, ValueError, WebStateError, json.JSONDecodeError, requests.RequestException) as exc:
        error_file = args.workspace.expanduser().resolve() / "web" / "responses" / f"{time.time_ns()}.error.json"
        if error_file.parent.is_dir():
            atomic_json(error_file, {"error": str(exc)})
        print(json.dumps({"status": "error", "error": str(exc), "evidence": str(error_file) if error_file.is_file() else None}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
