#!/usr/bin/env python3
"""Issue one manifest-authorized request and preserve complete session evidence."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests


SKILL = Path(__file__).resolve().parents[1]
COMMON = SKILL.parent / "ctf-common" / "scripts"


def manifest_values(workspace: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (workspace / "challenge.resolved.yaml").read_text(encoding="utf-8").splitlines():
        if ":" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def origin_of(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must include an http(s) origin")
    return f"{parsed.scheme}://{parsed.netloc}".lower()


def authorized_url(workspace: Path, url: str) -> None:
    manifest = manifest_values(workspace)
    if manifest.get("authorized", "").lower() != "true":
        raise ValueError("manifest does not authorize target traffic")
    if manifest.get("network_access") != "agent_allowed":
        raise ValueError("manifest does not allow agent network access")
    origin = manifest.get("origin") or manifest.get("target_origin")
    if not origin:
        raise ValueError("manifest requires an exact origin")
    if origin_of(url) != origin_of(origin):
        raise ValueError("URL origin is outside the authorized manifest origin")


def load_session(cookie_file: Path) -> requests.Session:
    session = requests.Session()
    payload = json.loads(cookie_file.read_text(encoding="utf-8"))
    for cookie in payload.get("cookies", []):
        session.cookies.set(
            cookie["name"], cookie["value"], domain=cookie.get("domain"), path=cookie.get("path", "/")
        )
    return session


def save_session(session: requests.Session, cookie_file: Path) -> None:
    cookies = [
        {"name": item.name, "value": item.value, "domain": item.domain, "path": item.path,
         "secure": item.secure}
        for item in session.cookies
    ]
    cookie_file.write_text(json.dumps({"schema_version": 1, "cookies": cookies}, indent=2) + "\n", encoding="utf-8")


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


def raw_response(response: requests.Response) -> bytes:
    status = f"HTTP/1.1 {response.status_code} {response.reason}\r\n".encode()
    headers = b"".join(f"{key}: {value}\r\n".encode() for key, value in response.headers.items())
    return status + headers + b"\r\n" + response.content


def record_attempt(workspace: Path, signature: str, progress: str | None) -> None:
    command = [sys.executable, str(COMMON / "record_attempt.py"), "--workspace", str(workspace), "--signature", signature]
    if progress:
        command.extend(("--progress", progress))
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode:
        raise ValueError(f"request rejected by attempt ledger: {result.stdout.strip()}")


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
        workspace = args.workspace.expanduser().resolve()
        authorized_url(workspace, args.url)
        if args.timeout <= 0:
            raise ValueError("timeout must be positive")
        body = args.data if args.data is not None else args.json_body or "&".join(sorted(args.form))
        signature = " | ".join((args.method.upper(), args.url, json.dumps(pairs(args.header), sort_keys=True), body))
        record_attempt(workspace, signature, args.progress)
        web = workspace / "web"
        cookie_file = web / "cookies.json"
        session = load_session(cookie_file)
        headers = pairs(args.header)
        request_args: dict[str, object] = {"headers": headers, "timeout": args.timeout, "allow_redirects": False}
        if args.data is not None:
            request_args["data"] = args.data
        elif args.json_body is not None:
            request_args["json"] = json.loads(args.json_body)
        elif args.form:
            request_args["data"] = pairs(args.form)
        started = time.monotonic()
        method = args.method.upper()
        url = args.url
        responses: list[requests.Response] = []
        for _ in range(6):
            response = session.request(method, url, **request_args)
            responses.append(response)
            location = response.headers.get("Location") if response.is_redirect else None
            if not location:
                break
            url = urljoin(url, location)
            authorized_url(workspace, url)
            if response.status_code == 303 or (response.status_code in {301, 302} and method not in {"GET", "HEAD"}):
                method = "GET"
                request_args.pop("data", None)
                request_args.pop("json", None)
        else:
            raise ValueError("redirect limit reached")
        elapsed_ms = round((time.monotonic() - started) * 1000, 3)
        stamp = f"{time.time_ns()}"
        request_files: list[Path] = []
        response_files: list[Path] = []
        for index, item in enumerate(responses):
            request_file = web / "requests" / f"{stamp}-{index}.raw"
            response_file = web / "responses" / f"{stamp}-{index}.raw"
            prepared = item.request
            request_file.write_bytes(
                f"{prepared.method} {prepared.url} HTTP/1.1\r\n".encode()
                + b"".join(f"{key}: {value}\r\n".encode() for key, value in prepared.headers.items())
                + b"\r\n" + (prepared.body.encode() if isinstance(prepared.body, str) else prepared.body or b"")
            )
            response_file.write_bytes(raw_response(item))
            request_files.append(request_file)
            response_files.append(response_file)
        summary_file = web / "responses" / f"{stamp}.json"
        summary_file.write_text(json.dumps({
            "requests": [str(path) for path in request_files], "responses": [str(path) for path in response_files], "status": response.status_code,
            "length": len(response.content), "elapsed_ms": elapsed_ms,
            "redirects": [{"url": item.url, "status": item.status_code} for item in responses[:-1]],
            "set_cookie": response.headers.get("Set-Cookie"),
        }, indent=2) + "\n", encoding="utf-8")
        save_session(session, cookie_file)
        print(json.dumps({"request": str(request_files[-1]), "response": str(response_files[-1]), "summary": str(summary_file)}))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, requests.RequestException) as exc:
        error_file = args.workspace.expanduser().resolve() / "web" / "responses" / f"{time.time_ns()}.error.json"
        if error_file.parent.is_dir():
            error_file.write_text(json.dumps({"error": str(exc)}) + "\n", encoding="utf-8")
        print(json.dumps({"status": "error", "error": str(exc), "evidence": str(error_file) if error_file.is_file() else None}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
