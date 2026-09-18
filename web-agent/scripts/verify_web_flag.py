#!/usr/bin/env python3
"""Verify flags only from recorded, authorized web response provenance."""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

from init_web_state import WebStateError, session_workspace
from web_provenance import validate_response_provenance


COMMON = Path(__file__).resolve().parents[2] / "ctf-common" / "scripts" / "verify_flag.py"


def verification_body(record: dict) -> bytes:
    body = Path(str(record["response_entity_body"])).read_bytes()
    encoding = str(record.get("body_capture", {}).get("content_encoding") or "").lower()
    if encoding == "gzip":
        return gzip.decompress(body)
    if encoding == "deflate":
        return zlib.decompress(body)
    if encoding in {"", "identity"}:
        return body
    raise WebStateError(f"cannot verify preserved {encoding!r} response body without a decoder")


def sent_evidence(record: dict) -> bytes:
    try:
        prepared_path = Path(str(record["request"]))
        prepared_bytes = prepared_path.read_bytes()
        prepared = json.loads(prepared_bytes.decode("utf-8"))
        headers = prepared.get("headers", [])
        body = base64.b64decode(prepared.get("body_base64", ""), validate=True)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise WebStateError("invalid recorded request evidence") from exc
    head = "\n".join([str(prepared.get("method", "")), str(prepared.get("url", ""))] + [f"{name}: {value}" for name, value in headers])
    url = urlsplit(str(prepared.get("url", "")))
    semantics = [f"path={unquote(url.path)}"]
    semantics.extend(f"query:{name}={value}" for name, value in parse_qsl(url.query, keep_blank_values=True))
    content_type = next((str(value) for name, value in headers if str(name).lower() == "content-type"), "")
    if content_type.split(";", 1)[0].strip().lower() == "application/x-www-form-urlencoded":
        try:
            form = body.decode("utf-8")
        except UnicodeDecodeError:
            form = ""
        semantics.extend(f"form:{name}={value}" for name, value in parse_qsl(form, keep_blank_values=True))
    return (
        b"prepared-record:\n" + prepared_bytes + b"\n\nprepared-input:\n"
        + head.encode("utf-8", errors="replace") + b"\n\n" + body
        + b"\n\nsemantic-inputs:\n" + "\n".join(semantics).encode("utf-8", errors="replace")
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, action="append", required=True)
    parser.add_argument("--strict", action="store_true")
    try:
        args = parser.parse_args()
        workspace = session_workspace(args.workspace)
        records = [validate_response_provenance(workspace, output) for output in args.output]
        if args.strict and len({str(record["request_id"]) for record in records}) < 2:
            raise WebStateError("strict mode requires two distinct authorized web requests")
        command = [sys.executable, str(COMMON), "--workspace", str(workspace)]
        with tempfile.TemporaryDirectory(prefix="verify-", dir=workspace / "web") as temporary:
            root = Path(temporary)
            for index, record in enumerate(records):
                output = root / f"{index}.body"
                sent = root / f"{index}.sent"
                output.write_bytes(verification_body(record))
                sent.write_bytes(sent_evidence(record))
                command.extend(("--output", str(output), "--sent", str(sent)))
            if args.strict:
                command.append("--strict")
            result = subprocess.run(command, text=True, capture_output=True, check=False)
        sys.stdout.write(result.stdout)
        return result.returncode
    except WebStateError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
