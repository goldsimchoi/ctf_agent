#!/usr/bin/env python3
"""Publish one pwn target-capture attestation for common verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


COMMON_SCRIPTS = Path(__file__).resolve().parents[2] / "ctf-common" / "scripts"
sys.path.insert(0, str(COMMON_SCRIPTS))

from ctf_workspace import (  # noqa: E402
    CollisionError,
    InvalidInput,
    _read_regular_under,
    publish_capture_attestation,
)


def manifest_scalars(data: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in data.decode("utf-8", errors="strict").splitlines():
        match = re.match(r"^\s*([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*?)\s*(?:#.*)?$", line)
        if match:
            key, value = match.groups()
            value = value.strip().strip("'\"")
            if value and not value.startswith(("[", "{", "|", ">")):
                values[key] = value
    return values


def bound_source_target(workspace: Path, session: dict[str, object], manifest: dict[str, str], supplied: str) -> str:
    source_target = supplied.strip()
    if (
        manifest.get("authorized") == "true"
        and manifest.get("network_access") == "agent_allowed"
        and manifest.get("host")
        and manifest.get("port")
    ):
        protocol = manifest.get("protocol", "tcp")
        if protocol != "tcp":
            raise InvalidInput("pwn remote capture requires manifest protocol tcp")
        try:
            port = int(manifest["port"])
        except ValueError as exc:
            raise InvalidInput("manifest port must be an integer") from exc
        if not 1 <= port <= 65535:
            raise InvalidInput("manifest port is outside the tcp range")
        expected = f"tcp://{manifest['host']}:{port}"
        if source_target == expected:
            return expected
    binary_value = manifest.get("binary")
    if not binary_value:
        raise InvalidInput("capture source does not match an authorized remote target or manifest binary")
    binary_relative = Path(binary_value)
    if binary_relative.is_absolute() or ".." in binary_relative.parts:
        raise InvalidInput("manifest binary must be a challenge-relative path")
    challenge = Path(str(session["challenge"])).expanduser().absolute()
    binary = _read_regular_under(challenge, challenge / binary_relative, "manifest binary")
    expected = f"local:{binary.path}"
    if source_target != expected:
        raise InvalidInput("capture source does not match the authorized target")
    return expected


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--capture-id", required=True)
    parser.add_argument("--source-target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sent", type=Path, required=True)
    args = parser.parse_args()

    try:
        workspace = args.workspace.expanduser().absolute()
        session_artifact = _read_regular_under(workspace, workspace / "session.json", "session")
        manifest_artifact = _read_regular_under(
            workspace, workspace / "challenge.resolved.yaml", "resolved manifest"
        )
        session = json.loads(session_artifact.data.decode("utf-8"))
        if session.get("category") != "pwn":
            raise InvalidInput("capture workspace is not a pwn session")
        manifest = manifest_scalars(manifest_artifact.data)
        source_target = bound_source_target(workspace, session, manifest, args.source_target)
        output = _read_regular_under(workspace, args.output, "capture output")
        sent = _read_regular_under(workspace, args.sent, "sent evidence")
        record = {
            "schema_version": 1,
            "workspace": str(workspace),
            "session_id": session["session_id"],
            "category": "pwn",
            "capture_id": args.capture_id,
            "source_target": source_target,
            "output": {"path": str(output.path), "sha256": hashlib.sha256(output.data).hexdigest()},
            "sent": {"path": str(sent.path), "sha256": hashlib.sha256(sent.data).hexdigest()},
        }
        attestation = publish_capture_attestation(workspace, record)
    except (CollisionError, InvalidInput, KeyError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    print(json.dumps({"status": "published", "attestation": str(attestation)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
