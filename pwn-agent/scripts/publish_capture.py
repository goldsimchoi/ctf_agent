#!/usr/bin/env python3
"""Publish one pwn target-capture attestation for common verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
from pathlib import Path


COMMON_SCRIPTS = Path(__file__).resolve().parents[2] / "ctf-common" / "scripts"
sys.path.insert(0, str(COMMON_SCRIPTS))

from ctf_workspace import (  # noqa: E402
    MAX_ARTIFACT_BYTES,
    CollisionError,
    InvalidInput,
    publish_capture_attestation,
)


def contained_regular_file(workspace: Path, path: Path, description: str) -> Path:
    candidate = path.expanduser().absolute()
    try:
        candidate.relative_to(workspace)
        metadata = candidate.lstat()
    except (OSError, ValueError) as exc:
        raise InvalidInput(f"{description} must be a session-contained file") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise InvalidInput(f"{description} must be a regular file")
    if metadata.st_size > MAX_ARTIFACT_BYTES:
        raise InvalidInput(f"{description} exceeds {MAX_ARTIFACT_BYTES} bytes")
    return candidate


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        total = 0
        while block := stream.read(1024 * 1024):
            total += len(block)
            if total > MAX_ARTIFACT_BYTES:
                raise InvalidInput(f"capture artifact exceeds {MAX_ARTIFACT_BYTES} bytes")
            hasher.update(block)
    return hasher.hexdigest()


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
        session = json.loads((workspace / "session.json").read_text(encoding="utf-8"))
        if session.get("category") != "pwn":
            raise InvalidInput("capture workspace is not a pwn session")
        source_target = args.source_target.strip()
        if not source_target.startswith(("local:", "tcp://")):
            raise InvalidInput("source target must identify a local process or tcp endpoint")
        output = contained_regular_file(workspace, args.output, "capture output")
        sent = contained_regular_file(workspace, args.sent, "sent evidence")
        record = {
            "schema_version": 1,
            "workspace": str(workspace),
            "session_id": session["session_id"],
            "category": "pwn",
            "capture_id": args.capture_id,
            "source_target": source_target,
            "output": {"path": str(output), "sha256": digest(output)},
            "sent": {"path": str(sent), "sha256": digest(sent)},
        }
        attestation = publish_capture_attestation(workspace, record)
    except (CollisionError, InvalidInput, KeyError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    print(json.dumps({"status": "published", "attestation": str(attestation)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
