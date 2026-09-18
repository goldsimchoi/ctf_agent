#!/usr/bin/env python3
"""Capture one manifest-authorized local reversing oracle run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


COMMON = Path(__file__).resolve().parents[2] / "ctf-common" / "scripts"
sys.path.insert(0, str(COMMON))

from ctf_workspace import (  # noqa: E402
    CollisionError,
    InvalidInput,
    _read_regular_under,
    publish_capture_attestation,
)


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _manifest_scalars(data: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in data.decode("utf-8", errors="strict").splitlines():
        match = re.match(r"^\s*([A-Za-z][A-Za-z0-9_-]*)\s*:\s*(.*?)\s*(?:#.*)?$", line)
        if match:
            key, value = match.groups()
            value = value.strip().strip("'\"")
            if value and not value.startswith(("[", "{", "|", ">")):
                values[key] = value
    return values


def _authorized_binary(workspace: Path, supplied: Path) -> tuple[Path, dict[str, Any], Path]:
    """Bind a solver invocation to the manifest's local, non-symlink binary."""
    workspace = _absolute(workspace)
    session_artifact = _read_regular_under(workspace, workspace / "session.json", "session")
    manifest_artifact = _read_regular_under(
        workspace, workspace / "challenge.resolved.yaml", "resolved manifest"
    )
    session = json.loads(session_artifact.data.decode("utf-8"))
    if not isinstance(session, dict) or session.get("category") != "rev":
        raise InvalidInput("capture workspace is not a reversing session")
    manifest = _manifest_scalars(manifest_artifact.data)
    if manifest.get("authorized", "").lower() != "true":
        raise InvalidInput("resolved manifest does not authorize a local binary capture")
    binary_value = manifest.get("binary")
    if not binary_value:
        raise InvalidInput("resolved manifest needs an authorized local binary")
    relative = Path(binary_value)
    if relative.is_absolute() or ".." in relative.parts:
        raise InvalidInput("manifest binary must be a challenge-relative path")
    challenge = _absolute(Path(str(session["challenge"])))
    expected = _absolute(challenge / relative)
    if not _under(expected, challenge):
        raise InvalidInput("manifest binary must be beneath the session challenge")
    if _absolute(supplied) != expected:
        raise InvalidInput("supplied binary does not match the manifest binary")
    _read_regular_under(challenge, expected, "manifest binary")
    return workspace, session, expected


def _stable_binary(path: Path, challenge: Path) -> int:
    """Open the authorized binary once and execute that descriptor on Linux."""
    snapshot = _read_regular_under(challenge, path, "manifest binary")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not metadata.st_mode & 0o111
        or (metadata.st_dev, metadata.st_ino) != (snapshot.device, snapshot.inode)
    ):
        os.close(descriptor)
        raise InvalidInput("manifest binary changed or is not executable")
    return descriptor


def _oracle_directory(workspace: Path) -> Path:
    oracle = workspace / "rev" / "oracle"
    oracle.mkdir(parents=True, exist_ok=True)
    metadata = os.lstat(oracle)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise InvalidInput("oracle directory must be a real session-local directory")
    return oracle


def _new_evidence_path(path: Path, oracle: Path, description: str) -> Path:
    raw = _absolute(path)
    if not _under(raw, oracle) or raw.parent != oracle:
        raise InvalidInput(f"{description} must be a direct file in this session's rev/oracle directory")
    try:
        os.lstat(raw)
    except FileNotFoundError:
        return raw
    raise InvalidInput(f"{description} already exists or is a symlink: {raw}")


def _write_new_bytes(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", errors="surrogateescape")


def _attest(workspace: Path, session: dict[str, Any], target: Path, output: Path, sent: Path) -> Path:
    output_snapshot = _read_regular_under(workspace, output, "capture output")
    sent_snapshot = _read_regular_under(workspace, sent, "sent evidence")
    record = {
        "schema_version": 1,
        "workspace": str(workspace),
        "session_id": session["session_id"],
        "category": "rev",
        "capture_id": f"oracle-{time.time_ns()}-{secrets.token_hex(4)}",
        "source_target": f"local:{target}",
        "output": {"path": str(output_snapshot.path), "sha256": hashlib.sha256(output_snapshot.data).hexdigest()},
        "sent": {"path": str(sent_snapshot.path), "sha256": hashlib.sha256(sent_snapshot.data).hexdigest()},
    }
    return publish_capture_attestation(workspace, record)


def run_oracle(
    workspace: Path,
    binary: Path,
    candidate: str,
    output: Path | None = None,
    timeout: float = 5.0,
    sent: Path | None = None,
) -> dict[str, object]:
    """Run the authorized target once and attest exact sent/output byte evidence."""
    workspace, session, binary = _authorized_binary(workspace, binary)
    if timeout <= 0:
        raise InvalidInput("timeout must be positive")
    challenge = _absolute(Path(str(session["challenge"])))
    oracle = _oracle_directory(workspace)
    if output is None:
        output = oracle / f"oracle-{time.time_ns()}.out"
    output = _new_evidence_path(output, oracle, "oracle output")
    if sent is None:
        sent = output.with_suffix(".sent")
    sent = _new_evidence_path(sent, oracle, "oracle sent input")
    if output == sent:
        raise InvalidInput("oracle output and sent input paths must differ")
    sent_data = candidate.encode("utf-8") + b"\n"
    descriptor = _stable_binary(binary, challenge)
    try:
        _write_new_bytes(sent, sent_data)
        try:
            result = subprocess.run(
                [f"/proc/self/fd/{descriptor}"],
                input=sent_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
                pass_fds=(descriptor,),
            )
            transcript = _bytes(result.stdout)
            returncode = result.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            transcript = _bytes(exc.output if exc.output is not None else exc.stdout)
            returncode = None
            timed_out = True
    finally:
        os.close(descriptor)
    _write_new_bytes(output, transcript)
    attestation = _attest(workspace, session, binary, output, sent)
    return {
        "workspace": str(workspace),
        "binary": str(binary),
        "source_target": f"local:{binary}",
        "output": str(output),
        "sent": str(sent),
        "attestation": str(attestation),
        "returncode": returncode,
        "timed_out": timed_out,
    }


def verify_oracle(workspace: Path, output: Path, sent: Path, attestation: Path) -> tuple[int, dict[str, object]]:
    """Verify a capture; this never creates an attestation from arbitrary files."""
    command = [
        sys.executable, str(COMMON / "verify_flag.py"), "--workspace", str(workspace),
        "--output", str(output), "--sent", str(sent), "--attestation", str(attestation),
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        payload = {"status": "error", "error": result.stderr.strip() or "invalid verifier response"}
    return result.returncode, payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sent", type=Path)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--verify", action="store_true")
    try:
        args = parser.parse_args()
        result = run_oracle(args.workspace, args.binary, args.candidate, args.output, args.timeout, args.sent)
        if args.verify:
            code, verification = verify_oracle(
                Path(result["workspace"]), Path(result["output"]),
                Path(result["sent"]), Path(result["attestation"]),
            )
            result["verification"] = verification
            print(json.dumps(result, ensure_ascii=False))
            return code
    except (CollisionError, InvalidInput, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
