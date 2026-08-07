#!/usr/bin/env python3
"""Verify a flag from two or more clean binary-safe transcripts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path


DEFAULT_PATTERNS = (
    rb"FLAG\{[^}\r\n]+\}",
    rb"flag\{[^}\r\n]+\}",
    rb"[A-Za-z0-9_]{2,32}\{[^}\r\n]+\}",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
        raise


def candidates(data: bytes, patterns: tuple[bytes, ...]) -> set[bytes]:
    found: set[bytes] = set()
    for pattern in patterns:
        found.update(re.findall(pattern, data))
    return found


def finish(
    result_path: Path,
    outputs: list[Path],
    status: str,
    reason: str,
    flag: bytes | None = None,
) -> int:
    payload = {
        "status": status,
        "reason": reason,
        "flag": flag.decode("utf-8", errors="replace") if flag else None,
        "reproductions": len(outputs) if status == "verified" else 0,
        "outputs": [
            {"path": str(path.resolve()), "sha256": digest(path)}
            for path in outputs
        ],
    }
    write_atomic(result_path, payload)
    print(json.dumps(payload, ensure_ascii=False))
    return 0 if status == "verified" else 2


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, action="append", required=True)
    parser.add_argument("--sent", type=Path, action="append", default=[])
    parser.add_argument("--pattern", action="append", default=[])
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()

    if len(args.output) < 2:
        return finish(
            args.result,
            args.output,
            "unverified",
            "requires_two_clean_reproductions",
        )

    patterns = tuple(
        pattern.encode("utf-8") for pattern in args.pattern
    ) or DEFAULT_PATTERNS
    try:
        per_run = [candidates(path.read_bytes(), patterns) for path in args.output]
    except re.error as exc:
        parser.error(f"invalid flag pattern: {exc}")

    common = set.intersection(*per_run)
    if not common:
        reason = "no_candidate" if not any(per_run) else "candidate_not_reproduced"
        return finish(args.result, args.output, "unverified", reason)

    sent_data = b"\n".join(path.read_bytes() for path in args.sent)
    independent = sorted(
        (candidate for candidate in common if candidate not in sent_data),
        key=lambda item: (len(item), item),
    )
    if not independent:
        return finish(
            args.result,
            args.output,
            "unverified",
            "candidate_was_user_input",
        )

    return finish(
        args.result,
        args.output,
        "verified",
        "reproduced_in_clean_sessions",
        independent[0],
    )


if __name__ == "__main__":
    raise SystemExit(main())
