#!/usr/bin/env python3
"""JSON entry point for creating a common CTF session."""

import json
import os
import stat
import sys
from pathlib import Path

from ctf_intake import IntakeError, IntakeRequest, read_request_json
from ctf_workspace import CollisionError, InvalidInput, JsonArgumentParser, create_session


def _read_request_path(path: Path) -> IntakeRequest:
    raw = path.expanduser().absolute()
    descriptor = os.open(raw.anchor, os.O_RDONLY | os.O_DIRECTORY)
    file_descriptor: int | None = None
    try:
        for part in raw.parts[1:-1]:
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        file_descriptor = os.open(
            raw.name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
            dir_fd=descriptor,
        )
        if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            raise IntakeError(f"request JSON is not a regular file: {raw}")
        with os.fdopen(file_descriptor, "rb") as stream:
            file_descriptor = None
            return read_request_json(stream)
    except OSError as exc:
        raise IntakeError(f"request JSON is unreadable: {raw}") from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        os.close(descriptor)


def main() -> int:
    parser = JsonArgumentParser()
    parser.add_argument("challenge", type=Path)
    parser.add_argument("--category", choices=("pwn", "web", "rev"), required=True)
    parser.add_argument("--event-root", type=Path)
    parser.add_argument("--session-id")
    parser.add_argument("--request-json", metavar="{-|PATH}")
    parser.add_argument("--statement")
    parser.add_argument("--target")
    parser.add_argument("--binary")
    parser.add_argument("--flag-pattern")
    try:
        args = parser.parse_args()
        individual = (args.statement, args.target, args.binary, args.flag_pattern)
        if args.request_json is not None and any(value is not None for value in individual):
            raise IntakeError("--request-json cannot be mixed with individual intake flags")
        if args.request_json == "-":
            intake = read_request_json(sys.stdin.buffer)
        elif args.request_json is not None:
            intake = _read_request_path(Path(args.request_json))
        elif any(value is not None for value in individual):
            intake = IntakeRequest(
                statement=args.statement or "",
                target=args.target,
                binary=args.binary,
                flag_pattern=args.flag_pattern,
            )
        else:
            intake = None
        row = create_session(
            args.challenge,
            args.category,
            args.event_root,
            args.session_id,
            intake=intake,
        )
    except (InvalidInput, CollisionError, IntakeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    row["workspace"] = str(row["workspace"])
    row["findings"] = [str(path) for path in row["findings"]]
    print(json.dumps(row, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
