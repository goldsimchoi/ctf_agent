#!/usr/bin/env python3
"""JSON entry point for creating a common CTF session."""

import argparse
import json
import sys
from pathlib import Path

from ctf_workspace import CollisionError, InvalidInput, JsonArgumentParser, create_session


def main() -> int:
    parser = JsonArgumentParser()
    parser.add_argument("challenge", type=Path)
    parser.add_argument("--category", choices=("pwn", "web", "rev"), required=True)
    parser.add_argument("--event-root", type=Path)
    parser.add_argument("--session-id")
    try:
        args = parser.parse_args()
        row = create_session(args.challenge, args.category, args.event_root, args.session_id)
    except (InvalidInput, CollisionError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    row["workspace"] = str(row["workspace"])
    row["findings"] = [str(path) for path in row["findings"]]
    print(json.dumps(row, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
