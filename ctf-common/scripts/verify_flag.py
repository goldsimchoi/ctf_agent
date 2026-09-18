#!/usr/bin/env python3
"""JSON entry point for race/strict flag verification."""

import argparse
import json
from pathlib import Path

from ctf_workspace import DEFAULT_PATTERNS, InvalidInput, verify_outputs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, action="append", required=True)
    parser.add_argument("--sent", type=Path, action="append", default=[])
    parser.add_argument("--pattern", action="append", default=[])
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    try:
        if not args.workspace.expanduser().resolve().is_dir():
            raise InvalidInput(f"workspace is not a directory: {args.workspace}")
        patterns = tuple(item.encode("utf-8") for item in args.pattern) or DEFAULT_PATTERNS
        result = verify_outputs(args.output, args.sent, patterns, args.strict)
    except InvalidInput as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "verified" else 2


if __name__ == "__main__":
    raise SystemExit(main())
