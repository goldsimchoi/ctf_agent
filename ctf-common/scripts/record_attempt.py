#!/usr/bin/env python3
"""JSON entry point for recording a session attempt."""

import argparse
import json
from pathlib import Path

from ctf_workspace import BudgetExhausted, InvalidInput, record_attempt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--signature", required=True)
    parser.add_argument("--progress")
    args = parser.parse_args()
    try:
        state = record_attempt(args.workspace, args.signature, args.progress)
    except BudgetExhausted as exc:
        print(json.dumps({"status": "exhausted", "error": str(exc)}))
        return 3
    except InvalidInput as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    print(json.dumps(state, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
