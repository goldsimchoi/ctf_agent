#!/usr/bin/env python3
"""JSON entry point for publishing an immutable common finding."""

import argparse
import json
from pathlib import Path

from ctf_workspace import InvalidInput, publish_finding


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--kind", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--summary", required=True)
    args = parser.parse_args()
    try:
        path = publish_finding(args.workspace, args.kind, args.evidence, args.summary)
    except InvalidInput as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 2
    print(json.dumps({"status": "published", "finding": str(path)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
