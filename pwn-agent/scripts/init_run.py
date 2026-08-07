#!/usr/bin/env python3
"""Create an isolated, append-only workspace for one pwn challenge run."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import sys
from pathlib import Path


SKILL_DIR = Path(__file__).resolve().parents[1]
EXPLOIT_TEMPLATE = SKILL_DIR / "assets" / "exploit.py"


def yaml_scalar(path: Path, key: str) -> str | None:
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*:\s*['\"]?([^#'\"]+)")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.match(line)
        if match:
            return match.group(1).strip()
    return None


def safe_name(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip(".-")
    if not result or result in {".", ".."}:
        raise ValueError(f"unsafe identifier: {value!r}")
    return result


def is_elf(path: Path) -> bool:
    try:
        return path.is_file() and path.read_bytes()[:4] == b"\x7fELF"
    except OSError:
        return False


def discover_binary(directory: Path) -> Path | None:
    candidates = [
        path
        for path in directory.iterdir()
        if is_elf(path)
        and not path.name.startswith(("libc", "ld-", "ld-linux"))
    ]
    return candidates[0] if len(candidates) == 1 else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("challenge", type=Path)
    parser.add_argument("--runs-root", type=Path, default=Path("runs"))
    parser.add_argument(
        "--run-id",
        default=dt.datetime.now().strftime("%Y%m%d-%H%M%S"),
    )
    args = parser.parse_args()

    challenge = args.challenge.resolve()
    manifest: Path | None = None
    direct_binary: Path | None = None
    if challenge.is_file() and challenge.suffix.lower() in {".yaml", ".yml"}:
        manifest = challenge
    elif challenge.is_file():
        direct_binary = challenge
    elif challenge.is_dir() and (challenge / "challenge.yaml").is_file():
        manifest = challenge / "challenge.yaml"
    elif challenge.is_dir():
        direct_binary = discover_binary(challenge)
        if direct_binary is None:
            parser.error(
                "no manifest and no single unambiguous top-level ELF: "
                f"{challenge}"
            )
    else:
        parser.error(f"challenge not found: {challenge}")

    if manifest:
        challenge_id = safe_name(
            yaml_scalar(manifest, "id") or manifest.parent.name
        )
        source = manifest.parent.resolve()
    else:
        assert direct_binary is not None
        challenge_id = safe_name(
            direct_binary.stem if challenge.is_file() else challenge.name
        )
        source = direct_binary.parent.resolve()
    run_id = safe_name(args.run_id)
    workspace = args.runs_root.resolve() / run_id / challenge_id
    if workspace.exists():
        parser.error(f"workspace already exists: {workspace}")

    workspace.mkdir(parents=True)
    for name in (
        "crashes",
        "explorers",
        "gdb",
        "ida",
        "logs",
        "transcripts",
    ):
        (workspace / name).mkdir()

    shutil.copy2(EXPLOIT_TEMPLATE, workspace / "exploit.py")
    resolved_manifest = workspace / "challenge.resolved.yaml"
    if manifest:
        shutil.copy2(manifest, resolved_manifest)
    else:
        assert direct_binary is not None
        binary_value = str(direct_binary.resolve()).replace("'", "''")
        resolved_manifest.write_text(
            f"id: {challenge_id}\n"
            f"binary: '{binary_value}'\n"
            "authorized: true\n",
            encoding="utf-8",
        )
    state = {
        "schema_version": 1,
        "challenge_id": challenge_id,
        "status": "ingest",
        "source": str(source),
        "facts": [],
        "hypotheses": [],
        "experiments": [],
        "capabilities": {},
        "strategy": None,
    }
    (workspace / "state.json").write_text(
        json.dumps(state, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (workspace / "notes.md").write_text(
        f"# {challenge_id}\n\n"
        "## Facts\n\n"
        "## Hypotheses\n\n"
        "## Experiments\n\n"
        "## Current strategy\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "workspace": str(workspace),
                "challenge_id": challenge_id,
                "manifest": str(resolved_manifest),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"init_run: {exc}", file=sys.stderr)
        raise SystemExit(2)
