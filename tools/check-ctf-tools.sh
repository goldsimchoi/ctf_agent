#!/usr/bin/env bash
# Emit exactly one JSON document describing CTF tooling.  Missing optional
# accelerators are deliberately reported as degraded rather than failing here.
set -euo pipefail

CTF_ROOT=/home/normalone/CTF
VENV="$CTF_ROOT/.venv"
export CTF_ROOT VENV

exec python3 - <<'PY'
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

CTF_ROOT = Path(os.environ["CTF_ROOT"])
VENV = Path(os.environ["VENV"])
VENV_PYTHON = VENV / "bin" / "python"

FALLBACKS = {
    "gdb": "Use native binutils and strace for local runtime evidence.",
    "radare2": "Use readelf, objdump, nm, strings, GDB, and idalib MCP.",
    "ffuf": "Use the session-owned requests/httpx probe helper.",
    "sqlmap": "Use manual, manifest-scoped requests and preserve evidence.",
    "nmap": "Use only manifest-scoped HTTP/browser primitives; do not scan adjacent hosts.",
    "nuclei": "Use manual, manifest-scoped checks with requests or Playwright.",
    "httpx": "Use Python httpx/requests in the managed CTF environment.",
    "ltrace": "Use strace, GDB, and controlled target executions.",
    "binwalk": "Use file, strings, readelf, and targeted extraction only.",
    "qemu-x86_64": "Use native execution or record that cross-architecture execution is unavailable.",
    "gobuster": "Use ffuf or the session-owned HTTP helper with an authorized wordlist.",
    "chrome": "Use Playwright's Chromium cache, or retain HTTP-only session evidence.",
    "gdb MCP": "Use native gdb, readelf, objdump, nm, and strace.",
    "idalib MCP": "Use native static tools and controlled GDB traces.",
}

MODULES = {
    "pwn": ("pwntools", "Use native sockets and GDB/binutils while recording the missing pwntools capability."),
    "angr": ("angr", "Use a small solver/keygen and the target executable as the oracle."),
    "capstone": ("capstone", "Use objdump and idalib/native disassembly."),
    "unicorn": ("unicorn", "Use the target executable or QEMU/GDB for controlled execution."),
    "z3": ("z3-solver", "Use a direct solver/keygen or constrain the search with target executions."),
    "lief": ("lief", "Use readelf, objdump, and native binary utilities."),
    "requests": ("requests", "Use curl only for an explicitly authorized exact origin."),
    "httpx": ("httpx", "Use requests or curl with session-owned evidence files."),
    "playwright": ("playwright", "Use requests/httpx; browser-only flows require manual Chrome evidence."),
}


def degraded(reason: str, fallback: str, path: str | None = None, version: str | None = None) -> dict:
    return {"status": "degraded", "path": path, "version": version, "reason": reason, "fallback": fallback}


def available(path: str | None, version: str | None) -> dict:
    return {"status": "available", "path": path, "version": version, "reason": None, "fallback": None}


def command_version(path: str) -> str | None:
    for argument in ("--version", "-version", "version"):
        try:
            result = subprocess.run([path, argument], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=8, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        text = result.stdout.strip()
        if text:
            return text.splitlines()[0][:300]
    return None


def cli(name: str) -> dict:
    path = shutil.which(name)
    venv_command = VENV / "bin" / name
    if not path and venv_command.is_file() and os.access(venv_command, os.X_OK):
        path = str(venv_command)
    if not path:
        return degraded(f"{name} is not on PATH", FALLBACKS[name])
    return available(path, command_version(path))


def module(name: str, distribution: str, fallback: str) -> dict:
    if not VENV_PYTHON.is_file():
        return degraded(f"managed environment is missing: {VENV_PYTHON}", fallback, str(VENV_PYTHON))
    probe = (
        "import importlib.metadata, importlib.util, json, sys; "
        "name, distribution = sys.argv[1:]; "
        "spec = importlib.util.find_spec(name); "
        "print(json.dumps({'path': spec.origin if spec else None, "
        "'version': importlib.metadata.version(distribution) if spec else None}))"
    )
    try:
        result = subprocess.run([str(VENV_PYTHON), "-c", probe, name, distribution], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False)
        payload = json.loads(result.stdout) if result.returncode == 0 else {"path": None, "version": None}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        payload = {"path": None, "version": None}
    if payload["path"]:
        return available(payload["path"], payload["version"])
    return degraded(f"Python module {name} is unavailable in {VENV_PYTHON}", fallback, payload["path"], payload["version"])


def mcp(name: str) -> dict:
    config_paths = (Path("/home/normalone/.codex/config.toml"), Path("/home/normalone/.config/codex/config.toml"))
    marker = re.compile(rf"(?:mcp_servers\.{re.escape(name)}\b|mcp_servers\.{re.escape(name)}\.|\b{re.escape(name)}\b)")
    for config in config_paths:
        try:
            if config.is_file() and marker.search(config.read_text(encoding="utf-8", errors="replace")):
                return available(str(config), "configured")
        except OSError:
            continue
    label = f"{name} MCP"
    return degraded(f"{label} is not referenced by the local Codex configuration", FALLBACKS[label])


def chrome() -> dict:
    for name in ("google-chrome", "chromium", "chromium-browser"):
        path = shutil.which(name)
        if path:
            return available(path, command_version(path))
    cache_roots = (Path("/home/normalone/.cache/ms-playwright"), Path("/home/normalone/.cache/ms-playwright-go"))
    for root in cache_roots:
        if root.is_dir() and any(root.iterdir()):
            return available(str(root), "Playwright Chromium cache")
    return degraded("no system Chrome/Chromium or Playwright Chromium cache was found", FALLBACKS["chrome"])


venv = available(str(VENV_PYTHON), None) if VENV_PYTHON.is_file() else degraded(
    f"managed environment is missing: {VENV_PYTHON}",
    "Run bash tools/install-ctf-tools.sh to create the uv-managed Python 3.12 environment.",
    str(VENV_PYTHON),
)
if VENV_PYTHON.is_file():
    try:
        venv["version"] = subprocess.run([str(VENV_PYTHON), "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=8, check=False).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        venv["version"] = None

report = {
    "schema_version": 1,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "venv": venv,
    "cli": {name: cli(name) for name in ("gdb", "radare2", "ffuf", "sqlmap", "nmap", "nuclei", "httpx", "ltrace", "binwalk", "qemu-x86_64", "gobuster")},
    "python": {name: module(name, distribution, fallback) for name, (distribution, fallback) in MODULES.items()},
    "mcp": {name: mcp(name) for name in ("gdb", "idalib")},
    "browser": {"chrome": chrome()},
}
capabilities = [report["venv"], *report["cli"].values(), *report["python"].values(), *report["mcp"].values(), *report["browser"].values()]
report["summary"] = {
    "available": sum(item["status"] == "available" for item in capabilities),
    "degraded": sum(item["status"] == "degraded" for item in capabilities),
}
print(json.dumps(report, sort_keys=True, indent=2))
PY
