#!/usr/bin/env bash
# Emit exactly one JSON document describing usable CTF tooling. A discovered
# pathname alone is never evidence that a tool is usable.
set -euo pipefail

CTF_ROOT=${CTF_TOOLS_ROOT:-/home/normalone/CTF}
VENV=${CTF_TOOLS_VENV:-"$CTF_ROOT/.venv"}
export CTF_ROOT VENV

exec python3 - <<'PY'
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tomllib
from datetime import datetime, timezone

VENV = Path(os.environ["VENV"])
VENV_PYTHON = VENV / "bin" / "python"
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
BAD_OUTPUT = re.compile(r"(?:traceback|\busage:|\berror:|\bexception\b)", re.IGNORECASE)
FALLBACKS = {
    "gdb": "Use native binutils and strace for local runtime evidence.", "radare2": "Use readelf, objdump, nm, strings, GDB, and idalib MCP.",
    "ffuf": "Use the session-owned requests/httpx probe helper.", "sqlmap": "Use manual, manifest-scoped requests and preserve evidence.",
    "nmap": "Use only manifest-scoped HTTP/browser primitives; do not scan adjacent hosts.", "nuclei": "Use manual, manifest-scoped checks with requests or Playwright.",
    "httpx": "Use Python httpx/requests in the managed CTF environment.", "ltrace": "Use strace, GDB, and controlled target executions.",
    "binwalk": "Use file, strings, readelf, and targeted extraction only.", "qemu-x86_64": "Use native execution or record that cross-architecture execution is unavailable.",
    "gobuster": "Use ffuf or the session-owned HTTP helper with an authorized wordlist.", "chrome": "Use a verified system Chrome/Chromium, or retain HTTP-only session evidence.",
    "gdb MCP": "Use native gdb, readelf, objdump, nm, and strace.", "idalib MCP": "Use native static tools and controlled GDB traces.",
}
CLI_SPECS = {
    "gdb": (("--version",), r"GNU gdb\s+.*\d+(?:\.\d+)+"), "radare2": (("-v",), r"^radare2\s+\d+(?:\.\d+)+"),
    "ffuf": (("-V",), r"^ffuf version:\s*\d+(?:\.\d+)+"), "sqlmap": (("--version",), r"^\d+(?:\.\d+)+"),
    "nmap": (("--version",), r"^Nmap version\s+\d+(?:\.\d+)+"), "nuclei": (("-version",), r"Nuclei Engine Version:\s*v\d+(?:\.\d+)+"),
    "httpx": (("-version",), r"(?:projectdiscovery\.io|Current Version:\s*v\d+(?:\.\d+)+)"), "ltrace": (("--version",), r"^ltrace\s+\d+(?:\.\d+)+"),
    "binwalk": (("--version",), r"(?:binwalk|Binwalk).*(?:\d+(?:\.\d+)+|version)"), "qemu-x86_64": (("--version",), r"^qemu-x86_64 version\s+\d+(?:\.\d+)+"),
    "gobuster": (("--version",), r"^gobuster version\s+\d+(?:\.\d+)+"),
}
MODULES = {
    "pwn": ("pwntools", "Use native sockets and GDB/binutils while recording the missing pwntools capability."), "angr": ("angr", "Use a small solver/keygen and the target executable as the oracle."),
    "capstone": ("capstone", "Use objdump and idalib/native disassembly."), "unicorn": ("unicorn", "Use the target executable or QEMU/GDB for controlled execution."),
    "z3": ("z3-solver", "Use a direct solver/keygen or constrain the search with target executions."), "lief": ("lief", "Use readelf, objdump, and native binary utilities."),
    "requests": ("requests", "Use curl only for an explicitly authorized exact origin."), "httpx": ("httpx", "Use requests or curl with session-owned evidence files."),
    "playwright": ("playwright", "Use requests/httpx; browser-only flows require manual Chrome evidence."),
}

def degraded(reason, fallback, path=None, version=None):
    return {"status": "degraded", "path": path, "version": version, "reason": reason, "fallback": fallback}
def available(path, version):
    return {"status": "available", "path": path, "version": version, "reason": None, "fallback": None}
def run_probe(command, pattern, timeout=10, allow_usage=False):
    try:
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    except OSError as error: return None, f"probe OS error ({error.strerror or error.__class__.__name__}): {command[0]}"
    except subprocess.TimeoutExpired: return None, f"probe timed out after {timeout}s: {' '.join(command)}"
    output = ANSI.sub("", result.stdout or "").strip()
    if result.returncode: return None, f"probe exited {result.returncode}: {' '.join(command)}"
    if not output: return None, f"probe produced no version output: {' '.join(command)}"
    if BAD_OUTPUT.search(output) and not allow_usage: return None, f"probe produced error/usage output: {' '.join(command)}"
    match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
    if not match: return None, f"probe output did not identify the required tool: {' '.join(command)}"
    return match.group(0)[:300], None
def resolve_command(name):
    path = shutil.which(name)
    venv_command = VENV / "bin" / name
    return path or (str(venv_command) if venv_command.is_file() and os.access(venv_command, os.X_OK) else None)
def cli(name):
    path = resolve_command(name)
    if not path: return degraded(f"{name} is not on PATH", FALLBACKS[name])
    arguments, pattern = CLI_SPECS[name]
    version, error = run_probe([path, *arguments], pattern)
    if error:
        label = "ProjectDiscovery httpx" if name == "httpx" else name
        return degraded(f"{label} is present but unusable: {error}", FALLBACKS[name], path)
    return available(path, version)
def module(name, distribution, fallback):
    if not VENV_PYTHON.is_file(): return degraded(f"managed environment is missing: {VENV_PYTHON}", fallback, str(VENV_PYTHON))
    program = "import importlib.metadata,importlib.util,json,sys;name,dist=sys.argv[1:];s=importlib.util.find_spec(name);print(json.dumps({'path':s.origin if s else None,'version':importlib.metadata.version(dist) if s else None}))"
    try:
        result = subprocess.run([str(VENV_PYTHON), "-c", program, name, distribution], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=12, check=False)
        payload = json.loads(result.stdout) if result.returncode == 0 else {"path": None, "version": None}
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError): payload = {"path": None, "version": None}
    return available(payload["path"], payload["version"]) if payload["path"] else degraded(f"Python module {name} is unavailable in {VENV_PYTHON}", fallback, payload["path"], payload["version"])
def config_paths():
    return (Path(os.environ["CTF_TOOLS_CONFIG"]),) if os.environ.get("CTF_TOOLS_CONFIG") else (Path("/home/normalone/.codex/config.toml"), Path("/home/normalone/.config/codex/config.toml"))
def read_config():
    for path in config_paths():
        try:
            if path.is_file(): return path, tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError): continue
    return None, {}
def configured_command(name, config_path, config):
    entry = config.get("mcp_servers", {}).get(name)
    if not isinstance(entry, dict): return None
    command, args = entry.get("command"), entry.get("args", [])
    if not isinstance(command, str) or not command: return degraded(f"{name} MCP configuration has no command", FALLBACKS[f"{name} MCP"], str(config_path) if config_path else None)
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args): return degraded(f"{name} MCP configuration has invalid args", FALLBACKS[f"{name} MCP"], str(config_path) if config_path else None)
    resolved = command if os.path.isabs(command) else shutil.which(command)
    if not resolved or not os.path.isfile(resolved) or not os.access(resolved, os.X_OK): return degraded(f"{name} MCP command is not executable: {command}", FALLBACKS[f"{name} MCP"], command)
    version, error = run_probe([resolved, *args, "--help"], r"(?:mcp|gdb|usage|help)", allow_usage=True)
    return available(resolved, version) if not error else degraded(f"{name} MCP command is unusable: {error}", FALLBACKS[f"{name} MCP"], resolved)
def idalib_plugin(config_path, config):
    plugins = config.get("plugins", {})
    enabled = isinstance(plugins, dict) and any("ida-pro-mcp" in str(key) and isinstance(value, dict) and value.get("enabled") is True for key, value in plugins.items())
    if not enabled: return degraded("idalib MCP is not configured as a server or enabled plugin", FALLBACKS["idalib MCP"], str(config_path) if config_path else None)
    override = os.environ.get("CTF_TOOLS_IDALIB_PLUGIN")
    candidates = (Path(override),) if override else tuple(sorted(Path("/home/normalone/.codex/plugins/cache/mrexodia/ida-pro-mcp").glob("*/"), reverse=True))
    plugin = next((p for p in candidates if (p / "pyproject.toml").is_file()), None)
    if not plugin: return degraded("idalib MCP plugin is enabled but no local plugin project is available", FALLBACKS["idalib MCP"], str(config_path) if config_path else None)
    version, error = run_probe(["uv", "run", "--directory", str(plugin), "idalib-mcp", "--help"], r"MCP supervisor for IDA Pro", 20, allow_usage=True)
    if error: return degraded(f"idalib MCP plugin is unusable: {error}", FALLBACKS["idalib MCP"], str(plugin))
    try: package_version = tomllib.loads((plugin / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError): package_version = version
    return available(str(plugin), package_version)
def mcp(name):
    config_path, config = read_config()
    direct = configured_command(name, config_path, config)
    if direct is not None: return direct
    if name == "idalib": return idalib_plugin(config_path, config)
    return degraded(f"{name} MCP is not configured", FALLBACKS[f"{name} MCP"], str(config_path) if config_path else None)
def chrome():
    names = tuple(filter(None, os.environ.get("CTF_TOOLS_BROWSER_COMMANDS", "google-chrome,chromium,chromium-browser").split(",")))
    for name in names:
        path = shutil.which(name)
        if path:
            version, error = run_probe([path, "--version"], r"(?:Google Chrome|Chromium)\s+\d+\.\d+")
            if not error: return available(path, version)
    roots = (Path(os.environ["CTF_TOOLS_PLAYWRIGHT_CACHE"]),) if os.environ.get("CTF_TOOLS_PLAYWRIGHT_CACHE") else (Path("/home/normalone/.cache/ms-playwright"), Path("/home/normalone/.cache/ms-playwright-go"))
    for root in roots:
        if root.is_dir():
            for candidate in root.glob("**/chrome"):
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    version, error = run_probe([str(candidate), "--version"], r"(?:Google Chrome|Chromium)\s+\d+\.\d+")
                    if not error: return available(str(candidate), version)
    return degraded("no successfully probed system Chrome/Chromium or Playwright browser executable was found", FALLBACKS["chrome"])

venv_version, venv_error = run_probe([str(VENV_PYTHON), "--version"], r"^Python 3\.12\.\d+") if VENV_PYTHON.is_file() else (None, "managed Python executable is missing")
venv = available(str(VENV_PYTHON), venv_version) if not venv_error else degraded(f"managed environment is unusable: {venv_error}", "Run bash tools/install-ctf-tools.sh to create the uv-managed Python 3.12 environment.", str(VENV_PYTHON))
report = {"schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(), "venv": venv, "cli": {name: cli(name) for name in CLI_SPECS}, "python": {name: module(name, distribution, fallback) for name, (distribution, fallback) in MODULES.items()}, "mcp": {name: mcp(name) for name in ("gdb", "idalib")}, "browser": {"chrome": chrome()}}
capabilities = [report["venv"], *report["cli"].values(), *report["python"].values(), *report["mcp"].values(), *report["browser"].values()]
report["summary"] = {"available": sum(item["status"] == "available" for item in capabilities), "degraded": sum(item["status"] == "degraded" for item in capabilities)}
print(json.dumps(report, sort_keys=True, indent=2))
PY
