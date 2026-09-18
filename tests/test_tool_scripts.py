"""Executable contract tests for the local CTF tool bootstrap scripts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "install-ctf-tools.sh"
CHECKER = ROOT / "tools" / "check-ctf-tools.sh"
README = ROOT / "README.md"

REQUIRED_CLIS = (
    "gdb",
    "radare2",
    "ffuf",
    "sqlmap",
    "nmap",
    "nuclei",
    "httpx",
    "ltrace",
    "binwalk",
    "qemu-x86_64",
    "gobuster",
)
REQUIRED_MODULES = (
    "pwn",
    "angr",
    "capstone",
    "unicorn",
    "z3",
    "lief",
    "requests",
    "httpx",
    "playwright",
)


class ToolScriptTests(unittest.TestCase):
    def run_command(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **(env or {})},
        )

    def checker_report(self, env: dict[str, str]) -> dict[str, object]:
        result = self.run_command("bash", str(CHECKER), env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_scripts_are_valid_bash(self) -> None:
        """A shell syntax regression must fail before an installer can mutate a host."""
        for script in (INSTALLER, CHECKER):
            result = self.run_command("bash", "-n", str(script))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_installer_dry_run_is_non_mutating_plan(self) -> None:
        """The dry run catches an installer that attempts package installation immediately."""
        result = self.run_command("bash", str(INSTALLER), "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/home/normalone/CTF/.venv", result.stdout)
        self.assertIn("pwntools==4.15.0", result.stdout)
        self.assertIn("github.com/ffuf/ffuf/v2@v2.1.0", result.stdout)
        self.assertIn("nuclei", result.stdout)
        self.assertNotIn("@latest", result.stdout)

    def test_checker_emits_one_json_capability_document(self) -> None:
        """The checker must be machine-readable even when capabilities are absent."""
        result = self.run_command("bash", str(CHECKER))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["schema_version"], 1)
        self.assertIn("venv", report)
        self.assertIn("cli", report)
        self.assertIn("python", report)
        self.assertIn("mcp", report)
        self.assertIn("browser", report)
        for name in REQUIRED_CLIS:
            self.assert_capability(report["cli"][name])
        for name in REQUIRED_MODULES:
            self.assert_capability(report["python"][name])
        for name in ("gdb", "idalib"):
            self.assert_capability(report["mcp"][name])
        self.assert_capability(report["browser"]["chrome"])

    def test_checker_rejects_failed_and_unrelated_cli_probes(self) -> None:
        """A PATH entry is not a capability when its probe fails or identifies another tool."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            binaries = temporary_path / "bin"
            binaries.mkdir()
            self.write_executable(binaries / "ffuf", "exit 7")
            self.write_executable(binaries / "httpx", "echo 'httpx 0.28.1'; exit 0")
            self.write_executable(binaries / "gobuster", "echo 'usage: gobuster'; exit 0")
            config = temporary_path / "config.toml"
            config.write_text("[mcp_servers.gdb]\ncommand = '/missing/gdb-mcp'\n", encoding="utf-8")
            stale_cache = temporary_path / "playwright-cache"
            stale_cache.mkdir()
            report = self.checker_report(
                {
                    "PATH": f"{binaries}:{os.environ['PATH']}",
                    "CTF_TOOLS_CONFIG": str(config),
                    "CTF_TOOLS_VENV": str(temporary_path / "missing-venv"),
                    "CTF_TOOLS_BROWSER_COMMANDS": "missing-browser",
                    "CTF_TOOLS_PLAYWRIGHT_CACHE": str(stale_cache),
                }
            )
        self.assertEqual(report["cli"]["ffuf"]["status"], "degraded")
        self.assertIn("exit", report["cli"]["ffuf"]["reason"])
        self.assertEqual(report["cli"]["httpx"]["status"], "degraded")
        self.assertIn("ProjectDiscovery", report["cli"]["httpx"]["reason"])
        self.assertEqual(report["cli"]["gobuster"]["status"], "degraded")
        self.assertEqual(report["mcp"]["gdb"]["status"], "degraded")
        self.assertEqual(report["mcp"]["idalib"]["status"], "degraded")
        self.assertEqual(report["browser"]["chrome"]["status"], "degraded")

    def test_checker_validates_a_configured_mcp_command(self) -> None:
        """A configured MCP is available only when its command can execute safely."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            executable = temporary_path / "gdb-mcp"
            self.write_executable(executable, "echo 'gdb MCP ready'")
            config = temporary_path / "config.toml"
            config.write_text(
                f"[mcp_servers.gdb]\ncommand = '{executable}'\nargs = ['--stdio']\n",
                encoding="utf-8",
            )
            report = self.checker_report(
                {
                    "CTF_TOOLS_CONFIG": str(config),
                    "CTF_TOOLS_VENV": str(temporary_path / "missing-venv"),
                    "CTF_TOOLS_BROWSER_COMMANDS": "missing-browser",
                    "CTF_TOOLS_PLAYWRIGHT_CACHE": str(temporary_path / "missing-cache"),
                }
            )
        self.assertEqual(report["mcp"]["gdb"]["status"], "available")
        self.assertEqual(report["mcp"]["gdb"]["path"], str(executable))

    def test_checker_degrades_a_corrupt_managed_python_without_losing_json(self) -> None:
        """A present but unexecutable venv Python must not crash the capability report."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            venv_python = temporary_path / "CTF" / ".venv" / "bin" / "python"
            venv_python.parent.mkdir(parents=True)
            venv_python.write_text("this is not an executable\n", encoding="utf-8")
            venv_python.chmod(0o755)
            config = temporary_path / "config.toml"
            config.write_text("", encoding="utf-8")
            report = self.checker_report(
                {
                    "CTF_TOOLS_ROOT": str(temporary_path / "CTF"),
                    "CTF_TOOLS_CONFIG": str(config),
                    "CTF_TOOLS_BROWSER_COMMANDS": "missing-browser",
                    "CTF_TOOLS_PLAYWRIGHT_CACHE": str(temporary_path / "missing-cache"),
                }
            )
        self.assertEqual(report["venv"]["status"], "degraded")
        self.assertIn("probe OS error", report["venv"]["reason"])
        self.assertEqual(report["python"]["angr"]["status"], "degraded")

    def write_executable(self, path: Path, body: str) -> None:
        path.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
        path.chmod(0o755)

    def assert_capability(self, capability: dict[str, object]) -> None:
        self.assertIn(capability["status"], ("available", "degraded"))
        self.assertIn("path", capability)
        self.assertIn("version", capability)
        if capability["status"] == "degraded":
            self.assertIsInstance(capability.get("reason"), str)
            self.assertTrue(capability["reason"])
            self.assertIsInstance(capability.get("fallback"), str)
            self.assertTrue(capability["fallback"])

    def test_readme_has_exact_workspace_and_all_skill_invocations(self) -> None:
        """The documented entrypoints must cover all three installed skills."""
        text = README.read_text(encoding="utf-8")
        self.assertIn("/home/normalone/CTF/<event>/challenges/<challenge>", text)
        for invocation in ("$pwn-agent", "$web-agent", "$rev-agent"):
            self.assertIn(invocation, text)
        self.assertIn("race", text)
        self.assertIn("strict", text)


if __name__ == "__main__":
    unittest.main()
