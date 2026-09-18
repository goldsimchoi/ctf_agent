"""Executable contract tests for the local CTF tool bootstrap scripts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
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
    def run_command(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            args,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

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
        self.assertIn("pwntools", result.stdout)
        self.assertIn("nuclei", result.stdout)

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
