"""Executable contract tests for the local CTF tool bootstrap scripts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import hashlib
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "install-ctf-tools.sh"
CHECKER = ROOT / "tools" / "check-ctf-tools.sh"
SQLMAP_REVISION = "5365c7e53d03c268b14cfc924398340d1365e863"
R2_REVISION = "8e57aff6dc36517bbab2aff199154f099e3471ea"

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

    def test_checker_imports_modules_in_the_managed_environment(self) -> None:
        """find_spec is insufficient: an import-time dependency error must degrade the module."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            fake_module_dir = temporary_path / "modules"
            fake_module_dir.mkdir()
            (fake_module_dir / "angr.py").write_text("raise ImportError('fixture dependency broke')\n", encoding="utf-8")
            venv_python = temporary_path / "CTF" / ".venv" / "bin" / "python"
            venv_python.parent.mkdir(parents=True)
            self.write_executable(
                venv_python,
                f"PYTHONPATH='{fake_module_dir}' exec '/home/normalone/CTF/.venv/bin/python' \"$@\"",
            )
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
        self.assertEqual(report["python"]["angr"]["status"], "degraded")
        self.assertIn("fixture dependency broke", report["python"]["angr"]["reason"])

    def test_sqlmap_checkout_failure_does_not_expose_an_unpinned_wrapper(self) -> None:
        """A failed pinned checkout must not create a runnable wrapper from arbitrary source."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            fake_bin = temporary_path / "bin"
            fake_bin.mkdir()
            self.write_executable(
                fake_bin / "git",
                "if [ \"$1\" = clone ]; then mkdir -p \"$3/.git\"; touch \"$3/sqlmap.py\"; exit 0; fi\n"
                "if [ \"$1\" = -C ]; then echo 'forced checkout failure' >&2; exit 7; fi\nexit 1",
            )
            local_root = temporary_path / "local"
            result = self.run_command(
                "bash", str(INSTALLER), "--component", "sqlmap",
                env={
                    "PATH": f"{fake_bin}:/usr/bin:/bin",
                    "CTF_TOOLS_ROOT": str(temporary_path / "CTF"),
                    "CTF_TOOLS_LOCAL_BIN": str(local_root / "bin"),
                    "CTF_TOOLS_LOCAL_OPT": str(local_root / "opt"),
                },
            )
            wrapper = local_root / "bin" / "sqlmap"
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("pinned sqlmap revision", result.stderr)
            self.assertFalse(wrapper.exists())

    def test_radare2_checkout_failure_does_not_build_unpinned_source(self) -> None:
        """A failed radare2 pin must stop before configure or make can execute."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            fake_bin = temporary_path / "bin"
            fake_bin.mkdir()
            self.write_executable(
                fake_bin / "git",
                "if [ \"$1\" = clone ]; then mkdir -p \"$3/.git\"; "
                "printf '%s\\n' '#!/usr/bin/env bash' 'touch \"$CTF_TEST_BUILD_MARKER\"' > \"$3/configure\"; chmod +x \"$3/configure\"; exit 0; fi\n"
                "if [ \"$1\" = -C ]; then echo 'forced checkout failure' >&2; exit 7; fi\nexit 1",
            )
            marker = temporary_path / "build-ran"
            local_root = temporary_path / "local"
            result = self.run_command(
                "bash", str(INSTALLER), "--component", "radare2",
                env={
                    "PATH": f"{fake_bin}:/usr/bin:/bin",
                    "CTF_TOOLS_ROOT": str(temporary_path / "CTF"),
                    "CTF_TOOLS_LOCAL_BIN": str(local_root / "bin"),
                    "CTF_TOOLS_LOCAL_OPT": str(local_root / "opt"),
                    "CTF_TEST_BUILD_MARKER": str(marker),
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("pinned radare2 revision", result.stderr)
            self.assertFalse(marker.exists())

    def test_sqlmap_rerun_disables_a_stale_managed_wrapper_when_pin_validation_fails(self) -> None:
        """A second run must not trust an existing installer-owned sqlmap wrapper."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            local_root = temporary_path / "local"
            local_bin = local_root / "bin"
            local_bin.mkdir(parents=True)
            source = local_root / "opt" / "sqlmap"
            source.mkdir(parents=True)
            (source / ".git").mkdir()
            (source / "sqlmap.py").write_text("stale source\n", encoding="utf-8")
            self.write_executable(local_bin / "sqlmap", "echo stale sqlmap")
            self.write_ownership_marker(local_root / "opt", "sqlmap", local_bin / "sqlmap", SQLMAP_REVISION)
            fake_bin = temporary_path / "fake-bin"
            fake_bin.mkdir()
            self.write_executable(fake_bin / "git", "echo 'forced checkout failure' >&2; exit 7")
            environment = {
                "PATH": f"{local_bin}:{fake_bin}:/usr/bin:/bin",
                "CTF_TOOLS_ROOT": str(temporary_path / "CTF"),
                "CTF_TOOLS_LOCAL_BIN": str(local_bin),
                "CTF_TOOLS_LOCAL_OPT": str(local_root / "opt"),
            }
            for _ in range(2):
                result = self.run_command("bash", str(INSTALLER), "--component", "sqlmap", env=environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("pinned sqlmap revision", result.stderr)
                self.assertFalse((local_bin / "sqlmap").exists())

    def test_radare2_rerun_disables_a_stale_managed_binary_when_pin_validation_fails(self) -> None:
        """A second run must not build or retain an installer-owned unpinned radare2."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            local_root = temporary_path / "local"
            local_bin = local_root / "bin"
            local_bin.mkdir(parents=True)
            source = local_root / "opt" / "radare2"
            source.mkdir(parents=True)
            (source / ".git").mkdir()
            marker = temporary_path / "build-ran"
            self.write_executable(source / "configure", f"touch '{marker}'")
            self.write_executable(local_bin / "radare2", "echo stale radare2")
            self.write_ownership_marker(local_root / "opt", "radare2", local_bin / "radare2", R2_REVISION)
            fake_bin = temporary_path / "fake-bin"
            fake_bin.mkdir()
            self.write_executable(fake_bin / "git", "echo 'forced checkout failure' >&2; exit 7")
            environment = {
                "PATH": f"{local_bin}:{fake_bin}:/usr/bin:/bin",
                "CTF_TOOLS_ROOT": str(temporary_path / "CTF"),
                "CTF_TOOLS_LOCAL_BIN": str(local_bin),
                "CTF_TOOLS_LOCAL_OPT": str(local_root / "opt"),
            }
            for _ in range(2):
                result = self.run_command("bash", str(INSTALLER), "--component", "radare2", env=environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("pinned radare2 revision", result.stderr)
                self.assertFalse((local_bin / "radare2").exists())
                self.assertFalse(marker.exists())

    def test_unmarked_and_dry_run_exposures_are_preserved_on_pin_failure(self) -> None:
        """Unknown local collisions and dry runs never permit installer-owned deletion."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            for tool in ("sqlmap", "radare2"):
                local_root = temporary_path / tool / "local"
                local_bin = local_root / "bin"
                local_bin.mkdir(parents=True)
                source = local_root / "opt" / tool
                source.mkdir(parents=True)
                (source / ".git").mkdir()
                exposure = local_bin / tool
                self.write_executable(exposure, f"echo user-{tool}")
                before = (exposure.stat().st_ino, exposure.read_bytes())
                fake_bin = temporary_path / tool / "fake-bin"
                fake_bin.mkdir()
                self.write_executable(fake_bin / "git", "echo 'forced checkout failure' >&2; exit 7")
                environment = {
                    "PATH": f"{local_bin}:{fake_bin}:/usr/bin:/bin",
                    "CTF_TOOLS_ROOT": str(temporary_path / tool / "CTF"),
                    "CTF_TOOLS_LOCAL_BIN": str(local_bin),
                    "CTF_TOOLS_LOCAL_OPT": str(local_root / "opt"),
                }
                real = self.run_command("bash", str(INSTALLER), "--component", tool, env=environment)
                self.assertEqual(real.returncode, 0, real.stderr)
                self.assertTrue(exposure.exists())
                self.assertEqual((exposure.stat().st_ino, exposure.read_bytes()), before)
                dry = self.run_command("bash", str(INSTALLER), "--dry-run", "--component", tool, env=environment)
                self.assertEqual(dry.returncode, 0, dry.stderr)
                self.assertTrue(exposure.exists())
                self.assertEqual((exposure.stat().st_ino, exposure.read_bytes()), before)

    def write_ownership_marker(self, marker_root: Path, tool: str, exposure: Path, revision: str) -> None:
        marker_dir = marker_root / ".ctf-agent-tools"
        marker_dir.mkdir()
        digest = hashlib.sha256(exposure.read_bytes()).hexdigest()
        (marker_dir / f"{tool}.marker").write_text(
            f"tool={tool}\npath={exposure}\nrevision={revision}\nsha256={digest}\n",
            encoding="utf-8",
        )

    def test_skill_metadata_and_common_initializer_create_category_run_layouts(self) -> None:
        """Skill metadata and the documented common initializer agree on category workspaces."""
        for category in ("pwn", "web", "rev"):
            skill = ROOT / f"{category}-agent"
            metadata = yaml.safe_load((skill / "agents" / "openai.yaml").read_text(encoding="utf-8"))
            asset = yaml.safe_load((skill / "assets" / "challenge.yaml").read_text(encoding="utf-8"))
            self.assertEqual(metadata["interface"]["display_name"].split()[0].lower(), {"pwn": "pwn", "web": "web", "rev": "reversing"}[category])
            self.assertEqual(asset["category"], category)
        with tempfile.TemporaryDirectory() as temporary:
            event = Path(temporary) / "event"
            challenge = event / "challenges" / "demo"
            challenge.mkdir(parents=True)
            (challenge / "artifact.bin").write_bytes(b"fixture")
            for category in ("pwn", "web", "rev"):
                result = self.run_command(
                    "python3", str(ROOT / "ctf-common" / "scripts" / "init_session.py"),
                    str(challenge), "--category", category, "--event-root", str(event),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                workspace = Path(json.loads(result.stdout)["workspace"])
                self.assertTrue(workspace.is_dir())
                self.assertIn(f"runs/{category}/", workspace.as_posix())

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

if __name__ == "__main__":
    unittest.main()
