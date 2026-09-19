"""Executable contract tests for the local CTF tool bootstrap scripts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "tools" / "install-ctf-tools.sh"
SKILL_INSTALLER = ROOT / "tools" / "install-ctf-skills.sh"
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
        for script in (INSTALLER, CHECKER, SKILL_INSTALLER):
            result = self.run_command("bash", "-n", str(script))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_skill_installer_creates_all_links_and_is_idempotent(self) -> None:
        """A rerun must preserve the exact links that registered the three skills."""
        with tempfile.TemporaryDirectory() as temporary:
            skills_home = Path(temporary) / "skills"
            environment = {"CTF_SKILLS_HOME": str(skills_home)}
            first = self.run_command("bash", str(SKILL_INSTALLER), env=environment)
            self.assertEqual(first.returncode, 0, first.stderr)
            first_report = json.loads(first.stdout)
            self.assertEqual(first_report["source"], str(ROOT))
            self.assertEqual(first_report["destination"], str(skills_home))
            before: dict[str, tuple[int, str]] = {}
            for name in ("pwn-agent", "web-agent", "rev-agent"):
                link = skills_home / name
                self.assertTrue(link.is_symlink())
                self.assertEqual(link.resolve(), (ROOT / name).resolve())
                self.assertTrue((link / "SKILL.md").is_file())
                self.assertEqual(first_report["skills"][name]["status"], "installed")
                before[name] = (link.lstat().st_ino, os.readlink(link))

            second = self.run_command("bash", str(SKILL_INSTALLER), env=environment)
            self.assertEqual(second.returncode, 0, second.stderr)
            second_report = json.loads(second.stdout)
            for name in ("pwn-agent", "web-agent", "rev-agent"):
                link = skills_home / name
                self.assertEqual((link.lstat().st_ino, os.readlink(link)), before[name])
                self.assertEqual(second_report["skills"][name]["status"], "unchanged")

    def test_skill_installer_refuses_unrelated_collisions_without_replacement(self) -> None:
        """A user-owned path or unrelated symlink must survive registration unchanged."""
        for collision_kind in ("file", "directory", "symlink"):
            with self.subTest(collision_kind=collision_kind), tempfile.TemporaryDirectory() as temporary:
                temporary_path = Path(temporary)
                skills_home = temporary_path / "skills"
                skills_home.mkdir()
                collision = skills_home / "web-agent"
                if collision_kind == "file":
                    collision.write_text("user-owned\n", encoding="utf-8")
                elif collision_kind == "directory":
                    collision.mkdir()
                    (collision / "keep.txt").write_text("user-owned\n", encoding="utf-8")
                else:
                    unrelated = temporary_path / "unrelated"
                    unrelated.mkdir()
                    collision.symlink_to(unrelated)
                before_inode = collision.lstat().st_ino
                before_link = os.readlink(collision) if collision.is_symlink() else None

                result = self.run_command(
                    "bash", str(SKILL_INSTALLER),
                    env={"CTF_SKILLS_HOME": str(skills_home)},
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("refusing to replace", result.stderr)
                self.assertEqual(collision.lstat().st_ino, before_inode)
                if before_link is not None:
                    self.assertEqual(os.readlink(collision), before_link)
                elif collision_kind == "file":
                    self.assertEqual(collision.read_text(encoding="utf-8"), "user-owned\n")
                else:
                    self.assertEqual((collision / "keep.txt").read_text(encoding="utf-8"), "user-owned\n")

    def test_installer_dry_run_is_non_mutating_plan(self) -> None:
        """The dry run catches an installer that attempts package installation immediately."""
        result = self.run_command("bash", str(INSTALLER), "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/home/normalone/CTF/.venv", result.stdout)
        self.assertIn("pwntools==4.15.0", result.stdout)
        self.assertIn("github.com/ffuf/ffuf/v2@v2.1.0", result.stdout)
        self.assertIn("GOBIN=/home/normalone/CTF/.tools/bin", result.stdout)
        self.assertIn("nuclei", result.stdout)
        self.assertNotIn("@latest", result.stdout)

    def test_installer_rejects_component_without_a_value_before_mutation(self) -> None:
        """A trailing --component returns usage promptly and never creates its CTF root."""
        with tempfile.TemporaryDirectory() as temporary:
            ctf_root = Path(temporary) / "CTF"
            result = subprocess.run(
                ["bash", str(INSTALLER), "--component"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=3,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "CTF_TOOLS_ROOT": str(ctf_root)},
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("missing value for --component", result.stderr)
            self.assertIn("Usage:", result.stderr)
            self.assertFalse(ctf_root.exists())

    def test_checker_emits_one_json_capability_document(self) -> None:
        """The checker must be machine-readable even when capabilities are absent."""
        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_command(
                "bash", str(CHECKER),
                env={"CTF_SKILLS_HOME": str(Path(temporary) / "missing-skills")},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
        self.assertEqual(report["schema_version"], 1)
        self.assertIn("venv", report)
        self.assertIn("cli", report)
        self.assertIn("python", report)
        self.assertIn("mcp", report)
        self.assertIn("browser", report)
        self.assertIn("skills", report)
        for name in REQUIRED_CLIS:
            self.assert_capability(report["cli"][name])
        for name in REQUIRED_MODULES:
            self.assert_capability(report["python"][name])
        for name in ("gdb", "idalib"):
            self.assert_capability(report["mcp"][name])
        self.assert_capability(report["browser"]["chrome"])
        for name in ("pwn-agent", "web-agent", "rev-agent"):
            self.assert_capability(report["skills"][name])
            self.assertEqual(report["skills"][name]["status"], "degraded")
        self.assertEqual(report["skill_summary"], {"available": 0, "degraded": 3})

    def test_checker_reports_registered_skills_as_available(self) -> None:
        """Only resolved skill links with regular SKILL.md files are available."""
        with tempfile.TemporaryDirectory() as temporary:
            skills_home = Path(temporary) / "skills"
            skills_home.mkdir()
            for name in ("pwn-agent", "web-agent", "rev-agent"):
                (skills_home / name).symlink_to(ROOT / name)

            report = self.checker_report({"CTF_SKILLS_HOME": str(skills_home)})

        for name in ("pwn-agent", "web-agent", "rev-agent"):
            self.assertEqual(report["skills"][name]["status"], "available")
            self.assertEqual(report["skills"][name]["path"], str((ROOT / name).resolve()))
        self.assertEqual(report["skill_summary"], {"available": 3, "degraded": 0})

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
                    "CTF_TOOLS_ROOT": str(temporary_path / "CTF"),
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
            ctf_root = temporary_path / "CTF"
            result = self.run_command(
                "bash", str(INSTALLER), "--component", "sqlmap",
                env={
                    "PATH": f"{fake_bin}:/usr/bin:/bin",
                    "CTF_TOOLS_ROOT": str(ctf_root),
                },
            )
            wrapper = ctf_root / ".tools" / "bin" / "sqlmap"
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
            ctf_root = temporary_path / "CTF"
            result = self.run_command(
                "bash", str(INSTALLER), "--component", "radare2",
                env={
                    "PATH": f"{fake_bin}:/usr/bin:/bin",
                    "CTF_TOOLS_ROOT": str(ctf_root),
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
            local_root = temporary_path / "CTF"
            local_bin = local_root / ".tools" / "bin"
            local_bin.mkdir(parents=True)
            source = local_root / ".tools" / "src" / "sqlmap"
            source.mkdir(parents=True)
            (source / ".git").mkdir()
            (source / "sqlmap.py").write_text("stale source\n", encoding="utf-8")
            self.write_executable(local_bin / "sqlmap", "echo stale sqlmap")
            (local_root / ".tools" / "state").mkdir(parents=True)
            self.write_dedicated_marker(local_root / ".tools" / "state", "sqlmap", local_bin / "sqlmap", SQLMAP_REVISION)
            fake_bin = temporary_path / "fake-bin"
            fake_bin.mkdir()
            self.write_executable(fake_bin / "git", "echo 'forced checkout failure' >&2; exit 7")
            environment = {
                "PATH": f"{local_bin}:{fake_bin}:/usr/bin:/bin",
                "CTF_TOOLS_ROOT": str(local_root),
            }
            for _ in range(2):
                result = self.run_command("bash", str(INSTALLER), "--component", "sqlmap", env=environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("pinned sqlmap revision", result.stderr)
                self.assertFalse((local_bin / "sqlmap").exists())

    def test_sqlmap_valid_managed_clone_is_not_recloned_on_rerun(self) -> None:
        """A valid managed sqlmap checkout is pinned again without a mutable clone attempt."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            ctf_root = temporary_path / "CTF"
            source = ctf_root / ".tools" / "src" / "sqlmap"
            (source / ".git").mkdir(parents=True)
            (source / "sqlmap.py").write_text("print('fixture')\n", encoding="utf-8")
            fake_bin = temporary_path / "fake-bin"
            fake_bin.mkdir()
            clone_marker = temporary_path / "clone-ran"
            self.write_executable(
                fake_bin / "git",
                f'if [ "$1" = clone ]; then touch "{clone_marker}"; exit 66; fi\n'
                f'if [ "$1" = -C ] && [ "$3" = rev-parse ]; then echo "{SQLMAP_REVISION}"; exit 0; fi\n'
                'if [ "$1" = -C ] && [ "$3" = checkout ]; then exit 0; fi\nexit 1',
            )
            result = self.run_command(
                "bash", str(INSTALLER), "--component", "sqlmap",
                env={"PATH": f"{fake_bin}:/usr/bin:/bin", "CTF_TOOLS_ROOT": str(ctf_root)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(clone_marker.exists())
            self.assertTrue((ctf_root / ".tools" / "bin" / "sqlmap").is_file())

    def test_radare2_rerun_disables_a_stale_managed_binary_when_pin_validation_fails(self) -> None:
        """A second run must not build or retain an installer-owned unpinned radare2."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            local_root = temporary_path / "CTF"
            local_bin = local_root / ".tools" / "bin"
            local_bin.mkdir(parents=True)
            source = local_root / ".tools" / "src" / "radare2"
            source.mkdir(parents=True)
            (source / ".git").mkdir()
            marker = temporary_path / "build-ran"
            self.write_executable(source / "configure", f"touch '{marker}'")
            self.write_executable(local_bin / "radare2", "echo stale radare2")
            (local_root / ".tools" / "state").mkdir(parents=True)
            self.write_dedicated_marker(local_root / ".tools" / "state", "radare2", local_bin / "radare2", R2_REVISION)
            fake_bin = temporary_path / "fake-bin"
            fake_bin.mkdir()
            self.write_executable(fake_bin / "git", "echo 'forced checkout failure' >&2; exit 7")
            environment = {
                "PATH": f"{local_bin}:{fake_bin}:/usr/bin:/bin",
                "CTF_TOOLS_ROOT": str(local_root),
            }
            for _ in range(2):
                result = self.run_command("bash", str(INSTALLER), "--component", "radare2", env=environment)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("pinned radare2 revision", result.stderr)
                self.assertFalse((local_bin / "radare2").exists())
                self.assertFalse(marker.exists())

    def test_unmarked_and_dry_run_exposures_are_preserved_on_pin_failure(self) -> None:
        """Dedicated unmarked collisions and dry runs are retained byte-for-byte."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            for tool in ("sqlmap", "radare2"):
                ctf_root = temporary_path / tool / "CTF"
                local_bin = ctf_root / ".tools" / "bin"
                state = ctf_root / ".tools" / "state"
                source = ctf_root / ".tools" / "src" / tool
                local_bin.mkdir(parents=True)
                state.mkdir(parents=True)
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
                    "CTF_TOOLS_ROOT": str(ctf_root),
                }
                real = self.run_command("bash", str(INSTALLER), "--component", tool, env=environment)
                self.assertEqual(real.returncode, 0, real.stderr)
                self.assertIn("unmarked or mismatching", real.stderr)
                self.assertTrue(exposure.exists())
                self.assertEqual((exposure.stat().st_ino, exposure.read_bytes()), before)
                dry = self.run_command("bash", str(INSTALLER), "--dry-run", "--component", tool, env=environment)
                self.assertEqual(dry.returncode, 0, dry.stderr)
                self.assertTrue(exposure.exists())
                self.assertEqual((exposure.stat().st_ino, exposure.read_bytes()), before)

    def test_dedicated_managed_bin_never_deletes_shared_user_tool_and_is_preferred(self) -> None:
        """A failed pin disables only marker-owned CTF .tools exposure, never ~/.local/bin."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            ctf_root = temporary_path / "CTF"
            managed_bin = ctf_root / ".tools" / "bin"
            state = ctf_root / ".tools" / "state"
            source = ctf_root / ".tools" / "src" / "sqlmap"
            shared_bin = temporary_path / "shared-bin"
            for directory in (managed_bin, state, source, shared_bin):
                directory.mkdir(parents=True, exist_ok=True)
            (source / ".git").mkdir()
            (source / "sqlmap.py").write_text("stale source\n", encoding="utf-8")
            dedicated = managed_bin / "sqlmap"
            shared = shared_bin / "sqlmap"
            self.write_executable(dedicated, "echo managed sqlmap")
            self.write_executable(shared, "echo user sqlmap")
            self.write_dedicated_marker(state, "sqlmap", dedicated, SQLMAP_REVISION)
            shared_before = (shared.stat().st_ino, shared.read_bytes())
            fake_bin = temporary_path / "fake-bin"
            fake_bin.mkdir()
            self.write_executable(fake_bin / "git", "echo 'forced checkout failure' >&2; exit 7")
            environment = {"PATH": f"{managed_bin}:{shared_bin}:{fake_bin}:/usr/bin:/bin", "CTF_TOOLS_ROOT": str(ctf_root)}
            dedicated_before = (dedicated.stat().st_ino, dedicated.read_bytes())
            marker_before = (state / "sqlmap.marker").read_bytes()
            dry = self.run_command("bash", str(INSTALLER), "--dry-run", "--component", "sqlmap", env=environment)
            self.assertEqual(dry.returncode, 0, dry.stderr)
            self.assertTrue(dedicated.exists())
            self.assertEqual((dedicated.stat().st_ino, dedicated.read_bytes()), dedicated_before)
            self.assertEqual((state / "sqlmap.marker").read_bytes(), marker_before)
            result = self.run_command("bash", str(INSTALLER), "--component", "sqlmap", env=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(dedicated.exists())
            self.assertTrue(shared.exists())
            self.assertEqual((shared.stat().st_ino, shared.read_bytes()), shared_before)
            env_file = ctf_root / ".tools" / "env.sh"
            env_check = self.run_command("bash", "-n", str(env_file))
            self.assertEqual(env_check.returncode, 0, env_check.stderr)
            enabled = self.run_command("bash", "-c", f'. "{env_file}"; printf %s "$PATH"')
            self.assertTrue(enabled.stdout.startswith(f"{managed_bin}:"))
            self.assertTrue(shared.exists())

    def test_managed_env_quotes_special_root_without_executing_it(self) -> None:
        """Sourcing env.sh handles shell metacharacters literally and cannot run a marker command."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            sentinel = temporary_path / "executed"
            ctf_root = temporary_path / ("CTF space ' $(touch " + str(sentinel) + ")")
            fake_bin = temporary_path / "fake-bin"
            fake_bin.mkdir()
            self.write_executable(fake_bin / "git", "echo 'forced checkout failure' >&2; exit 7")
            result = self.run_command(
                "bash", str(INSTALLER), "--component", "sqlmap",
                env={"PATH": f"{fake_bin}:/usr/bin:/bin", "CTF_TOOLS_ROOT": str(ctf_root)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            env_file = ctf_root / ".tools" / "env.sh"
            syntax = self.run_command("bash", "-n", str(env_file))
            self.assertEqual(syntax.returncode, 0, syntax.stderr)
            sourced = self.run_command("bash", "-c", '. "$1"; printf %s "$PATH"', "bash", str(env_file))
            self.assertEqual(sourced.returncode, 0, sourced.stderr)
            self.assertTrue(sourced.stdout.startswith(f"{ctf_root / '.tools' / 'bin'}:"))
            managed_bin = ctf_root / ".tools" / "bin"
            self.write_executable(managed_bin / "managed-tool", "exit 0")
            unset_path = self.run_command("/bin/bash", "-c", 'set -u; unset PATH; . "$1"; printf "%s|%s" "$PATH" "$(command -v managed-tool)"', "bash", str(env_file))
            self.assertEqual(unset_path.returncode, 0, unset_path.stderr)
            self.assertEqual(unset_path.stdout, f"{managed_bin}|{managed_bin / 'managed-tool'}")
            empty_path = self.run_command("/bin/bash", "-c", 'set -u; PATH=; . "$1"; printf "%s|%s" "$PATH" "$(command -v managed-tool)"', "bash", str(env_file))
            self.assertEqual(empty_path.returncode, 0, empty_path.stderr)
            self.assertEqual(empty_path.stdout, f"{managed_bin}|{managed_bin / 'managed-tool'}")
            inherited_path = self.run_command("/bin/bash", "-c", 'set -u; . "$1"; printf %s "$PATH"', "bash", str(env_file), env={"PATH": "/existing/bin:/another bin"})
            self.assertEqual(inherited_path.returncode, 0, inherited_path.stderr)
            self.assertEqual(inherited_path.stdout, f"{managed_bin}:/existing/bin:/another bin")
            managed_lib = ctf_root / ".tools" / "lib"
            unset_libraries = self.run_command("bash", "-c", 'unset LD_LIBRARY_PATH; . "$1"; printf %s "${LD_LIBRARY_PATH-}"', "bash", str(env_file))
            self.assertEqual(unset_libraries.returncode, 0, unset_libraries.stderr)
            self.assertEqual(unset_libraries.stdout, str(managed_lib))
            empty_libraries = self.run_command("bash", "-c", 'LD_LIBRARY_PATH=; . "$1"; printf %s "${LD_LIBRARY_PATH-}"', "bash", str(env_file))
            self.assertEqual(empty_libraries.returncode, 0, empty_libraries.stderr)
            self.assertEqual(empty_libraries.stdout, str(managed_lib))
            inherited_libraries = self.run_command(
                "bash", "-c", '. "$1"; printf %s "${LD_LIBRARY_PATH-}"', "bash", str(env_file),
                env={"LD_LIBRARY_PATH": "/existing/lib:/another lib"},
            )
            self.assertEqual(inherited_libraries.returncode, 0, inherited_libraries.stderr)
            self.assertEqual(inherited_libraries.stdout, f"{managed_lib}:/existing/lib:/another lib")
            self.assertFalse(sentinel.exists())

    def test_installer_rejects_newline_in_managed_environment_root(self) -> None:
        """Newlines are explicitly rejected instead of being emitted into shell source."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            ctf_root = temporary_path / "bad\nroot"
            result = self.run_command(
                "bash", str(INSTALLER), "--component", "sqlmap",
                env={"PATH": "/usr/bin:/bin", "CTF_TOOLS_ROOT": str(ctf_root)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("managed tool environment", result.stdout)
            self.assertFalse((ctf_root / ".tools" / "env.sh").exists())

    def test_checker_prefers_dedicated_ctf_tool_bin_over_shared_path(self) -> None:
        """A valid managed executable is reported from CTF/.tools before a shared PATH twin."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            ctf_root = temporary_path / "CTF"
            managed_bin = ctf_root / ".tools" / "bin"
            shared_bin = temporary_path / "shared-bin"
            managed_bin.mkdir(parents=True)
            shared_bin.mkdir()
            self.write_executable(managed_bin / "ffuf", "echo 'ffuf version: 2.1.0'")
            self.write_executable(shared_bin / "ffuf", "echo 'ffuf version: 9.9.9'")
            config = temporary_path / "config.toml"
            config.write_text("", encoding="utf-8")
            report = self.checker_report(
                {
                    "CTF_TOOLS_ROOT": str(ctf_root),
                    "CTF_TOOLS_CONFIG": str(config),
                    "CTF_TOOLS_BROWSER_COMMANDS": "missing-browser",
                    "CTF_TOOLS_PLAYWRIGHT_CACHE": str(temporary_path / "missing-cache"),
                    "PATH": f"{shared_bin}:{os.environ['PATH']}",
                }
            )
        self.assertEqual(report["cli"]["ffuf"]["status"], "available")
        self.assertEqual(report["cli"]["ffuf"]["path"], str(managed_bin / "ffuf"))
        self.assertEqual(report["cli"]["ffuf"]["source"], "managed .tools")

    def test_checker_probes_managed_radare2_with_managed_libraries(self) -> None:
        """The checker supplies CTF/.tools/lib for a dedicated radare2 probe."""
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            ctf_root = temporary_path / "CTF"
            managed_bin = ctf_root / ".tools" / "bin"
            managed_lib = ctf_root / ".tools" / "lib"
            managed_bin.mkdir(parents=True)
            managed_lib.mkdir()
            (managed_bin / "radare2").write_text(
                f'#!/bin/bash\n[ "$PATH" = "{managed_bin}" ] || exit 126\n'
                f'[ "$LD_LIBRARY_PATH" = "{managed_lib}" ] || exit 127\necho "radare2 5.9.9"\n',
                encoding="utf-8",
            )
            (managed_bin / "radare2").chmod(0o755)
            config = temporary_path / "config.toml"
            config.write_text("", encoding="utf-8")
            result = self.run_command(
                "/bin/bash", str(CHECKER),
                env={
                    "CTF_TOOLS_ROOT": str(ctf_root),
                    "CTF_TOOLS_CONFIG": str(config),
                    "CTF_TOOLS_VENV": str(temporary_path / "missing-venv"),
                    "CTF_TOOLS_BROWSER_COMMANDS": "missing-browser",
                    "CTF_TOOLS_PLAYWRIGHT_CACHE": str(temporary_path / "missing-cache"),
                    "LD_LIBRARY_PATH": "",
                    "PATH": "",
                    "CTF_TOOLS_CHECKER_PYTHON": sys.executable,
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
        self.assertEqual(report["cli"]["radare2"]["status"], "available")
        self.assertEqual(report["cli"]["radare2"]["source"], "managed .tools")

    def write_dedicated_marker(self, state: Path, tool: str, exposure: Path, revision: str) -> None:
        digest = hashlib.sha256(exposure.read_bytes()).hexdigest()
        (state / f"{tool}.marker").write_text(
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
