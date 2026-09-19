import fcntl
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = REPO_ROOT / "rev-agent"
COMMON_SCRIPTS = REPO_ROOT / "ctf-common" / "scripts"
SCRIPTS = SKILL_DIR / "scripts"
sys.path.insert(0, str(COMMON_SCRIPTS))
sys.path.insert(0, str(SCRIPTS))

from ctf_intake import IntakeRequest  # noqa: E402
from ctf_workspace import create_session  # noqa: E402
from init_rev_state import init_rev_state  # noqa: E402
import record_clue as rev_state  # noqa: E402
from record_clue import (  # noqa: E402
    record_clue,
    record_contradiction,
    record_experiment,
    record_hypothesis,
)


def run_script(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(path), *args],
        text=True,
        capture_output=True,
        check=False,
    )


class RevAgentTests(unittest.TestCase):
    def make_workspace(self, root: Path, session_id: str) -> Path:
        event_root = root / "event"
        challenge = event_root / "challenges" / "crackme"
        challenge.mkdir(parents=True, exist_ok=True)
        (challenge / "challenge.yaml").write_text(
            "id: crackme\nauthorized: true\nbinary: chall\n",
            encoding="utf-8",
        )
        target = challenge / "chall"
        target.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        target.chmod(0o755)
        result = run_script(
            COMMON_SCRIPTS / "init_session.py",
            str(challenge),
            "--category", "rev",
            "--event-root", str(event_root),
            "--session-id", session_id,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return Path(json.loads(result.stdout)["workspace"])

    def target_path(self, workspace: Path) -> Path:
        return Path(json.loads((workspace / "session.json").read_text())["challenge"]) / "chall"

    def test_metadata_and_challenge_asset_are_structured_for_reversing(self) -> None:
        metadata = yaml.safe_load(
            (SKILL_DIR / "agents" / "openai.yaml").read_text(encoding="utf-8")
        )
        challenge = yaml.safe_load(
            (SKILL_DIR / "assets" / "challenge.yaml").read_text(encoding="utf-8")
        )

        self.assertEqual(metadata["interface"]["display_name"], "Reversing Agent")
        self.assertTrue(metadata["policy"]["allow_implicit_invocation"])
        self.assertIn("https://h4c.team/posts/49", metadata["sources"])
        self.assertEqual(challenge["category"], "rev")

    def test_preinit_selection_requires_contained_regular_nonsymlink_file(self) -> None:
        for relative in ("SKILL.md", "references/safety.md"):
            with self.subTest(relative=relative):
                instructions = (SKILL_DIR / relative).read_text(encoding="utf-8")
                normalized = " ".join(instructions.split())

                self.assertIn("regular, non-symlink file", normalized)
                self.assertIn("resolved path remains inside the challenge", normalized)
                self.assertIn("common initializer", normalized)

    def test_yaml_free_intake_binds_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            challenge = root / "event" / "challenges" / "serial-checker"
            challenge.mkdir(parents=True)
            target = challenge / "chall"
            ran = challenge / "ran"
            target.write_text(
                "#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\n"
                f"Path({str(ran)!r}).write_text('ran', encoding='utf-8')\n"
                "sys.stdout.buffer.write(b'H4C{generated-manifest}\\n')\n"
                "sys.stdout.buffer.flush()\n"
                "sys.stderr.buffer.write(b'raw-stderr\\xff')\n",
                encoding="utf-8",
            )
            target.chmod(0o755)

            row = create_session(
                challenge,
                "rev",
                intake=IntakeRequest(
                    statement="Find the correct serial and return H4C{...}",
                    binary="chall",
                    flag_pattern=r"H4C\{[^}\r\n]+\}",
                ),
            )
            self.assertFalse((challenge / "challenge.yaml").exists())
            self.assertEqual(row["intake"]["target_status"], "bound")
            workspace = Path(row["workspace"])
            request = json.loads(
                (workspace / "challenge-request.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                request["statement"],
                "Find the correct serial and return H4C{...}",
            )
            self.assertEqual(request["binary"], "chall")
            self.assertIn(
                "binary: chall",
                (workspace / "challenge.resolved.yaml").read_text(encoding="utf-8"),
            )
            init_rev_state(workspace)

            result = run_script(
                SKILL_DIR / "assets" / "solver.py",
                "--workspace", str(workspace),
                "--binary", str(target),
                "--candidate", "correct-serial",
                "--verify",
            )

            self.assertEqual(result.returncode, 0, result.stdout)
            payload = json.loads(result.stdout)
            self.assertEqual(Path(payload["sent"]).read_bytes(), b"correct-serial\n")
            self.assertEqual(
                Path(payload["output"]).read_bytes(),
                b"H4C{generated-manifest}\nraw-stderr\xff",
            )
            attestation = json.loads(
                Path(payload["attestation"]).read_text(encoding="utf-8")
            )
            self.assertEqual(attestation["source_target"], f"local:{target}")
            self.assertEqual(attestation["output"]["path"], payload["output"])
            self.assertEqual(payload["verification"]["status"], "verified")

            ran.unlink()
            foreign = root / "foreign"
            foreign.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
            foreign.chmod(0o755)
            rejected = run_script(
                SKILL_DIR / "assets" / "solver.py",
                "--workspace", str(workspace),
                "--binary", str(foreign),
                "--candidate", "must-not-run",
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertFalse(ran.exists())

            no_binary = root / "event" / "challenges" / "needs-selection"
            no_binary.mkdir()
            pending = create_session(
                no_binary,
                "rev",
                intake=IntakeRequest(statement="Find the correct serial"),
            )
            self.assertEqual(pending["intake"]["target_status"], "needs_selection")
            pending_workspace = Path(pending["workspace"])
            self.assertFalse((pending_workspace / "rev" / "oracle").exists())

    def test_init_creates_session_local_ida_gdb_and_oracle_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-layout")
            state = init_rev_state(workspace)

            self.assertEqual(Path(state["workspace"]), workspace)
            for name in ("ida_dir", "gdb_dir", "oracle_dir"):
                self.assertTrue(Path(state[name]).is_dir())
                self.assertTrue(Path(state[name]).is_relative_to(workspace))
            self.assertEqual(json.loads(Path(state["clues"]).read_text())["clues"], [])
            self.assertEqual(json.loads(Path(state["hypotheses"]).read_text())["hypotheses"], [])
            self.assertEqual(json.loads(Path(state["contradictions"]).read_text())["contradictions"], [])

    def test_init_rejects_a_symlinked_rev_directory_without_writing_outside(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = self.make_workspace(root, "rev-init-symlink")
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_text("unchanged", encoding="utf-8")
            (workspace / "rev").symlink_to(outside, target_is_directory=True)

            with self.assertRaises(ValueError):
                init_rev_state(workspace)

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")
            self.assertEqual(list(outside.iterdir()), [sentinel])

    def test_replaced_rev_directory_rejects_state_and_oracle_operations_without_outside_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = self.make_workspace(root, "rev-state-symlink")
            init_rev_state(workspace)
            hypothesis = record_hypothesis(workspace, "base", "break at base")
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_text("unchanged", encoding="utf-8")
            rev = workspace / "rev"
            rev.rename(workspace / "rev-moved")
            rev.symlink_to(outside, target_is_directory=True)

            for operation in (
                lambda: record_clue(workspace, "gdb/a", "clue", next_action="trace"),
                lambda: record_hypothesis(workspace, "second", "break at second"),
                lambda: record_contradiction(workspace, hypothesis["id"], "gdb/b", "conflict"),
            ):
                with self.subTest(operation=operation):
                    with self.assertRaises(ValueError):
                        operation()
            target = self.target_path(workspace)
            solver = run_script(
                SKILL_DIR / "assets" / "solver.py", "--workspace", str(workspace),
                "--binary", str(target), "--candidate", "input",
            )
            self.assertEqual(solver.returncode, 2)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")
            self.assertEqual(list(outside.iterdir()), [sentinel])

    def test_held_rev_descriptor_keeps_ledger_operation_on_original_directory_after_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = self.make_workspace(root, "rev-held-directory")
            init_rev_state(workspace)
            rev = workspace / "rev"
            with rev_state._lock(workspace, ".clues.lock") as (_rev, directory):
                moved = workspace / "rev-held"
                rev.rename(moved)
                rev.mkdir()
                attacker = {"schema_version": 1, "clues": [{"id": "attacker"}]}
                (rev / "clues.json").write_text(json.dumps(attacker), encoding="utf-8")
                sentinel = rev / "sentinel"
                sentinel.write_text("unchanged", encoding="utf-8")

                payload, entries = rev_state._load(directory, "clues.json", "clues")
                entries.append({"id": "clue-0001"})
                rev_state._atomic_json(directory, "clues.json", payload)

            self.assertEqual(json.loads((moved / "clues.json").read_text())["clues"], [{"id": "clue-0001"}])
            self.assertEqual(json.loads((rev / "clues.json").read_text()), attacker)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")

    def test_wal_publish_failure_leaves_no_partial_record_or_overwrites_good_journal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-wal-publish")
            init_rev_state(workspace)
            journal = workspace / "rev" / ".state.transaction.json"
            with rev_state._lock(workspace, ".state.lock") as (_rev, directory):
                with self.assertRaises(ValueError):
                    rev_state._write_new_json(directory, journal.name, {"bad": {"not-json"}})
                self.assertFalse(journal.exists())
                good = {"schema_version": 1, "hypotheses": {"schema_version": 1, "hypotheses": []}, "contradictions": {"schema_version": 1, "contradictions": []}}
                rev_state._write_new_json(directory, journal.name, good)
                before = journal.read_bytes()
                with self.assertRaises(ValueError):
                    rev_state._write_new_json(directory, journal.name, {"bad": {"still-not-json"}})
                self.assertEqual(journal.read_bytes(), before)
            recovered = record_hypothesis(workspace, "recovered", "break at recovered")
            self.assertEqual(recovered["status"], "active")
            self.assertFalse(journal.exists())

    def test_clue_requires_next_action(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-clue-required")
            with self.assertRaises(ValueError):
                record_clue(workspace, evidence="strings.txt", summary="AES constants")

    def test_clue_records_evidence_xrefs_functions_and_next_action(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-clue")
            entry = record_clue(
                workspace,
                evidence="artifacts/strings.txt",
                summary="comparison constant near input validation",
                xrefs=["0x4012ab", "strcmp@plt"],
                functions=["main", "check_password"],
                next_action="trace input bytes to the comparison",
            )

            ledger = json.loads((workspace / "rev" / "clues.json").read_text())
            self.assertEqual(ledger["clues"], [entry])
            self.assertEqual(entry["xrefs"], ["0x4012ab", "strcmp@plt"])
            self.assertEqual(entry["functions"], ["main", "check_password"])
            self.assertEqual(entry["next_action"], "trace input bytes to the comparison")

    def test_hypothesis_requires_falsifying_test_and_is_rejected_after_two_no_progress_experiments(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-hypothesis")
            with self.assertRaises(ValueError):
                record_hypothesis(workspace, "input is XORed", falsifying_test="")

            hypothesis = record_hypothesis(
                workspace,
                "input is XORed with a fixed key",
                falsifying_test="compare a runtime input trace with XOR prediction",
            )
            first = record_experiment(
                workspace,
                hypothesis["id"],
                evidence="gdb/trace-1.txt",
                result="trace did not expose the comparison",
            )
            second = record_experiment(
                workspace,
                hypothesis["id"],
                evidence="gdb/trace-2.txt",
                result="second trace also did not discriminate the hypothesis",
            )

            self.assertEqual(first["status"], "active")
            self.assertEqual(first["no_progress"], 1)
            self.assertEqual(second["status"], "rejected")
            self.assertEqual(second["no_progress"], 2)
            ledger = json.loads((workspace / "rev" / "hypotheses.json").read_text())
            self.assertEqual(ledger["hypotheses"][0]["falsifying_test"], hypothesis["falsifying_test"])

    def test_oracle_template_executes_target_and_preserves_output_in_session(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-oracle")
            init_rev_state(workspace)
            target = self.target_path(workspace)
            target.write_text(
                "#!/usr/bin/env python3\nimport sys\nprint('accepted:' + sys.stdin.read().strip())\n",
                encoding="utf-8",
            )
            target.chmod(0o755)
            output = workspace / "rev" / "oracle" / "trial.txt"

            result = run_script(
                SKILL_DIR / "assets" / "solver.py",
                "--workspace", str(workspace),
                "--binary", str(target),
                "--candidate", "flag{oracle}",
                "--output", str(output),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["returncode"], 0)
            self.assertEqual(output.read_text(encoding="utf-8"), "accepted:flag{oracle}\n")
            attestation = Path(payload["attestation"])
            record = json.loads(attestation.read_text(encoding="utf-8"))
            self.assertEqual(record["source_target"], f"local:{target}")
            self.assertEqual(record["output"]["path"], str(output))

    def test_oracle_saves_sent_input_and_rejects_an_echoed_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-oracle-echo")
            init_rev_state(workspace)
            target = self.target_path(workspace)
            target.write_text(
                "#!/usr/bin/env python3\nimport sys\nprint(sys.stdin.read().strip())\n",
                encoding="utf-8",
            )
            target.chmod(0o755)

            result = run_script(
                SKILL_DIR / "assets" / "solver.py",
                "--workspace", str(workspace),
                "--binary", str(target),
                "--candidate", "FLAG{echoed}",
                "--verify",
            )

            self.assertEqual(result.returncode, 2, result.stderr)
            payload = json.loads(result.stdout)
            sent = Path(payload["sent"])
            self.assertTrue(sent.is_file())
            self.assertTrue(sent.is_relative_to(workspace / "rev" / "oracle"))
            self.assertEqual(sent.read_text(encoding="utf-8"), "FLAG{echoed}\n")
            self.assertEqual(payload["verification"]["status"], "unverified")
            self.assertEqual(payload["verification"]["reason"], "candidate_was_user_input")

    def test_oracle_preserves_raw_non_utf8_stdout_and_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-oracle-raw")
            target = self.target_path(workspace)
            target.write_text(
                "#!/usr/bin/env python3\nimport sys\n"
                "sys.stdout.buffer.write(b'\\xffstdout'); sys.stdout.buffer.flush()\n"
                "sys.stderr.buffer.write(b'\\x80stderr'); sys.stderr.buffer.flush()\n",
                encoding="utf-8",
            )
            target.chmod(0o755)

            result = run_script(
                SKILL_DIR / "assets" / "solver.py",
                "--workspace", str(workspace), "--binary", str(target), "--candidate", "input",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(Path(payload["output"]).read_bytes(), b"\xffstdout\x80stderr")
            self.assertEqual(Path(payload["sent"]).read_bytes(), b"input\n")
            self.assertTrue(Path(payload["attestation"]).is_file())

    def test_oracle_preserves_partial_raw_output_after_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-oracle-timeout")
            target = self.target_path(workspace)
            target.write_text(
                "#!/usr/bin/env python3\nimport sys, time\n"
                "sys.stdout.buffer.write(b'\\xffpartial'); sys.stdout.buffer.flush()\n"
                "time.sleep(2)\n",
                encoding="utf-8",
            )
            target.chmod(0o755)

            result = run_script(
                SKILL_DIR / "assets" / "solver.py",
                "--workspace", str(workspace), "--binary", str(target),
                "--candidate", "input", "--timeout", "0.05",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["timed_out"])
            self.assertIsNone(payload["returncode"])
            self.assertEqual(Path(payload["output"]).read_bytes(), b"\xffpartial")
            self.assertTrue(Path(payload["attestation"]).is_file())

    def test_oracle_rejects_manifest_mismatch_and_symlinked_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = self.make_workspace(root, "rev-oracle-binding")
            target = self.target_path(workspace)
            foreign = root / "foreign.py"
            foreign.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            foreign.chmod(0o755)
            mismatch = run_script(
                SKILL_DIR / "assets" / "solver.py",
                "--workspace", str(workspace), "--binary", str(foreign), "--candidate", "input",
            )
            self.assertEqual(mismatch.returncode, 2)
            self.assertIn("manifest binary", json.loads(mismatch.stdout)["error"])

            target.unlink()
            target.symlink_to(foreign)
            symlink = run_script(
                SKILL_DIR / "assets" / "solver.py",
                "--workspace", str(workspace), "--binary", str(target), "--candidate", "input",
            )
            self.assertEqual(symlink.returncode, 2)
            self.assertIn("manifest binary", json.loads(symlink.stdout)["error"])
            self.assertFalse((workspace / "rev" / "oracle").exists())

    def test_oracle_rejects_colliding_evidence_paths_before_running_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = self.make_workspace(root, "rev-oracle-collision")
            init_rev_state(workspace)
            ran = root / "target-ran"
            target = self.target_path(workspace)
            target.write_text(
                "#!/usr/bin/env python3\nfrom pathlib import Path\n"
                f"Path({str(ran)!r}).write_text('ran')\n",
                encoding="utf-8",
            )
            target.chmod(0o755)
            oracle = workspace / "rev" / "oracle"
            for output, sent in ((oracle / "shared.out", oracle / "shared.out"), (oracle / "derived.sent", None)):
                with self.subTest(output=output.name):
                    command = [
                        SKILL_DIR / "assets" / "solver.py",
                        "--workspace", str(workspace),
                        "--binary", str(target),
                        "--candidate", "candidate",
                        "--output", str(output),
                    ]
                    if sent is not None:
                        command.extend(("--sent", str(sent)))
                    result = run_script(*command)

                    self.assertEqual(result.returncode, 2)
                    self.assertIn("must differ", json.loads(result.stdout)["error"])
                    self.assertFalse(output.exists())
                    self.assertFalse(ran.exists())

    def test_oracle_directory_replacement_cannot_write_outside_session(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = self.make_workspace(root, "rev-oracle-dir-swap")
            init_rev_state(workspace)
            oracle = workspace / "rev" / "oracle"
            outside = root / "outside"
            outside.mkdir()
            moved = workspace / "rev" / "oracle-moved"
            target = self.target_path(workspace)
            target.write_text(
                "#!/usr/bin/env python3\nfrom pathlib import Path\n"
                f"Path({str(oracle)!r}).rename({str(moved)!r})\n"
                f"Path({str(oracle)!r}).symlink_to({str(outside)!r}, target_is_directory=True)\n",
                encoding="utf-8",
            )
            target.chmod(0o755)
            output = oracle / "capture.out"

            result = run_script(
                SKILL_DIR / "assets" / "solver.py",
                "--workspace", str(workspace), "--binary", str(target),
                "--candidate", "input", "--output", str(output),
            )

            self.assertEqual(result.returncode, 2)
            self.assertFalse((outside / output.name).exists())
            self.assertFalse((outside / "capture.sent").exists())

    def test_pending_contradiction_transaction_repairs_one_sided_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-state-recover")
            state = init_rev_state(workspace)
            hypothesis = record_hypothesis(workspace, "base", "break at base")
            hypotheses_path = Path(state["hypotheses"])
            contradictions_path = Path(state["contradictions"])
            hypotheses = json.loads(hypotheses_path.read_text())
            contradictions = json.loads(contradictions_path.read_text())
            contradiction = {
                "id": "contradiction-0001", "hypothesis_id": hypothesis["id"],
                "evidence": "gdb/conflict.txt", "summary": "conflict", "recorded_at": "now",
            }
            hypotheses["hypotheses"][0]["contradiction_ids"] = [contradiction["id"]]
            contradictions["contradictions"] = [contradiction]
            journal = workspace / "rev" / ".state.transaction.json"
            journal.write_text(json.dumps({"schema_version": 1, "hypotheses": hypotheses, "contradictions": contradictions}), encoding="utf-8")
            hypotheses_path.write_text(json.dumps(hypotheses), encoding="utf-8")

            result = run_script(
                SCRIPTS / "record_clue.py", "experiment", "--workspace", str(workspace),
                "--hypothesis-id", hypothesis["id"], "--evidence", "gdb/trace.txt",
                "--result", "reached", "--progress",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(journal.exists())
            repaired = json.loads(contradictions_path.read_text())["contradictions"]
            self.assertEqual(repaired, [contradiction])
            base = json.loads(hypotheses_path.read_text())["hypotheses"][0]
            self.assertEqual(base["contradiction_ids"], [contradiction["id"]])

    def test_malformed_pending_transaction_preserves_ledgers_for_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-state-invalid-journal")
            state = init_rev_state(workspace)
            record_hypothesis(workspace, "base", "break at base")
            hypotheses_path = Path(state["hypotheses"])
            contradictions_path = Path(state["contradictions"])
            original_hypotheses = hypotheses_path.read_bytes()
            original_contradictions = contradictions_path.read_bytes()
            journal = workspace / "rev" / ".state.transaction.json"
            invalid_journals = [
                {},
                {
                    "schema_version": 1,
                    "hypotheses": {"schema_version": 1, "hypotheses": [
                        {"id": "hypothesis-0001", "statement": "a", "falsifying_test": "b",
                         "status": "active", "no_progress": 0, "experiments": [],
                         "contradiction_ids": ["contradiction-0001"], "created_at": "now"},
                        {"id": "hypothesis-0001", "statement": "c", "falsifying_test": "d",
                         "status": "active", "no_progress": 0, "experiments": [],
                         "contradiction_ids": [], "created_at": "now"},
                    ]},
                    "contradictions": {"schema_version": 1, "contradictions": []},
                },
            ]
            for payload in invalid_journals:
                with self.subTest(payload=payload):
                    journal.write_text(json.dumps(payload), encoding="utf-8")
                    result = run_script(
                        SCRIPTS / "record_clue.py", "hypothesis", "--workspace", str(workspace),
                        "--statement", "new", "--falsifying-test", "break at new",
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(hypotheses_path.read_bytes(), original_hypotheses)
                    self.assertEqual(contradictions_path.read_bytes(), original_contradictions)
                    self.assertTrue(journal.exists())

    def test_oracle_does_not_accept_single_run_strict_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = self.make_workspace(root, "rev-oracle-strict")
            init_rev_state(workspace)
            ran = root / "target-ran"
            target = self.target_path(workspace)
            target.write_text(
                "#!/usr/bin/env python3\nfrom pathlib import Path\n"
                f"Path({str(ran)!r}).write_text('ran')\n",
                encoding="utf-8",
            )
            target.chmod(0o755)

            result = run_script(
                SKILL_DIR / "assets" / "solver.py",
                "--workspace", str(workspace),
                "--binary", str(target),
                "--candidate", "candidate",
                "--strict",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("--strict", result.stderr)
            self.assertFalse(ran.exists())

    def test_state_cli_records_hypothesis_experiment_and_bidirectional_contradiction(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-state-cli")
            hypothesis_result = run_script(
                SCRIPTS / "record_clue.py",
                "hypothesis",
                "--workspace", str(workspace),
                "--statement", "the compare is reachable from main",
                "--falsifying-test", "break at the compare after valid input",
            )
            self.assertEqual(hypothesis_result.returncode, 0, hypothesis_result.stderr)
            hypothesis = json.loads(hypothesis_result.stdout)
            experiment_result = run_script(
                SCRIPTS / "record_clue.py",
                "experiment",
                "--workspace", str(workspace),
                "--hypothesis-id", hypothesis["id"],
                "--evidence", "gdb/reachable.txt",
                "--result", "breakpoint reached",
                "--progress",
            )
            self.assertEqual(experiment_result.returncode, 0, experiment_result.stderr)
            self.assertEqual(json.loads(experiment_result.stdout)["status"], "active")
            contradiction_result = run_script(
                SCRIPTS / "record_clue.py",
                "contradiction",
                "--workspace", str(workspace),
                "--hypothesis-id", hypothesis["id"],
                "--evidence", "gdb/alternate-path.txt",
                "--summary", "a second path bypasses the comparison",
            )
            self.assertEqual(contradiction_result.returncode, 0, contradiction_result.stderr)
            contradiction = json.loads(contradiction_result.stdout)

            hypotheses = json.loads((workspace / "rev" / "hypotheses.json").read_text())
            contradictions = json.loads((workspace / "rev" / "contradictions.json").read_text())
            self.assertEqual(contradiction["hypothesis_id"], hypothesis["id"])
            self.assertEqual(hypotheses["hypotheses"][0]["contradiction_ids"], [contradiction["id"]])
            self.assertEqual(contradictions["contradictions"], [contradiction])

    def test_concurrent_state_cli_updates_keep_all_hypotheses_and_links(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "rev-state-concurrent")
            base = run_script(
                SCRIPTS / "record_clue.py", "hypothesis", "--workspace", str(workspace),
                "--statement", "base hypothesis", "--falsifying-test", "break at base",
            )
            self.assertEqual(base.returncode, 0, base.stderr)
            hypothesis_id = json.loads(base.stdout)["id"]
            commands = [
                ["experiment", "--workspace", str(workspace), "--hypothesis-id", hypothesis_id,
                 "--evidence", "gdb/concurrent.txt", "--result", "reached", "--progress"],
                ["contradiction", "--workspace", str(workspace), "--hypothesis-id", hypothesis_id,
                 "--evidence", "gdb/conflict.txt", "--summary", "alternate path"],
                ["hypothesis", "--workspace", str(workspace), "--statement", "second hypothesis",
                 "--falsifying-test", "break at second"],
                ["hypothesis", "--workspace", str(workspace), "--statement", "third hypothesis",
                 "--falsifying-test", "break at third"],
            ]
            processes = [
                subprocess.Popen(
                    [sys.executable, str(SCRIPTS / "record_clue.py"), *command],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                for command in commands
            ]
            results = [process.communicate() for process in processes]
            self.assertTrue(all(process.returncode == 0 for process in processes), results)

            hypotheses = json.loads((workspace / "rev" / "hypotheses.json").read_text())["hypotheses"]
            contradictions = json.loads((workspace / "rev" / "contradictions.json").read_text())["contradictions"]
            self.assertEqual(len(hypotheses), 3)
            self.assertEqual(len({row["id"] for row in hypotheses}), 3)
            base_row = next(row for row in hypotheses if row["id"] == hypothesis_id)
            self.assertEqual(len(base_row["experiments"]), 1)
            self.assertEqual(base_row["contradiction_ids"], [contradictions[0]["id"]])

    def test_shared_state_lock_blocks_experiment_and_contradiction_until_release(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = self.make_workspace(root, "rev-state-lock")
            base = record_hypothesis(workspace, "base", "break at base")
            lock_path = workspace / "rev" / ".state.lock"
            commands = [
                ["experiment", "--workspace", str(workspace), "--hypothesis-id", base["id"],
                 "--evidence", "gdb/lock.txt", "--result", "reached", "--progress"],
                ["contradiction", "--workspace", str(workspace), "--hypothesis-id", base["id"],
                 "--evidence", "gdb/lock-conflict.txt", "--summary", "conflict"],
            ]
            processes: list[subprocess.Popen[str]] = []
            captures: dict[int, tuple[str, str]] = {}

            def reap(process: subprocess.Popen[str], timeout: float) -> tuple[str, str]:
                if process.pid in captures:
                    return captures[process.pid]
                def collect(wait: float) -> tuple[str, str] | None:
                    try:
                        result = process.communicate(timeout=wait)
                    except (subprocess.TimeoutExpired, OSError):
                        return None
                    if result is not None and process.returncode is not None:
                        captures[process.pid] = result
                        return result
                    return None

                def capture_or_empty() -> tuple[str, str]:
                    if process.returncode is not None:
                        captured = collect(0.1)
                        if captured is not None:
                            return captured
                    return ("", "")

                normal_deadline = time.monotonic() + timeout
                while time.monotonic() < normal_deadline:
                    if process.poll() is not None:
                        return capture_or_empty()
                    result = collect(max(0.01, min(0.1, normal_deadline - time.monotonic())))
                    if result is not None:
                        return result

                if process.poll() is not None:
                    return capture_or_empty()
                try:
                    process.terminate()
                except (ProcessLookupError, OSError):
                    pass
                grace_deadline = time.monotonic() + max(0.1, min(1.0, timeout))
                while time.monotonic() < grace_deadline:
                    if process.poll() is not None:
                        return capture_or_empty()
                    remaining = max(0.01, min(0.1, grace_deadline - time.monotonic()))
                    result = collect(remaining)
                    if result is not None:
                        return result
                    try:
                        process.wait(timeout=remaining)
                    except (subprocess.TimeoutExpired, OSError):
                        pass

                if process.poll() is None:
                    try:
                        process.kill()
                    except (ProcessLookupError, OSError):
                        pass
                final_deadline = time.monotonic() + max(0.1, min(1.0, timeout))
                while time.monotonic() < final_deadline:
                    if process.poll() is not None:
                        return capture_or_empty()
                    remaining = max(0.01, min(0.1, final_deadline - time.monotonic()))
                    result = collect(remaining)
                    if result is not None:
                        return result
                    try:
                        process.wait(timeout=remaining)
                    except (subprocess.TimeoutExpired, OSError):
                        pass
                return capture_or_empty()

            try:
                with lock_path.open("a+", encoding="utf-8") as lock:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                    try:
                        inode = lock_path.stat().st_ino
                        for command in commands:
                            processes.append(subprocess.Popen(
                                [sys.executable, str(SCRIPTS / "record_clue.py"), *command],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            ))
                        deadline = time.monotonic() + 3
                        observed: set[int] = set()
                        while time.monotonic() < deadline:
                            locks = Path("/proc/locks").read_text(encoding="utf-8")
                            for process in processes:
                                if process.poll() is None and any(
                                    "-> FLOCK" in line and f" {process.pid} " in line and f":{inode} " in line
                                    for line in locks.splitlines()
                                ):
                                    observed.add(process.pid)
                            if len(observed) == len(processes):
                                break
                            time.sleep(0.01)
                        self.assertEqual(observed, {process.pid for process in processes})
                    finally:
                        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                results = [reap(process, 3) for process in processes]
                self.assertTrue(all(process.returncode == 0 for process in processes), results)
            finally:
                for process in processes:
                    try:
                        reap(process, 0.2)
                    except BaseException:
                        pass
            ledger = json.loads((workspace / "rev" / "hypotheses.json").read_text())["hypotheses"][0]
            self.assertEqual(len(ledger["experiments"]), 1)
            self.assertEqual(len(ledger["contradiction_ids"]), 1)


if __name__ == "__main__":
    unittest.main()
