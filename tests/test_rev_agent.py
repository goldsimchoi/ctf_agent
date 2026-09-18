import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = REPO_ROOT / "rev-agent"
COMMON_SCRIPTS = REPO_ROOT / "ctf-common" / "scripts"
SCRIPTS = SKILL_DIR / "scripts"
sys.path.insert(0, str(SCRIPTS))

from init_rev_state import init_rev_state  # noqa: E402
from record_clue import (  # noqa: E402
    record_clue,
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
            "id: crackme\nauthorized: true\n",
            encoding="utf-8",
        )
        result = run_script(
            COMMON_SCRIPTS / "init_session.py",
            str(challenge),
            "--category", "rev",
            "--event-root", str(event_root),
            "--session-id", session_id,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return Path(json.loads(result.stdout)["workspace"])

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
            target = Path(temp) / "target.py"
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


if __name__ == "__main__":
    unittest.main()
