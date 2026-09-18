import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = REPO_ROOT / "pwn-agent"


def run_script(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SKILL_DIR / "scripts" / name), *args],
        text=True,
        capture_output=True,
        check=False,
    )


class PwnAgentScriptTests(unittest.TestCase):
    def make_challenge(self, root: Path) -> Path:
        challenge = root / "challenges" / "ret2win"
        challenge.mkdir(parents=True)
        (challenge / "challenge.yaml").write_text(
            "id: ret2win\nwall_time_seconds: 900\n",
            encoding="utf-8",
        )
        (challenge / "chall").write_bytes(b"\x7fELFfixture")
        return challenge

    def test_init_run_creates_a_common_pwn_session(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            event_root = Path(temp) / "event"
            challenge = self.make_challenge(event_root)

            result = run_script(
                "init_run.py",
                str(challenge),
                "--event-root",
                str(event_root),
                "--session-id",
                "pwn-test",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            workspace = Path(payload["workspace"])
            self.assertEqual(
                workspace,
                event_root
                / "runs"
                / "pwn"
                / f"ret2win-{payload['fingerprint'][:12]}"
                / "sessions"
                / "pwn-test",
            )
            self.assertTrue((workspace / "artifacts").is_dir())
            self.assertTrue((workspace / "logs").is_dir())
            self.assertTrue((workspace / "transcripts").is_dir())
            self.assertEqual(payload["category"], "pwn")

    def test_init_run_maps_unambiguous_legacy_run_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            event_root = Path(temp) / "event"
            challenge = self.make_challenge(event_root)

            result = run_script(
                "init_run.py",
                str(challenge),
                "--runs-root",
                str(event_root / "runs"),
                "--run-id",
                "legacy-pwn-run",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["session_id"], "legacy-pwn-run")
            self.assertEqual(Path(payload["workspace"]).parents[2], event_root / "runs" / "pwn")

    def test_verify_flag_uses_race_mode_for_one_non_echoed_target_output(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            output = root / "target.bin"
            sent = root / "sent.bin"
            result_path = root / "result.json"
            output.write_bytes(b"target response FLAG{real_flag}\n")
            sent.write_bytes(b"menu choice 1\n")

            result = run_script(
                "verify_flag.py",
                "--workspace",
                str(workspace),
                "--output",
                str(output),
                "--sent",
                str(sent),
                "--pattern",
                r"FLAG\{[^}\r\n]+\}",
                "--result",
                str(result_path),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "verified")
            self.assertEqual(payload["flag"], "FLAG{real_flag}")
            self.assertEqual(payload["reproductions"], 1)
            self.assertEqual(json.loads(result_path.read_text(encoding="utf-8")), payload)

    def test_verify_flag_rejects_user_input_echo(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            output = root / "target.bin"
            sent = root / "sent.bin"
            output.write_bytes(b"FLAG{echoed}\n")
            sent.write_bytes(b"FLAG{echoed}\n")

            result = run_script(
                "verify_flag.py",
                "--workspace",
                str(workspace),
                "--output",
                str(output),
                "--sent",
                str(sent),
            )

            self.assertEqual(result.returncode, 2)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "unverified")
            self.assertEqual(payload["reason"], "candidate_was_user_input")

    def test_verify_flag_forwards_strict_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            output = root / "target.bin"
            output.write_bytes(b"FLAG{one_run}\n")

            result = run_script(
                "verify_flag.py",
                "--workspace",
                str(workspace),
                "--output",
                str(output),
                "--strict",
            )

            self.assertEqual(result.returncode, 2)
            self.assertEqual(
                json.loads(result.stdout)["reason"],
                "requires_two_clean_reproductions",
            )


if __name__ == "__main__":
    unittest.main()
