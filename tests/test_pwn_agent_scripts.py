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

    def make_session(self, root: Path, session_id: str = "pwn-test") -> Path:
        event_root = root / "event"
        challenge = self.make_challenge(event_root)
        result = run_script(
            "init_run.py",
            str(challenge),
            "--event-root",
            str(event_root),
            "--session-id",
            session_id,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        workspace = Path(payload["workspace"])
        self.assertEqual(payload["category"], "pwn")
        self.assertTrue((workspace / "session.json").is_file())
        return workspace

    def make_capture(
        self,
        workspace: Path,
        capture_id: str,
        output_data: bytes,
        sent_data: bytes = b"1\n",
    ) -> tuple[Path, Path, Path]:
        output = workspace / "transcripts" / f"{capture_id}.output"
        sent = workspace / "transcripts" / f"{capture_id}.sent"
        output.write_bytes(output_data)
        sent.write_bytes(sent_data)
        result = run_script(
            "publish_capture.py",
            "--workspace",
            str(workspace),
            "--capture-id",
            capture_id,
            "--source-target",
            "tcp://ctf.example:31337",
            "--output",
            str(output),
            "--sent",
            str(sent),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        attestation = Path(json.loads(result.stdout)["attestation"])
        self.assertTrue(attestation.is_file())
        return output, sent, attestation

    def verify(self, workspace: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return run_script("verify_flag.py", "--workspace", str(workspace), *args)

    def test_init_run_creates_a_common_pwn_session(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_session(Path(temp))
            self.assertEqual(workspace.parent.name, "sessions")
            self.assertTrue((workspace / "artifacts").is_dir())
            self.assertTrue((workspace / "logs").is_dir())
            self.assertTrue((workspace / "transcripts").is_dir())

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

    def test_race_verifies_one_attested_non_echoed_capture_and_writes_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_session(Path(temp))
            output, sent, attestation = self.make_capture(
                workspace, "race-one", b"target response FLAG{real_flag}\n"
            )
            result_path = workspace / "artifacts" / "flag-result.json"

            result = self.verify(
                workspace,
                "--output", str(output),
                "--sent", str(sent),
                "--attestation", str(attestation),
                "--result", str(result_path),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "verified")
            self.assertEqual(payload["flag"], "FLAG{real_flag}")
            self.assertEqual(payload["reproductions"], 1)
            self.assertEqual(json.loads(result_path.read_text(encoding="utf-8")), payload)

    def test_attested_echo_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_session(Path(temp))
            output, sent, attestation = self.make_capture(
                workspace, "echo", b"FLAG{echoed}\n", b"FLAG{echoed}\n"
            )

            result = self.verify(
                workspace,
                "--output", str(output),
                "--sent", str(sent),
                "--attestation", str(attestation),
            )

            self.assertEqual(result.returncode, 2)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "unverified")
            self.assertEqual(payload["reason"], "candidate_was_user_input")

    def test_strict_verifies_two_independent_attested_captures(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_session(Path(temp))
            first = self.make_capture(workspace, "strict-one", b"FLAG{twice}\n")
            second = self.make_capture(workspace, "strict-two", b"again FLAG{twice}\n")

            result = self.verify(
                workspace,
                "--output", str(first[0]), "--sent", str(first[1]), "--attestation", str(first[2]),
                "--output", str(second[0]), "--sent", str(second[1]), "--attestation", str(second[2]),
                "--strict",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "verified")
            self.assertEqual(payload["reproductions"], 2)

    def test_strict_rejects_one_or_duplicate_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_session(Path(temp))
            capture = self.make_capture(workspace, "strict-one", b"FLAG{once}\n")
            one = self.verify(
                workspace,
                "--output", str(capture[0]), "--sent", str(capture[1]),
                "--attestation", str(capture[2]), "--strict",
            )
            duplicate = self.verify(
                workspace,
                "--output", str(capture[0]), "--sent", str(capture[1]),
                "--attestation", str(capture[2]),
                "--output", str(capture[0]), "--sent", str(capture[1]),
                "--attestation", str(capture[2]), "--strict",
            )

            self.assertEqual(json.loads(one.stdout)["reason"], "requires_two_clean_reproductions")
            duplicate_payload = json.loads(duplicate.stdout)
            self.assertEqual(duplicate_payload["status"], "candidate_only")
            self.assertEqual(duplicate_payload["reason"], "duplicate_capture_attestation")

    def test_unattested_candidate_is_candidate_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_session(Path(temp))
            output = workspace / "transcripts" / "unattested.output"
            sent = workspace / "transcripts" / "unattested.sent"
            output.write_bytes(b"FLAG{unattested}\n")
            sent.write_bytes(b"1\n")

            result = self.verify(
                workspace, "--output", str(output), "--sent", str(sent)
            )

            self.assertEqual(result.returncode, 2)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "candidate_only")
            self.assertEqual(payload["reason"], "missing_capture_attestation")


if __name__ == "__main__":
    unittest.main()
