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
    def test_init_run_accepts_direct_binary_without_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "babyrop"
            binary.write_bytes(b"\x7fELFfixture")

            result = run_script(
                "init_run.py",
                str(binary),
                "--runs-root",
                str(root / "runs"),
                "--run-id",
                "direct-run",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            workspace = Path(json.loads(result.stdout)["workspace"])
            self.assertEqual(workspace.name, "babyrop")
            resolved = (
                workspace / "challenge.resolved.yaml"
            ).read_text(encoding="utf-8")
            self.assertIn("id: babyrop", resolved)
            self.assertIn(str(binary.resolve()), resolved)
            self.assertEqual(binary.read_bytes(), b"\x7fELFfixture")

    def test_init_run_creates_isolated_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            challenge = root / "challenges" / "ret2win"
            input_dir = challenge / "input"
            input_dir.mkdir(parents=True)
            binary = input_dir / "chall"
            binary.write_bytes(b"\x7fELFfixture")
            (challenge / "challenge.yaml").write_text(
                "id: ret2win\nbinary: input/chall\n",
                encoding="utf-8",
            )

            result = run_script(
                "init_run.py",
                str(challenge),
                "--runs-root",
                str(root / "runs"),
                "--run-id",
                "test-run",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            workspace = Path(payload["workspace"])
            self.assertEqual(
                workspace,
                root / "runs" / "test-run" / "ret2win",
            )
            self.assertTrue((workspace / "exploit.py").is_file())
            self.assertTrue((workspace / "state.json").is_file())
            self.assertTrue((workspace / "notes.md").is_file())
            self.assertTrue((workspace / "transcripts").is_dir())
            state = json.loads(
                (workspace / "state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(state["status"], "ingest")
            self.assertEqual(state["challenge_id"], "ret2win")
            self.assertEqual(state["facts"], [])
            self.assertEqual(state["capabilities"], {})
            self.assertEqual(binary.read_bytes(), b"\x7fELFfixture")

    def test_verify_flag_rejects_user_input_echo(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output1 = root / "run1.bin"
            output2 = root / "run2.bin"
            sent = root / "sent.bin"
            result_path = root / "result.json"
            output1.write_bytes(b"hello FLAG{demo}\n")
            output2.write_bytes(b"hello FLAG{demo}\n")
            sent.write_bytes(b"FLAG{demo}\n")

            result = run_script(
                "verify_flag.py",
                "--output",
                str(output1),
                "--output",
                str(output2),
                "--sent",
                str(sent),
                "--pattern",
                r"FLAG\{[^}\r\n]+\}",
                "--result",
                str(result_path),
            )

            self.assertEqual(result.returncode, 2)
            self.assertTrue(result_path.is_file(), result.stderr)
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "unverified")
            self.assertEqual(payload["reason"], "candidate_was_user_input")
            self.assertIsNone(payload["flag"])

    def test_verify_flag_requires_reproduction_and_accepts_real_candidate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output1 = root / "run1.bin"
            output2 = root / "run2.bin"
            sent = root / "sent.bin"
            result_path = root / "result.json"
            output1.write_bytes(b"menu\nFLAG{real_flag}\n")
            output2.write_bytes(b"welcome\nFLAG{real_flag}\n")
            sent.write_bytes(b"1\n2\n")

            result = run_script(
                "verify_flag.py",
                "--output",
                str(output1),
                "--output",
                str(output2),
                "--sent",
                str(sent),
                "--pattern",
                r"FLAG\{[^}\r\n]+\}",
                "--result",
                str(result_path),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "verified")
            self.assertEqual(payload["flag"], "FLAG{real_flag}")
            self.assertEqual(payload["reproductions"], 2)


if __name__ == "__main__":
    unittest.main()
