import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = REPO_ROOT / "pwn-agent"
sys.path.insert(0, str(REPO_ROOT / "ctf-common" / "scripts"))

from ctf_intake import MAX_REQUEST_BYTES  # noqa: E402
from ctf_workspace import InvalidInput  # noqa: E402


def run_script(
    name: str,
    *args: str,
    input: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SKILL_DIR / "scripts" / name), *args],
        text=True,
        capture_output=True,
        check=False,
        input=input,
    )


class PwnAgentScriptTests(unittest.TestCase):
    def make_challenge(self, root: Path) -> Path:
        challenge = root / "challenges" / "ret2win"
        challenge.mkdir(parents=True)
        (challenge / "challenge.yaml").write_text(
            "id: ret2win\nbinary: chall\nauthorized: true\n"
            "network_access: agent_allowed\nhost: ctf.example\nport: 31337\n"
            "protocol: tcp\nwall_time_seconds: 900\n",
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

    def test_init_run_accepts_lossless_stdin_intake_and_binds_capture_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            event_root = Path(temp) / "event"
            challenge = event_root / "challenges" / "stdin-pwn"
            challenge.mkdir(parents=True)
            binary = challenge / "chall"
            binary.write_bytes(b"\x7fELFfixture")
            other_binary = challenge / "other"
            other_binary.write_bytes(b"\x7fELFother")
            statement = (
                "The service is available with nc pwn.example 31337\n"
                "Preserve `quotes`, $(commands), and {{ templates }} exactly."
            )
            payload = json.dumps(
                {
                    "statement": statement,
                    "target": "nc pwn.example 31337",
                    "binary": "chall",
                }
            )

            result = run_script(
                "init_run.py",
                str(challenge),
                "--event-root",
                str(event_root),
                "--request-json",
                "-",
                input=payload,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertEqual(len(result.stdout.splitlines()), 1)
            row = json.loads(result.stdout)
            workspace = Path(row["workspace"])
            stored = json.loads(
                Path(row["intake"]["request_path"]).read_text(encoding="utf-8")
            )
            self.assertEqual(stored["statement"], statement)
            self.assertEqual(
                (stored["normalized"]["host"], stored["normalized"]["port"]),
                ("pwn.example", 31337),
            )
            self.assertFalse((challenge / "challenge.yaml").exists())
            manifest = (workspace / "challenge.resolved.yaml").read_text(
                encoding="utf-8"
            )
            for scalar in (
                'authorized: "true"',
                "binary: chall",
                "host: pwn.example",
                "network_access: agent_allowed",
                'port: "31337"',
                "protocol: tcp",
            ):
                self.assertIn(scalar, manifest)

            output = workspace / "transcripts" / "intake.output"
            sent = workspace / "transcripts" / "intake.sent"
            output.write_bytes(b"target response\n")
            sent.write_bytes(b"1\n")
            accepted_targets = (
                "tcp://pwn.example:31337",
                f"local:{binary.resolve()}",
            )
            for index, source_target in enumerate(accepted_targets):
                accepted = run_script(
                    "publish_capture.py",
                    "--workspace",
                    str(workspace),
                    "--capture-id",
                    f"accepted-{index}",
                    "--source-target",
                    source_target,
                    "--output",
                    str(output),
                    "--sent",
                    str(sent),
                )
                self.assertEqual(accepted.returncode, 0, accepted.stderr)

            rejected_targets = (
                "tcp://other.example:31337",
                "tcp://pwn.example:31338",
                f"local:{other_binary.resolve()}",
            )
            for index, source_target in enumerate(rejected_targets):
                rejected = run_script(
                    "publish_capture.py",
                    "--workspace",
                    str(workspace),
                    "--capture-id",
                    f"rejected-{index}",
                    "--source-target",
                    source_target,
                    "--output",
                    str(output),
                    "--sent",
                    str(sent),
                )
                self.assertEqual(rejected.returncode, 2)

    def test_local_capture_requires_explicit_authorization(self) -> None:
        for authorization in ('authorized: "false"\n', ""):
            with self.subTest(authorization=authorization):
                with tempfile.TemporaryDirectory() as temp:
                    workspace = self.make_session(Path(temp))
                    session = json.loads((workspace / "session.json").read_text())
                    binary = Path(session["challenge"]) / "chall"
                    (workspace / "challenge.resolved.yaml").write_text(
                        authorization + "binary: chall\n", encoding="utf-8",
                    )
                    output = workspace / "transcripts" / "capture.output"
                    sent = workspace / "transcripts" / "capture.sent"
                    output.write_bytes(b"response")
                    sent.write_bytes(b"input")
                    before = sorted(path.relative_to(workspace) for path in workspace.rglob("*"))

                    result = run_script(
                        "publish_capture.py", "--workspace", str(workspace),
                        "--capture-id", "unauthorized", "--source-target", f"local:{binary}",
                        "--output", str(output), "--sent", str(sent),
                    )

                    self.assertEqual(result.returncode, 2, result.stdout)
                    self.assertEqual(json.loads(result.stdout)["status"], "error")
                    self.assertIn("authoriz", json.loads(result.stdout)["error"])
                    self.assertEqual(
                        sorted(path.relative_to(workspace) for path in workspace.rglob("*")), before,
                    )

    def test_local_capture_rejects_authorization_before_binary_read(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "pwn_capture_authorization_test", SKILL_DIR / "scripts" / "publish_capture.py",
        )
        capture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(capture)
        for authorization in ({"authorized": "false"}, {}):
            with self.subTest(authorization=authorization):
                with patch.object(
                    capture, "_read_regular_under",
                    side_effect=AssertionError("unauthorized binary was read"),
                ):
                    with self.assertRaisesRegex(InvalidInput, "authoriz"):
                        capture.bound_source_target(
                            Path("/unused/workspace"), {"challenge": "/unused/challenge"},
                            {"binary": "chall", **authorization}, "local:/unused/challenge/chall",
                        )

    def test_intake_capture_preserves_quoted_binary_identity(self) -> None:
        for name in ("chall#one", 'chall"two', "chall\\three"):
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as temp:
                    challenge = Path(temp) / "challenge"
                    challenge.mkdir()
                    binary = challenge / name
                    binary.write_bytes(b"fixture")
                    initialized = run_script("init_run.py", str(challenge), "--binary", name)
                    self.assertEqual(initialized.returncode, 0, initialized.stdout)
                    workspace = Path(json.loads(initialized.stdout)["workspace"])
                    output = workspace / "transcripts" / "capture.output"
                    sent = workspace / "transcripts" / "capture.sent"
                    output.write_bytes(b"response")
                    sent.write_bytes(b"input")
                    result = run_script(
                        "publish_capture.py", "--workspace", str(workspace),
                        "--capture-id", "quoted", "--source-target", f"local:{binary}",
                        "--output", str(output), "--sent", str(sent),
                    )
                    self.assertEqual(result.returncode, 0, result.stdout)
                    attestation = json.loads(Path(json.loads(result.stdout)["attestation"]).read_text())
                    self.assertEqual(attestation["source_target"], f"local:{binary}")

    def test_init_run_forwards_individual_intake_fields_as_literal_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            challenge = root / "individual-pwn"
            challenge.mkdir()
            (challenge / "chall with spaces").write_bytes(b"\x7fELFfixture")
            statement = "Literal $(not-a-command) and `not-code`"

            result = run_script(
                "init_run.py",
                str(challenge),
                "--statement",
                statement,
                "--target",
                "pwn.example:31337",
                "--binary",
                "chall with spaces",
                "--flag-pattern",
                r"PWN\{[^}]+\}",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            row = json.loads(result.stdout)
            stored = json.loads(
                Path(row["intake"]["request_path"]).read_text(encoding="utf-8")
            )
            self.assertEqual(stored["statement"], statement)
            self.assertEqual(stored["target_input"], "pwn.example:31337")
            self.assertEqual(stored["binary"], "chall with spaces")
            self.assertEqual(stored["flag_pattern"], r"PWN\{[^}]+\}")

    def test_init_run_rejects_missing_or_malformed_stdin_before_allocation(self) -> None:
        invalid_inputs = (None, "{not-json")
        for index, invalid_input in enumerate(invalid_inputs):
            with self.subTest(index=index):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    challenge = root / "invalid-pwn"
                    challenge.mkdir()

                    result = run_script(
                        "init_run.py",
                        str(challenge),
                        "--request-json",
                        "-",
                        input=invalid_input,
                    )

                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(json.loads(result.stdout)["status"], "error")
                    self.assertFalse((root / "runs").exists())

    def test_init_run_rejects_mixed_or_oversized_stdin_before_starting_child(self) -> None:
        cases = (
            (json.dumps({"statement": "valid"}), ("--statement", "mixed")),
            ("x" * (MAX_REQUEST_BYTES + 1), ()),
        )
        for index, (stdin, extra) in enumerate(cases):
            with self.subTest(index=index):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    challenge = root / "rejected-pwn"
                    challenge.mkdir()

                    result = run_script(
                        "init_run.py",
                        str(challenge),
                        "--request-json",
                        "-",
                        *extra,
                        input=stdin,
                    )

                    self.assertEqual(result.returncode, 2)
                    expected_error = (
                        "cannot be mixed"
                        if extra
                        else "request JSON stdin exceeds"
                    )
                    self.assertIn(expected_error, result.stderr)
                    self.assertFalse((root / "runs").exists())

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

    def test_capture_publisher_rejects_forged_remote_source_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_session(Path(temp))
            output = workspace / "transcripts" / "forged.output"
            sent = workspace / "transcripts" / "forged.sent"
            output.write_bytes(b"FLAG{forged}\n")
            sent.write_bytes(b"1\n")
            result = run_script(
                "publish_capture.py", "--workspace", str(workspace),
                "--capture-id", "forged", "--source-target", "tcp://other.example:31337",
                "--output", str(output), "--sent", str(sent),
            )

            self.assertEqual(result.returncode, 2)
            self.assertFalse((workspace / "artifacts" / "captures" / "forged.json").exists())

    def test_capture_publisher_rejects_symlinked_intermediate_evidence_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = self.make_session(root)
            outside = root / "outside"
            outside.mkdir()
            output = outside / "target.output"
            output.write_bytes(b"FLAG{outside}\n")
            sent = workspace / "transcripts" / "symlink.sent"
            sent.write_bytes(b"1\n")
            linked = workspace / "transcripts" / "linked"
            linked.symlink_to(outside, target_is_directory=True)
            result = run_script(
                "publish_capture.py", "--workspace", str(workspace),
                "--capture-id", "symlink", "--source-target", "tcp://ctf.example:31337",
                "--output", str(linked / output.name), "--sent", str(sent),
            )

            self.assertEqual(result.returncode, 2)
            self.assertFalse((workspace / "artifacts" / "captures" / "symlink.json").exists())


if __name__ == "__main__":
    unittest.main()
