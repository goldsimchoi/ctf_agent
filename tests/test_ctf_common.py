import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "ctf-common" / "scripts"
sys.path.insert(0, str(REPO_ROOT / "ctf-common" / "scripts"))

from ctf_workspace import (  # noqa: E402
    BudgetExhausted,
    CollisionError,
    InvalidInput,
    MAX_ARTIFACT_BYTES,
    create_session,
    publish_capture_attestation,
    publish_finding,
    record_attempt,
    verify_outputs,
)


def run_common_script(name: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / name), *args],
        text=True,
        capture_output=True,
        check=False,
    )


class CommonWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "event"
        self.challenge = self.root / "challenges" / "login"
        self.other_challenge = self.root / "challenges" / "crackme"
        for challenge in (self.challenge, self.other_challenge):
            challenge.mkdir(parents=True)
            (challenge / "challenge.yaml").write_text(
                "id: " + challenge.name + "\nwall_time_seconds: 900\n",
                encoding="utf-8",
            )
            (challenge / "input.bin").write_bytes(b"fixture")

    def make_capture(
        self,
        row: dict,
        capture_id: str,
        output_data: bytes,
        sent_data: bytes = b"menu choice 1\n",
        source_target: str = "https://ctf.example/challenge",
    ) -> tuple[Path, Path, dict]:
        workspace = row["workspace"]
        output = workspace / "transcripts" / f"{capture_id}.output"
        sent = workspace / "transcripts" / f"{capture_id}.sent"
        output.write_bytes(output_data)
        sent.write_bytes(sent_data)
        attestation = {
            "schema_version": 1,
            "workspace": str(workspace.resolve()),
            "session_id": row["session_id"],
            "category": row["category"],
            "capture_id": capture_id,
            "source_target": source_target,
            "output": {
                "path": str(output.resolve()),
                "sha256": hashlib.sha256(output_data).hexdigest(),
            },
            "sent": {
                "path": str(sent.resolve()),
                "sha256": hashlib.sha256(sent_data).hexdigest(),
            },
        }
        return output, sent, publish_capture_attestation(workspace, attestation)

    def test_challenges_and_categories_receive_isolated_workspaces(self) -> None:
        web = create_session(self.challenge, "web")
        rev = create_session(self.challenge, "rev")
        other = create_session(self.other_challenge, "web")

        self.assertNotEqual(web["workspace"].parent.parent, rev["workspace"].parent.parent)
        self.assertNotEqual(web["workspace"].parent.parent, other["workspace"].parent.parent)
        self.assertTrue((web["workspace"] / "state.json").is_file())
        self.assertEqual(web["fingerprint"], create_session(self.challenge, "web")["fingerprint"])

    def test_concurrent_sessions_are_unique(self) -> None:
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(lambda _: create_session(self.challenge, "web"), range(16)))
        paths = {row["workspace"] for row in rows}
        self.assertEqual(len(paths), 16)

    def test_categories_have_separate_namespaces(self) -> None:
        rows = [create_session(self.challenge, category) for category in ("pwn", "web", "rev")]
        self.assertEqual({row["category"] for row in rows}, {"pwn", "web", "rev"})
        self.assertEqual(len({row["workspace"].parents[2] for row in rows}), 3)

    def test_finding_is_immutable_and_shared_within_a_category_workspace(self) -> None:
        first = create_session(self.challenge, "web")
        second = create_session(self.challenge, "web")
        evidence = first["workspace"] / "artifacts" / "response.txt"
        evidence.write_text("GET /flag returned 200", encoding="utf-8")

        finding = publish_finding(first["workspace"], "endpoint", evidence, "verified flag endpoint")

        second_evidence = second["workspace"] / "artifacts" / "request.txt"
        second_evidence.write_text("GET /health returned 200", encoding="utf-8")
        other_finding = publish_finding(second["workspace"], "endpoint", second_evidence, "verified health endpoint")
        payload = json.loads(finding.read_text(encoding="utf-8"))
        self.assertEqual(payload["kind"], "endpoint")
        shared_evidence = Path(payload["evidence"])
        self.assertNotEqual(shared_evidence, evidence.resolve())
        self.assertTrue(shared_evidence.is_file())
        self.assertEqual(shared_evidence.read_text(encoding="utf-8"), "GET /flag returned 200")
        evidence.write_text("mutated after publication", encoding="utf-8")
        self.assertEqual(shared_evidence.read_text(encoding="utf-8"), "GET /flag returned 200")
        self.assertTrue(finding.is_file())
        third = create_session(self.challenge, "web")
        self.assertEqual(third["findings"], sorted([finding, other_finding]))

    def test_unsafe_and_duplicate_explicit_session_ids_are_rejected(self) -> None:
        with self.assertRaises(InvalidInput):
            create_session(self.challenge, "web", session_id="../escape")
        create_session(self.challenge, "web", session_id="web-fixed")
        with self.assertRaises(CollisionError):
            create_session(self.challenge, "web", session_id="web-fixed")

    def test_initializer_rejects_symlinked_runs_component(self) -> None:
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (self.root / "runs").symlink_to(outside, target_is_directory=True)

        with self.assertRaises(InvalidInput):
            create_session(self.challenge, "web")

        self.assertEqual(list(outside.iterdir()), [])

    def test_publisher_rejects_symlinked_shared_component(self) -> None:
        row = create_session(self.challenge, "web")
        evidence = row["workspace"] / "artifacts" / "response.txt"
        evidence.write_bytes(b"safe evidence")
        common = row["workspace"].parents[1]
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (common / "shared" / "findings").rmdir()
        (common / "shared").rmdir()
        (common / "shared").symlink_to(outside, target_is_directory=True)

        with self.assertRaises(InvalidInput):
            publish_finding(row["workspace"], "endpoint", evidence, "must stay contained")

        self.assertEqual(list(outside.iterdir()), [])

    def test_initializer_rejects_symlinked_sessions_component(self) -> None:
        row = create_session(self.challenge, "web")
        sessions = row["workspace"].parent
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        row["workspace"].rename(outside / row["workspace"].name)
        sessions.rmdir()
        sessions.symlink_to(outside, target_is_directory=True)

        with self.assertRaises(InvalidInput):
            create_session(self.challenge, "web", session_id="web-second")

        self.assertFalse((outside / "web-second").exists())

    def test_publisher_rejects_mutated_session_identity_before_writing(self) -> None:
        row = create_session(self.challenge, "web")
        evidence = row["workspace"] / "artifacts" / "response.txt"
        evidence.write_bytes(b"safe evidence")
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        session_path = row["workspace"] / "session.json"
        session = json.loads(session_path.read_text(encoding="utf-8"))
        session["session_id"] = str(outside / "escape")
        session_path.write_text(json.dumps(session), encoding="utf-8")

        with self.assertRaises(InvalidInput):
            publish_finding(row["workspace"], "endpoint", evidence, "must stay contained")

        self.assertFalse((outside / "escape").exists())

    def test_two_no_progress_attempts_exhaust_budget_and_new_fact_allows_retry(self) -> None:
        row = create_session(self.challenge, "web")
        self.assertEqual(record_attempt(row["workspace"], "GET /admin 403")["no_progress"], 1)
        with self.assertRaises(BudgetExhausted):
            record_attempt(row["workspace"], "POST /login 401")

        progressed = create_session(self.challenge, "web")
        record_attempt(progressed["workspace"], "GET /admin 403", progress="new endpoint /api")
        state = record_attempt(progressed["workspace"], "POST /login 401")
        self.assertEqual(state["no_progress"], 1)
        with self.assertRaises(InvalidInput):
            record_attempt(progressed["workspace"], " post   /login 401 ")

    def test_progress_label_without_detail_is_rejected(self) -> None:
        row = create_session(self.challenge, "web")

        with self.assertRaises(InvalidInput):
            record_attempt(row["workspace"], "GET /admin 403", progress="fact")

        state = record_attempt(row["workspace"], "GET /admin 403")
        self.assertEqual(state["no_progress"], 1)

    def test_race_accepts_one_non_echoed_candidate_but_strict_requires_two(self) -> None:
        row = create_session(self.challenge, "web")
        output, sent, attestation = self.make_capture(row, "capture-one", b"target response FLAG{real}\n")
        pattern = (rb"FLAG\{[^}\r\n]+\}",)

        race = verify_outputs([output], [sent], pattern, strict=False, workspace=row["workspace"], attestations=[attestation])
        strict = verify_outputs([output], [sent], pattern, strict=True, workspace=row["workspace"], attestations=[attestation])
        self.assertEqual(race["status"], "verified")
        self.assertEqual(race["flag"], "FLAG{real}")
        self.assertEqual(strict["reason"], "requires_two_clean_reproductions")

    def test_verification_rejects_echoed_candidates(self) -> None:
        row = create_session(self.challenge, "web")
        output, sent, attestation = self.make_capture(row, "echo", b"FLAG{echoed}\n", b"FLAG{echoed}\n")

        result = verify_outputs(
            [output], [sent], (rb"FLAG\{[^}\r\n]+\}",), strict=False,
            workspace=row["workspace"], attestations=[attestation],
        )
        self.assertEqual(result["status"], "unverified")
        self.assertEqual(result["reason"], "candidate_was_user_input")

    def test_strict_verification_counts_a_candidate_in_two_of_three_outputs(self) -> None:
        row = create_session(self.challenge, "web")
        captures = [
            self.make_capture(row, "capture-one", b"FLAG{reproduced}\n"),
            self.make_capture(row, "capture-two", b"again FLAG{reproduced}\n"),
            self.make_capture(row, "capture-three", b"later output has no candidate\n"),
        ]
        outputs = [capture[0] for capture in captures]
        sent = [capture[1] for capture in captures]
        attestations = [capture[2] for capture in captures]

        result = verify_outputs(outputs, sent, (rb"FLAG\{[^}\r\n]+\}",), strict=True, workspace=row["workspace"], attestations=attestations)

        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["flag"], "FLAG{reproduced}")
        self.assertEqual(result["reproductions"], 2)

    def test_strict_verification_reports_clean_single_candidate_as_not_reproduced(self) -> None:
        row = create_session(self.challenge, "web")
        captures = [
            self.make_capture(row, "capture-one", b"FLAG{only_once}\n"),
            self.make_capture(row, "capture-two", b"later output has no candidate\n"),
            self.make_capture(row, "capture-three", b"another output has no candidate\n"),
        ]
        outputs = [capture[0] for capture in captures]
        sent = [capture[1] for capture in captures]
        attestations = [capture[2] for capture in captures]

        result = verify_outputs(outputs, sent, (rb"FLAG\{[^}\r\n]+\}",), strict=True, workspace=row["workspace"], attestations=attestations)

        self.assertEqual(result["status"], "unverified")
        self.assertEqual(result["reason"], "candidate_not_reproduced")

    def test_verification_without_attestation_is_candidate_only(self) -> None:
        output = self.root / "unattested-output.txt"
        sent = self.root / "unattested-sent.txt"
        output.write_bytes(b"FLAG{unattested}\n")
        sent.write_bytes(b"menu choice\n")

        result = verify_outputs([output], [sent], (rb"FLAG\{[^}\r\n]+\}",), strict=False)

        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(result["reason"], "missing_capture_attestation")

    def test_strict_verification_rejects_duplicate_capture_identity(self) -> None:
        row = create_session(self.challenge, "web")
        output, sent, attestation = self.make_capture(row, "capture-one", b"FLAG{duplicated}\n")

        result = verify_outputs(
            [output, output], [sent], (rb"FLAG\{[^}\r\n]+\}",), strict=True,
            workspace=row["workspace"], attestations=[attestation, attestation],
        )

        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(result["reason"], "duplicate_capture_attestation")

    def test_strict_verification_rejects_hardlinked_output_alias(self) -> None:
        row = create_session(self.challenge, "web")
        output, sent, first = self.make_capture(row, "capture-one", b"FLAG{aliased}\n")
        alias = row["workspace"] / "transcripts" / "capture-two.output"
        alias.hardlink_to(output)
        second_record = {
            "schema_version": 1,
            "workspace": str(row["workspace"]),
            "session_id": row["session_id"],
            "category": row["category"],
            "capture_id": "capture-two",
            "source_target": "https://ctf.example/challenge",
            "output": {"path": str(alias), "sha256": hashlib.sha256(b"FLAG{aliased}\n").hexdigest()},
            "sent": {"path": str(sent), "sha256": hashlib.sha256(b"menu choice 1\n").hexdigest()},
        }
        second = publish_capture_attestation(row["workspace"], second_record)

        result = verify_outputs(
            [output, alias], [sent], (rb"FLAG\{[^}\r\n]+\}",), strict=True,
            workspace=row["workspace"], attestations=[first, second],
        )

        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(result["reason"], "duplicate_capture_attestation")

    def test_verifier_rejects_symlinked_capture_record_without_path_read(self) -> None:
        row = create_session(self.challenge, "web")
        output, sent, _ = self.make_capture(row, "capture-one", b"FLAG{symlinked}\n")
        outside = Path(self.temp.name) / "outside-attestation.json"
        outside.write_text("{}", encoding="utf-8")
        capture = row["workspace"] / "artifacts" / "captures" / "symlink.json"
        capture.symlink_to(outside)

        result = verify_outputs(
            [output], [sent], (rb"FLAG\{[^}\r\n]+\}",), strict=False,
            workspace=row["workspace"], attestations=[capture],
        )

        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(result["reason"], "invalid_capture_attestation")

    def test_verifier_treats_malformed_capture_record_as_candidate_only(self) -> None:
        row = create_session(self.challenge, "web")
        output, sent, _ = self.make_capture(row, "capture-one", b"FLAG{malformed}\n")
        malformed = row["workspace"] / "artifacts" / "captures" / "malformed.json"
        malformed.write_text("not json", encoding="utf-8")

        result = verify_outputs(
            [output], [sent], (rb"FLAG\{[^}\r\n]+\}",), strict=False,
            workspace=row["workspace"], attestations=[malformed],
        )

        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(result["reason"], "invalid_capture_attestation")

    def test_verify_cli_treats_malformed_capture_record_as_candidate_only(self) -> None:
        row = create_session(self.challenge, "web")
        output, sent, _ = self.make_capture(row, "capture-one", b"FLAG{cli_malformed}\n")
        malformed = row["workspace"] / "artifacts" / "captures" / "malformed.json"
        malformed.write_text("not json", encoding="utf-8")

        result = run_common_script(
            "verify_flag.py",
            "--workspace", str(row["workspace"]),
            "--output", str(output),
            "--sent", str(sent),
            "--attestation", str(malformed),
            "--pattern", r"FLAG\{[^}\r\n]+\}",
        )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, "")
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "candidate_only")
        self.assertEqual(payload["reason"], "invalid_capture_attestation")

    def test_verifier_treats_sparse_oversized_capture_as_invalid_provenance(self) -> None:
        row = create_session(self.challenge, "web")
        output, sent, attestation = self.make_capture(row, "capture-one", b"small output\n")
        with output.open("r+b") as stream:
            stream.truncate(MAX_ARTIFACT_BYTES + 1)

        result = verify_outputs(
            [output], [sent], (rb"FLAG\{[^}\r\n]+\}",), strict=False,
            workspace=row["workspace"], attestations=[attestation],
        )

        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(result["reason"], "invalid_capture_attestation")

    def test_verifier_treats_sparse_oversized_attestation_as_invalid_provenance(self) -> None:
        row = create_session(self.challenge, "web")
        output, sent, attestation = self.make_capture(row, "capture-one", b"small output\n")
        with attestation.open("r+b") as stream:
            stream.truncate(MAX_ARTIFACT_BYTES + 1)

        result = verify_outputs(
            [output], [sent], (rb"FLAG\{[^}\r\n]+\}",), strict=False,
            workspace=row["workspace"], attestations=[attestation],
        )

        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(result["reason"], "invalid_capture_attestation")

    def test_initializer_skips_sparse_oversized_shared_evidence(self) -> None:
        row = create_session(self.challenge, "web")
        evidence = row["workspace"] / "artifacts" / "response.txt"
        evidence.write_bytes(b"small evidence")
        finding = publish_finding(row["workspace"], "endpoint", evidence, "verified endpoint")
        payload = json.loads(finding.read_text(encoding="utf-8"))
        with Path(payload["evidence"]).open("r+b") as stream:
            stream.truncate(MAX_ARTIFACT_BYTES + 1)

        next_row = create_session(self.challenge, "web")

        self.assertEqual(next_row["findings"], [])
        self.assertEqual(next_row["skipped_findings"]["reasons"], {"evidence_oversized": 1})

    def test_initializer_skips_sparse_oversized_shared_record(self) -> None:
        row = create_session(self.challenge, "web")
        record = row["workspace"].parents[1] / "shared" / "findings" / row["session_id"] / "oversized.json"
        record.parent.mkdir()
        with record.open("wb") as stream:
            stream.truncate(MAX_ARTIFACT_BYTES + 1)

        next_row = create_session(self.challenge, "web")

        self.assertEqual(next_row["findings"], [])
        self.assertEqual(next_row["skipped_findings"]["reasons"], {"oversized_record": 1})

    def test_initializer_skips_tampered_shared_finding_evidence(self) -> None:
        row = create_session(self.challenge, "web")
        evidence = row["workspace"] / "artifacts" / "response.txt"
        evidence.write_bytes(b"original")
        finding = publish_finding(row["workspace"], "endpoint", evidence, "verified endpoint")
        payload = json.loads(finding.read_text(encoding="utf-8"))
        Path(payload["evidence"]).write_bytes(b"tampered")

        next_row = create_session(self.challenge, "web")

        self.assertEqual(next_row["findings"], [])
        self.assertEqual(next_row["skipped_findings"]["count"], 1)
        self.assertEqual(next_row["skipped_findings"]["reasons"], {"evidence_digest_mismatch": 1})

    def test_initializer_skips_missing_shared_finding_evidence(self) -> None:
        row = create_session(self.challenge, "web")
        evidence = row["workspace"] / "artifacts" / "response.txt"
        evidence.write_bytes(b"original")
        finding = publish_finding(row["workspace"], "endpoint", evidence, "verified endpoint")
        payload = json.loads(finding.read_text(encoding="utf-8"))
        Path(payload["evidence"]).unlink()

        next_row = create_session(self.challenge, "web")

        self.assertEqual(next_row["findings"], [])
        self.assertEqual(next_row["skipped_findings"]["reasons"], {"evidence_missing": 1})

    def test_initializer_skips_path_escaping_shared_finding_record(self) -> None:
        row = create_session(self.challenge, "web")
        evidence = row["workspace"] / "artifacts" / "response.txt"
        evidence.write_bytes(b"original")
        finding = publish_finding(row["workspace"], "endpoint", evidence, "verified endpoint")
        payload = json.loads(finding.read_text(encoding="utf-8"))
        outside = Path(self.temp.name) / "outside-evidence"
        outside.write_bytes(b"original")
        payload["evidence"] = str(outside)
        payload["evidence_sha256"] = hashlib.sha256(b"original").hexdigest()
        finding.write_text(json.dumps(payload), encoding="utf-8")

        next_row = create_session(self.challenge, "web")

        self.assertEqual(next_row["findings"], [])
        self.assertEqual(next_row["skipped_findings"]["reasons"], {"evidence_outside_finding": 1})

    def test_initializer_skips_malformed_shared_finding_record(self) -> None:
        row = create_session(self.challenge, "web")
        malformed = row["workspace"].parents[1] / "shared" / "findings" / row["session_id"] / "bad.json"
        malformed.parent.mkdir()
        malformed.write_text("not json", encoding="utf-8")

        next_row = create_session(self.challenge, "web")

        self.assertEqual(next_row["findings"], [])
        self.assertEqual(next_row["skipped_findings"]["reasons"], {"malformed_record": 1})

    def test_initializer_skips_shared_finding_with_wrong_owner(self) -> None:
        row = create_session(self.challenge, "web")
        evidence = row["workspace"] / "artifacts" / "response.txt"
        evidence.write_bytes(b"original")
        finding = publish_finding(row["workspace"], "endpoint", evidence, "verified endpoint")
        payload = json.loads(finding.read_text(encoding="utf-8"))
        payload["session_id"] = "web-other"
        finding.write_text(json.dumps(payload), encoding="utf-8")

        next_row = create_session(self.challenge, "web")

        self.assertEqual(next_row["findings"], [])
        self.assertEqual(next_row["skipped_findings"]["reasons"], {"invalid_finding_owner": 1})

    def test_initializer_skips_shared_finding_with_unknown_schema(self) -> None:
        row = create_session(self.challenge, "web")
        evidence = row["workspace"] / "artifacts" / "response.txt"
        evidence.write_bytes(b"original")
        finding = publish_finding(row["workspace"], "endpoint", evidence, "verified endpoint")
        payload = json.loads(finding.read_text(encoding="utf-8"))
        payload["schema_version"] = 99
        finding.write_text(json.dumps(payload), encoding="utf-8")

        next_row = create_session(self.challenge, "web")

        self.assertEqual(next_row["findings"], [])
        self.assertEqual(next_row["skipped_findings"]["reasons"], {"malformed_record": 1})

    def test_cli_parse_errors_are_one_json_object_with_exit_two(self) -> None:
        cases = (
            ("init_session.py", str(self.challenge), "--category", "misc"),
            ("verify_flag.py", "--workspace", str(self.root)),
        )

        for name, *args in cases:
            with self.subTest(script=name):
                result = run_common_script(name, *args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stderr, "")
                self.assertEqual(len(result.stdout.splitlines()), 1)
                self.assertEqual(json.loads(result.stdout)["status"], "error")

    def test_publish_cli_reports_collision_as_json_error(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "publish_finding_cli", SCRIPTS_DIR / "publish_finding.py"
        )
        self.assertIsNotNone(spec)
        cli = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cli)
        output = io.StringIO()

        with (
            patch.object(cli, "publish_finding", side_effect=CollisionError("finding collision")),
            patch.object(
                sys,
                "argv",
                [
                    "publish_finding.py",
                    "--workspace",
                    str(self.root),
                    "--kind",
                    "endpoint",
                    "--evidence",
                    str(self.root / "evidence.txt"),
                    "--summary",
                    "collision fixture",
                ],
            ),
            contextlib.redirect_stdout(output),
        ):
            code = cli.main()

        self.assertEqual(code, 2)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "error")


if __name__ == "__main__":
    unittest.main()
