import contextlib
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
    create_session,
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
        output = self.root / "output.txt"
        sent = self.root / "sent.txt"
        output.write_bytes(b"target response FLAG{real}\n")
        sent.write_bytes(b"menu choice 1\n")
        pattern = (rb"FLAG\{[^}\r\n]+\}",)

        race = verify_outputs([output], [sent], pattern, strict=False)
        strict = verify_outputs([output], [sent], pattern, strict=True)
        self.assertEqual(race["status"], "verified")
        self.assertEqual(race["flag"], "FLAG{real}")
        self.assertEqual(strict["reason"], "requires_two_clean_reproductions")

    def test_verification_rejects_echoed_candidates(self) -> None:
        output = self.root / "output.txt"
        sent = self.root / "sent.txt"
        output.write_bytes(b"FLAG{echoed}\n")
        sent.write_bytes(b"FLAG{echoed}\n")

        result = verify_outputs([output], [sent], (rb"FLAG\{[^}\r\n]+\}",), strict=False)
        self.assertEqual(result["status"], "unverified")
        self.assertEqual(result["reason"], "candidate_was_user_input")

    def test_strict_verification_counts_a_candidate_in_two_of_three_outputs(self) -> None:
        outputs = [self.root / f"output-{number}.txt" for number in range(3)]
        outputs[0].write_bytes(b"FLAG{reproduced}\n")
        outputs[1].write_bytes(b"again FLAG{reproduced}\n")
        outputs[2].write_bytes(b"later output has no candidate\n")

        result = verify_outputs(outputs, [], (rb"FLAG\{[^}\r\n]+\}",), strict=True)

        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["flag"], "FLAG{reproduced}")
        self.assertEqual(result["reproductions"], 2)

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
