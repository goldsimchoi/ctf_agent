import json
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
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
        self.assertEqual(payload["evidence"], str(evidence.resolve()))
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


if __name__ == "__main__":
    unittest.main()
