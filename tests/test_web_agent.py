import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = REPO_ROOT / "web-agent"
COMMON_SCRIPTS = REPO_ROOT / "ctf-common" / "scripts"


def run_script(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(path), *args],
        text=True,
        capture_output=True,
        check=False,
    )


class WebAgentTests(unittest.TestCase):
    def make_workspace(self, root: Path, session_id: str) -> Path:
        event_root = root / "event"
        challenge = event_root / "challenges" / "portal"
        challenge.mkdir(parents=True, exist_ok=True)
        (challenge / "challenge.yaml").write_text(
            "id: portal\nauthorized: true\nnetwork_access: agent_allowed\n",
            encoding="utf-8",
        )
        result = run_script(
            COMMON_SCRIPTS / "init_session.py",
            str(challenge),
            "--category",
            "web",
            "--event-root",
            str(event_root),
            "--session-id",
            session_id,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return Path(json.loads(result.stdout)["workspace"])

    def init_web_state(self, workspace: Path) -> dict:
        result = run_script(
            SKILL_DIR / "scripts" / "init_web_state.py", "--workspace", str(workspace)
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def record_coverage(self, workspace: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return run_script(
            SKILL_DIR / "scripts" / "record_coverage.py", "--workspace", str(workspace), *args
        )

    def test_metadata_and_challenge_asset_are_structured_for_web(self) -> None:
        metadata = yaml.safe_load(
            (SKILL_DIR / "agents" / "openai.yaml").read_text(encoding="utf-8")
        )
        challenge = yaml.safe_load(
            (SKILL_DIR / "assets" / "challenge.yaml").read_text(encoding="utf-8")
        )

        self.assertEqual(metadata["interface"]["display_name"], "Web Agent")
        self.assertTrue(metadata["policy"]["allow_implicit_invocation"])
        self.assertIn("https://h4c.team/posts/74", metadata["sources"])
        self.assertEqual(challenge["category"], "web")

    def test_sessions_do_not_share_browser_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = self.init_web_state(self.make_workspace(root, "web-a"))
            second = self.init_web_state(self.make_workspace(root, "web-b"))

            self.assertNotEqual(first["cookie_jar"], second["cookie_jar"])
            self.assertNotEqual(first["browser_profile"], second["browser_profile"])
            for state in (first, second):
                self.assertTrue(Path(state["cookie_jar"]).is_file())
                self.assertTrue(Path(state["browser_profile"]).is_dir())
                self.assertTrue(Path(state["requests_dir"]).is_dir())
                self.assertTrue(Path(state["responses_dir"]).is_dir())
                coverage = json.loads(Path(state["coverage"]).read_text(encoding="utf-8"))
                self.assertEqual(coverage["entries"], [])

    def test_coverage_keeps_distinct_full_tuple_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "web-ledger")
            self.init_web_state(workspace)
            first = self.record_coverage(
                workspace,
                "--endpoint", "/search",
                "--method", "GET",
                "--location", "query",
                "--parameter", "q",
                "--technique", "reflection",
                "--status", "tested",
            )
            second = self.record_coverage(
                workspace,
                "--endpoint", "/search",
                "--method", "POST",
                "--location", "json",
                "--parameter", "filters",
                "--technique", "type-confusion",
                "--status", "tested",
            )

            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(second.returncode, 0, second.stderr)
            coverage = json.loads((workspace / "web" / "coverage.json").read_text(encoding="utf-8"))
            self.assertEqual(
                {
                    (entry["endpoint"], entry["method"], entry["location"], entry["parameter"], entry["technique"])
                    for entry in coverage["entries"]
                },
                {
                    ("/search", "GET", "query", "q", "reflection"),
                    ("/search", "POST", "json", "filters", "type-confusion"),
                },
            )

    def test_coverage_transitions_are_atomic_and_confirmation_requires_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "web-transitions")
            self.init_web_state(workspace)
            base = (
                "--endpoint", "/account",
                "--method", "POST",
                "--location", "form",
                "--parameter", "email",
                "--technique", "sqli",
            )
            tested = self.record_coverage(workspace, *base, "--status", "tested")
            promising = self.record_coverage(workspace, *base, "--status", "promising")
            evidence = workspace / "web" / "responses" / "account.raw"
            evidence.write_bytes(b"HTTP/1.1 200 OK\r\n\r\ntarget result")
            confirmed = self.record_coverage(
                workspace, *base, "--status", "confirmed", "--evidence", str(evidence)
            )
            backward = self.record_coverage(workspace, *base, "--status", "tested")

            self.assertEqual(tested.returncode, 0, tested.stderr)
            self.assertEqual(json.loads(tested.stdout)["previous_status"], "untested")
            self.assertEqual(promising.returncode, 0, promising.stderr)
            self.assertEqual(confirmed.returncode, 0, confirmed.stderr)
            self.assertEqual(backward.returncode, 2)

            missing = (
                "--endpoint", "/admin",
                "--method", "GET",
                "--location", "header",
                "--parameter", "X-Role",
                "--technique", "spoofing",
            )
            self.assertEqual(self.record_coverage(workspace, *missing, "--status", "tested").returncode, 0)
            self.assertEqual(self.record_coverage(workspace, *missing, "--status", "promising").returncode, 0)
            no_evidence = self.record_coverage(workspace, *missing, "--status", "confirmed")
            self.assertEqual(no_evidence.returncode, 2)

            coverage = json.loads((workspace / "web" / "coverage.json").read_text(encoding="utf-8"))
            account = next(entry for entry in coverage["entries"] if entry["endpoint"] == "/account")
            admin = next(entry for entry in coverage["entries"] if entry["endpoint"] == "/admin")
            self.assertEqual(account["status"], "confirmed")
            self.assertEqual(Path(account["evidence"]), evidence)
            self.assertEqual(admin["status"], "promising")


if __name__ == "__main__":
    unittest.main()
