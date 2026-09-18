import json
import gzip
import hashlib
import http.server
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = REPO_ROOT / "web-agent"
COMMON_SCRIPTS = REPO_ROOT / "ctf-common" / "scripts"
REQUEST = SKILL_DIR / "assets" / "request.py"
VERIFY_WEB_FLAG = SKILL_DIR / "scripts" / "verify_web_flag.py"
GZIP_BODY = gzip.compress(b"FLAG{compressed_target_result}", mtime=0)


def run_script(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(path), *args],
        text=True,
        capture_output=True,
        check=False,
    )


class TargetHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.server.hits += 1
        if self.path == "/gzip":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("X-Target-Evidence", "present")
            self.send_header("Content-Length", str(len(GZIP_BODY)))
            self.end_headers()
            self.wfile.write(GZIP_BODY)
        elif self.path == "/external-redirect":
            self.send_response(302)
            self.send_header("Location", self.server.external_url + "/outside")
            self.end_headers()
        else:
            self.send_error(404)

    def log_message(self, format: str, *args: object) -> None:
        pass


class CountHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.server.hits += 1
        self.send_response(200)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


class EchoHandler(http.server.BaseHTTPRequestHandler):
    def _reply(self, encoded: str) -> None:
        values = [value for _, value in parse_qsl(encoded, keep_blank_values=True)]
        body = next((value for value in values if value.startswith("FLAG{")), "no flag").encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.server.hits += 1
        self._reply(urlsplit(self.path).query)

    def do_POST(self) -> None:
        self.server.hits += 1
        length = int(self.headers.get("Content-Length", "0"))
        self._reply(self.rfile.read(length).decode("ascii"))

    def log_message(self, format: str, *args: object) -> None:
        pass


@contextmanager
def local_server(handler: type[http.server.BaseHTTPRequestHandler]):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.hits = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


class WebAgentTests(unittest.TestCase):
    def make_workspace(
        self, root: Path, session_id: str, origin: str | None = None, category: str = "web"
    ) -> Path:
        event_root = root / "event"
        challenge = event_root / "challenges" / "portal"
        challenge.mkdir(parents=True, exist_ok=True)
        manifest = "id: portal\nauthorized: true\nnetwork_access: agent_allowed\n"
        if origin is not None:
            manifest += f"origin: {origin}\n"
        (challenge / "challenge.yaml").write_text(
            manifest,
            encoding="utf-8",
        )
        result = run_script(
            COMMON_SCRIPTS / "init_session.py",
            str(challenge),
            "--category",
            category,
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

    def request(self, workspace: Path, url: str, *args: str) -> subprocess.CompletedProcess[str]:
        return run_script(REQUEST, "--workspace", str(workspace), "--url", url, *args)

    def verify(self, workspace: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return run_script(VERIFY_WEB_FLAG, "--workspace", str(workspace), *args)

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

    def test_coverage_transitions_are_atomic_and_confirmation_requires_verified_evidence(self) -> None:
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
            fake_evidence = workspace / "web" / "responses" / "account.body"
            fake_evidence.write_bytes(b"not recorded target evidence")
            confirmed = self.record_coverage(
                workspace, *base, "--status", "confirmed", "--evidence", str(fake_evidence)
            )

            self.assertEqual(tested.returncode, 0, tested.stderr)
            self.assertEqual(json.loads(tested.stdout)["previous_status"], "untested")
            self.assertEqual(promising.returncode, 0, promising.stderr)
            self.assertEqual(confirmed.returncode, 2)

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
            self.assertEqual(account["status"], "promising")
            self.assertEqual(admin["status"], "promising")

    def test_request_preserves_undecoded_body_and_records_provenance(self) -> None:
        with local_server(TargetHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.external_url = origin
            workspace = self.make_workspace(Path(temp), "web-capture", origin)
            self.init_web_state(workspace)
            result = self.request(workspace, origin + "/gzip", "--progress", "new fact: gzip evidence")

            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads(result.stdout)
            response = Path(output["response_entity_body"])
            provenance = json.loads(Path(output["provenance"]).read_text(encoding="utf-8"))
            self.assertEqual(response.suffix, ".body")
            self.assertEqual(response.read_bytes(), GZIP_BODY)
            self.assertEqual(provenance["entity_body_sha256"], hashlib.sha256(GZIP_BODY).hexdigest())
            self.assertEqual(provenance["status"], 200)
            self.assertIn(["X-Target-Evidence", "present"], provenance["headers"])
            self.assertFalse(provenance["request_capture"]["wire_exact"])
            self.assertFalse(provenance["body_capture"]["wire_exact"])
            self.assertEqual(provenance["body_capture"]["content_encoding"], "gzip")
            self.assertIn("HTTP framing", provenance["body_capture"]["transport_limitations"])

    def test_request_rejects_target_origin_and_non_web_session_before_traffic(self) -> None:
        with local_server(TargetHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.external_url = origin
            root = Path(temp)
            workspace = self.make_workspace(root, "web-target-origin")
            self.init_web_state(workspace)
            (workspace / "challenge.resolved.yaml").write_text(
                f"authorized: true\nnetwork_access: agent_allowed\ntarget_origin: {origin}\n",
                encoding="utf-8",
            )
            rejected_alias = self.request(workspace, origin + "/gzip")
            self.assertEqual(rejected_alias.returncode, 2)
            self.assertEqual(server.hits, 0)

            pwn = self.make_workspace(root, "pwn-traffic", origin, category="pwn")
            web = pwn / "web"
            for directory in (web / "requests", web / "responses"):
                directory.mkdir(parents=True)
            (web / "cookies.json").write_text('{"cookies": []}\n', encoding="utf-8")
            rejected_category = self.request(pwn, origin + "/gzip")
            self.assertEqual(rejected_category.returncode, 2)
            self.assertEqual(server.hits, 0)

    def test_request_rejects_external_redirect_without_following_it(self) -> None:
        with local_server(CountHandler) as (outside, outside_origin), local_server(TargetHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.external_url = outside_origin
            workspace = self.make_workspace(Path(temp), "web-redirect", origin)
            self.init_web_state(workspace)
            result = self.request(workspace, origin + "/external-redirect")

            self.assertEqual(result.returncode, 2)
            self.assertEqual(server.hits, 1)
            self.assertEqual(outside.hits, 0)

    def test_web_verifier_requires_recorded_provenance_for_race_and_strict(self) -> None:
        with local_server(TargetHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.external_url = origin
            workspace = self.make_workspace(Path(temp), "web-verify", origin)
            self.init_web_state(workspace)
            first = json.loads(self.request(
                workspace, origin + "/gzip", "--progress", "new fact: first target result"
            ).stdout)
            arbitrary = workspace / "artifacts" / "shell-output.raw"
            arbitrary.write_bytes(b"FLAG{shell_output}")
            rejected = self.verify(workspace, "--output", str(arbitrary))
            race = self.verify(workspace, "--output", first["response_entity_body"])
            duplicate_strict = self.verify(
                workspace, "--output", first["response_entity_body"], "--output", first["response_entity_body"], "--strict"
            )
            second = json.loads(self.request(
                workspace, origin + "/gzip", "--progress", "new fact: second target result"
            ).stdout)
            strict = self.verify(
                workspace, "--output", first["response_entity_body"], "--output", second["response_entity_body"], "--strict"
            )

            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(race.returncode, 0, race.stdout + race.stderr)
            self.assertEqual(json.loads(race.stdout)["flag"], "FLAG{compressed_target_result}")
            self.assertEqual(duplicate_strict.returncode, 2)
            self.assertEqual(strict.returncode, 0, strict.stderr)

            base = (
                "--endpoint", "/gzip", "--method", "GET", "--location", "query",
                "--parameter", "probe", "--technique", "compression",
            )
            self.assertEqual(self.record_coverage(workspace, *base, "--status", "tested").returncode, 0)
            self.assertEqual(self.record_coverage(workspace, *base, "--status", "promising").returncode, 0)
            self.assertEqual(
                self.record_coverage(workspace, *base, "--status", "confirmed", "--evidence", first["response_entity_body"]).returncode,
                0,
            )

    def test_web_verifier_rejects_percent_decoded_url_and_form_echoes(self) -> None:
        with local_server(EchoHandler) as (_, origin), tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "web-echo", origin)
            self.init_web_state(workspace)
            from_url = json.loads(self.request(
                workspace,
                origin + "/echo?one=FLAG%7Bvalue%7D&one=second+value",
                "--progress", "new fact: encoded URL echo",
            ).stdout)
            from_form = json.loads(self.request(
                workspace,
                origin + "/echo",
                "--method", "POST",
                "--header", "Content-Type=application/x-www-form-urlencoded",
                "--data", "one=FLAG%7Bvalue%7D&one=second+value",
                "--progress", "new fact: encoded form echo",
            ).stdout)

            self.assertEqual(self.verify(workspace, "--output", from_url["response_entity_body"]).returncode, 2)
            self.assertEqual(self.verify(workspace, "--output", from_form["response_entity_body"]).returncode, 2)

    def test_web_verifier_rejects_echo_in_second_repeated_query_and_form_value(self) -> None:
        with local_server(EchoHandler) as (_, origin), tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "web-second-echo", origin)
            self.init_web_state(workspace)
            from_query = json.loads(self.request(
                workspace,
                origin + "/echo?one=benign&one=FLAG%7Bsecond%7D",
                "--progress", "new fact: second query echo",
            ).stdout)
            from_form = json.loads(self.request(
                workspace,
                origin + "/echo",
                "--method", "POST",
                "--header", "Content-Type=application/x-www-form-urlencoded",
                "--data", "one=benign&one=FLAG%7Bsecond%7D",
                "--progress", "new fact: second form echo",
            ).stdout)

            self.assertEqual(self.verify(workspace, "--output", from_query["response_entity_body"]).returncode, 2)
            self.assertEqual(self.verify(workspace, "--output", from_form["response_entity_body"]).returncode, 2)

    def test_web_verifier_rejects_plus_decoded_words_in_reflected_flag(self) -> None:
        with local_server(EchoHandler) as (_, origin), tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "web-plus-echo", origin)
            self.init_web_state(workspace)
            response = json.loads(self.request(
                workspace,
                origin + "/echo?one=benign&one=FLAG%7Btwo+words%7D",
                "--progress", "new fact: plus decoded echo",
            ).stdout)

            verified = self.verify(workspace, "--output", response["response_entity_body"])
            self.assertEqual(verified.returncode, 2)


if __name__ == "__main__":
    unittest.main()
