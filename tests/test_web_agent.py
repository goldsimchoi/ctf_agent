import json
import gzip
import hashlib
import http.server
import os
import base64
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zlib
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = REPO_ROOT / "web-agent"
COMMON_SCRIPTS = REPO_ROOT / "ctf-common" / "scripts"
REQUEST = SKILL_DIR / "assets" / "request.py"
VERIFY_WEB_FLAG = SKILL_DIR / "scripts" / "verify_web_flag.py"
sys.path.insert(0, str(SKILL_DIR / "scripts"))
from web_provenance import prepared_sent_evidence, sent_history  # noqa: E402
from ctf_workspace import MAX_ARTIFACT_BYTES  # noqa: E402
GZIP_BODY = gzip.compress(b"FLAG{compressed_target_result}", mtime=0)
READY_EXEC = """
import os
import sys

ready = sys.argv[1]
fd = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
try:
    os.write(fd, b"ready")
    os.fsync(fd)
finally:
    os.close(fd)
os.execv(sys.executable, [sys.executable, *sys.argv[2:]])
"""


def run_script(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(path), *args],
        text=True,
        capture_output=True,
        check=False,
    )


def start_ready_request(
    workspace: Path, url: str, ready: Path, *args: str
) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            sys.executable,
            "-c",
            READY_EXEC,
            str(ready),
            str(REQUEST),
            "--workspace",
            str(workspace),
            "--url",
            url,
            *args,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def wait_for_ready(process: subprocess.Popen[str], ready: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if ready.read_bytes() == b"ready":
                return
        except FileNotFoundError:
            pass
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(f"ready request exited early: {stdout} {stderr}")
        time.sleep(0.01)
    raise AssertionError("ready request did not publish its fsynced handshake")


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


class HistoryHandler(http.server.BaseHTTPRequestHandler):
    def _reply(self, body: str) -> None:
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self.server.hits += 1
        parsed = urlsplit(self.path)
        values = [value for _, value in parse_qsl(parsed.query, keep_blank_values=True)]
        if parsed.path == "/redirect-start":
            self.server.redirect_value = next(value for value in values if value.startswith("FLAG{"))
            self.send_response(302)
            self.send_header("Location", "/redirect-final")
            self.end_headers()
        elif parsed.path == "/redirect-final":
            self._reply(self.server.redirect_value)
        elif parsed.path == "/remember":
            self.server.previous_value = next(value for value in values if value.startswith("FLAG{"))
            self._reply("stored")
        elif parsed.path == "/return":
            self._reply(self.server.previous_value)
        elif parsed.path == "/return-form":
            self._reply(self.server.previous_form)
        elif parsed.path == "/return-json":
            self._reply(self.server.previous_json)
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        self.server.hits += 1
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        if self.path == "/remember-form":
            self.server.previous_form = next(value for _, value in parse_qsl(body) if value.startswith("FLAG{"))
            self._reply("stored")
        else:
            payload = json.loads(body)
            value = payload["nested"]["flag"]
            if self.path == "/remember-json":
                self.server.previous_json = value
                self._reply("stored")
            else:
                self._reply(value)

    def log_message(self, format: str, *args: object) -> None:
        pass


class EncodingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/bomb":
            body = gzip.compress(b"A" * (4 * 1024 * 1024 + 1), mtime=0)
            encoding = "gzip"
        elif self.path == "/deflate":
            body = zlib.compress(b"FLAG{deflate_target}")
            encoding = "deflate"
        elif self.path == "/malformed-gzip":
            body = b"not-a-gzip-stream"
            encoding = "gzip"
        elif self.path == "/malformed-deflate":
            body = b"not-a-deflate-stream"
            encoding = "deflate"
        elif self.path == "/trailing":
            body = gzip.compress(b"FLAG{trailing_target}", mtime=0) + b"trailing"
            encoding = "gzip"
        else:
            body = b"FLAG{unsupported_encoding}"
            encoding = "br"
        self.send_response(200)
        self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class BarrierHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        name = urlsplit(self.path).path.strip("/")
        self.server.order.append(name)
        if name == "first":
            self.server.first_seen.set()
            self.server.release.wait(timeout=5)
        else:
            self.server.second_seen.set()
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class RawBodyHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.server.hits += 1
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.bodies.append(body)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class FailedOutboundHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.server.hits += 1
        self.server.stored = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.accepted.set()
        self.send_response(200)
        self.send_header("Content-Length", "64")
        self.end_headers()
        self.wfile.write(b"partial")
        self.wfile.flush()
        time.sleep(1)

    def do_GET(self) -> None:
        self.server.hits += 1
        body = self.server.stored
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class ChainHandler(http.server.BaseHTTPRequestHandler):
    def _reply(self, body: bytes, redirect: str | None = None) -> None:
        self.send_response(302 if redirect else 200)
        if redirect:
            self.send_header("Location", redirect)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.server.hits += 1
        if self.path == "/start":
            self._reply(b"FLAG{same_chain}", "/final")
        elif self.path == "/final":
            self._reply(b"FLAG{same_chain}")
        else:
            self._reply(b"nothing here")

    def log_message(self, format: str, *args: object) -> None:
        pass


class SameUrlChainHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.server.hits += 1
        self.server.same_url_hits += 1
        if self.server.same_url_hits == 1:
            body = b"FLAG{same_url_chain}"
            self.send_response(302)
            self.send_header("Location", "/same")
        elif self.server.same_url_hits == 2:
            body = b"FLAG{same_url_chain}"
            self.send_response(200)
        else:
            body = b"no candidate"
            self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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

    def test_raw_plain_and_binary_request_bodies_are_echo_evidence(self) -> None:
        with local_server(RawBodyHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.bodies = []
            workspace = self.make_workspace(Path(temp), "web-raw-body", origin)
            self.init_web_state(workspace)
            plain = json.loads(self.request(
                workspace, origin + "/plain", "--method", "POST",
                "--header", "Content-Type=text/plain", "--data", "prefix FLAG{plain_body_echo}",
                "--progress", "new fact: plain raw body",
            ).stdout)
            binary_source = workspace / "artifacts" / "binary-input"
            binary_source.write_bytes(b"\x00\xffFLAG{binary_body_echo}\x80")
            binary = json.loads(run_script(
                REQUEST, "--workspace", str(workspace), "--url", origin + "/binary", "--method", "POST",
                "--header", "Content-Type=application/octet-stream", "--data-file", str(binary_source),
                "--progress", "new fact: binary raw body",
            ).stdout)

            self.assertEqual(server.bodies, [b"prefix FLAG{plain_body_echo}", b"\x00\xffFLAG{binary_body_echo}\x80"])
            for captured in (plain, binary):
                rejected = self.verify(workspace, "--output", captured["response_entity_body"])
                self.assertEqual(rejected.returncode, 2)
                self.assertEqual(json.loads(rejected.stdout)["status"], "unverified")

    def test_failed_outbound_request_stays_in_history_and_blocks_later_echo(self) -> None:
        with local_server(FailedOutboundHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.accepted = threading.Event()
            server.stored = b""
            workspace = self.make_workspace(Path(temp), "web-incomplete", origin)
            self.init_web_state(workspace)
            failed = self.request(
                workspace, origin + "/store", "--method", "POST", "--data", "FLAG{failed_send_echo}",
                "--timeout", "0.1", "--progress", "new fact: timeout after store",
            )
            self.assertEqual(failed.returncode, 2, failed.stderr)
            self.assertTrue(server.accepted.wait(timeout=2))
            history = json.loads((workspace / "web" / "history.json").read_text(encoding="utf-8"))
            self.assertEqual(len(history["requests"]), 1)
            self.assertFalse(history["requests"][0]["complete"])
            self.assertTrue(Path(history["requests"][0]["request"]).is_file())
            self.assertEqual(list((workspace / "web" / "captures").iterdir()), [])

            reflected = json.loads(self.request(
                workspace, origin + "/return", "--progress", "new fact: stored value returned"
            ).stdout)
            rejected = self.verify(workspace, "--output", reflected["response_entity_body"])
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(json.loads(rejected.stdout)["status"], "unverified")

    def test_sent_history_counts_boundaries_and_leaves_overflow_capture_unattested(self) -> None:
        with local_server(TargetHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.external_url = origin
            workspace = self.make_workspace(Path(temp), "web-history-bound", origin)
            self.init_web_state(workspace)
            requests_dir = workspace / "web" / "requests"

            def prepared(body_size: int, padding: int = 0) -> bytes:
                return json.dumps({
                    "method": "POST", "url": origin + "/history", "headers": [],
                    "body_base64": base64.b64encode(b"x" * body_size).decode("ascii"),
                    "padding": "p" * padding, "wire_exact": False,
                }, separators=(",", ":")).encode("utf-8")

            second = prepared(0)
            second_evidence = prepared_sent_evidence(second)
            target = MAX_ARTIFACT_BYTES - len(second_evidence)
            low, high, best = 0, target, prepared(0)
            while low <= high:
                middle = (low + high) // 2
                candidate = prepared(middle)
                try:
                    evidence = prepared_sent_evidence(candidate)
                except ValueError:
                    high = middle - 1
                    continue
                if len(evidence) <= target:
                    best = candidate
                    low = middle + 1
                else:
                    high = middle - 1
            padding = target - len(prepared_sent_evidence(best))
            first = json.loads(best)
            first["padding"] += "p" * padding
            first = json.dumps(first, separators=(",", ":")).encode("utf-8")
            self.assertEqual(len(prepared_sent_evidence(first)) + len(second_evidence), MAX_ARTIFACT_BYTES)
            first_path = requests_dir / "near-bound.prepared.json"
            second_path = requests_dir / "second.prepared.json"
            first_path.write_bytes(first)
            second_path.write_bytes(second)
            self.assertEqual(len(sent_history(workspace, [first_path])), MAX_ARTIFACT_BYTES - len(second_evidence))
            self.assertTrue(sent_history(workspace, [first_path, second_path]) is None)

            (workspace / "web" / "history.json").write_text(json.dumps({
                "schema_version": 1, "requests": [{"request": str(first_path), "complete": True}],
            }), encoding="utf-8")
            captured = json.loads(self.request(
                workspace, origin + "/gzip", "--progress", "new fact: boundary history capture"
            ).stdout)
            provenance = json.loads(Path(captured["provenance"]).read_text(encoding="utf-8"))
            self.assertIsNone(captured["attestation"])
            self.assertNotIn("capture", provenance)
            rejected = self.verify(workspace, "--output", captured["response_entity_body"])
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(json.loads(rejected.stdout)["status"], "error")

    def test_strict_rejects_duplicate_same_url_request_chain(self) -> None:
        with local_server(SameUrlChainHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.same_url_hits = 0
            workspace = self.make_workspace(Path(temp), "web-strict-chain", origin)
            self.init_web_state(workspace)
            chain = json.loads(self.request(workspace, origin + "/same", "--progress", "new fact: same URL redirect chain").stdout)
            unrelated = json.loads(self.request(workspace, origin + "/same", "--progress", "new fact: same URL unrelated output").stdout)
            bodies = json.loads(Path(chain["summary"]).read_text(encoding="utf-8"))["response_entity_bodies"]
            rejected = self.verify(workspace, "--strict", "--output", bodies[0], "--output", bodies[1], "--output", unrelated["response_entity_body"])

            self.assertEqual(rejected.returncode, 2)
            payload = json.loads(rejected.stdout)
            self.assertEqual(payload["status"], "error")
            self.assertEqual(payload["error"], "strict mode requires two distinct authorized web requests")

    def test_web_state_rejects_symlinked_root_and_swapped_write_or_lock_targets(self) -> None:
        with local_server(TargetHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.external_url = origin
            root = Path(temp)
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_text("unchanged", encoding="utf-8")

            initial = self.make_workspace(root, "web-symlink-init", origin)
            (initial / "web").symlink_to(outside, target_is_directory=True)
            init = run_script(SKILL_DIR / "scripts" / "init_web_state.py", "--workspace", str(initial))
            self.assertEqual(init.returncode, 2)
            self.assertEqual(sorted(path.name for path in outside.iterdir()), ["sentinel"])

            swapped = self.make_workspace(root, "web-symlink-write", origin)
            self.init_web_state(swapped)
            responses = swapped / "web" / "responses"
            responses.rmdir()
            responses.symlink_to(outside, target_is_directory=True)
            write_rejected = self.request(swapped, origin + "/gzip", "--progress", "new fact: swapped response directory")
            self.assertEqual(write_rejected.returncode, 2)
            self.assertEqual(sorted(path.name for path in outside.iterdir()), ["sentinel"])

            locked = self.make_workspace(root, "web-symlink-lock", origin)
            self.init_web_state(locked)
            (locked / "web" / ".history.lock").symlink_to(outside / "lock")
            lock_rejected = self.request(locked, origin + "/gzip", "--progress", "new fact: swapped history lock")
            self.assertEqual(lock_rejected.returncode, 2)
            self.assertEqual(sorted(path.name for path in outside.iterdir()), ["sentinel"])

    def test_request_publishes_capture_time_common_attestation(self) -> None:
        with local_server(TargetHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.external_url = origin
            workspace = self.make_workspace(Path(temp), "web-attestation", origin)
            self.init_web_state(workspace)
            captured = json.loads(self.request(
                workspace, origin + "/gzip", "--progress", "new fact: attested target"
            ).stdout)
            provenance = json.loads(Path(captured["provenance"]).read_text(encoding="utf-8"))
            attestation = Path(captured["attestation"])
            record = json.loads(attestation.read_text(encoding="utf-8"))

            self.assertTrue(attestation.is_file())
            self.assertEqual(attestation.parent, workspace / "artifacts" / "captures")
            self.assertEqual(record["source_target"], origin + "/gzip")
            self.assertEqual(record["output"]["path"], provenance["capture"]["output"])
            self.assertEqual(record["sent"]["path"], provenance["capture"]["sent"])

    def test_verifier_rejects_current_json_redirect_and_prior_session_echoes(self) -> None:
        with local_server(HistoryHandler) as (_, origin), tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "web-history", origin)
            self.init_web_state(workspace)
            current_json = json.loads(self.request(
                workspace, origin + "/json", "--method", "POST",
                "--header", "Content-Type=application/json",
                "--json", '{"nested":{"flag":"FLAG{json_echo}"}}',
                "--progress", "new fact: JSON echo",
            ).stdout)
            redirect = json.loads(self.request(
                workspace, origin + "/redirect-start?x=FLAG%7Bredirect_echo%7D",
                "--progress", "new fact: redirect echo",
            ).stdout)
            self.request(
                workspace, origin + "/remember?x=FLAG%7Bprior_echo%7D",
                "--progress", "new fact: prior query",
            )
            prior = json.loads(self.request(
                workspace, origin + "/return", "--progress", "new fact: prior reflection"
            ).stdout)
            self.request(
                workspace, origin + "/remember-form", "--method", "POST",
                "--header", "Content-Type=application/x-www-form-urlencoded",
                "--data", "x=FLAG%7Bprior_form%7D",
                "--progress", "new fact: prior form",
            )
            prior_form = json.loads(self.request(
                workspace, origin + "/return-form", "--progress", "new fact: prior form reflection"
            ).stdout)
            self.request(
                workspace, origin + "/remember-json", "--method", "POST",
                "--header", "Content-Type=application/json",
                "--json", '{"nested":{"flag":"FLAG{prior_json}"}}',
                "--progress", "new fact: prior JSON",
            )
            prior_json = json.loads(self.request(
                workspace, origin + "/return-json", "--progress", "new fact: prior JSON reflection"
            ).stdout)

            self.assertEqual(self.verify(workspace, "--output", current_json["response_entity_body"]).returncode, 2)
            self.assertEqual(self.verify(workspace, "--output", redirect["response_entity_body"]).returncode, 2)
            self.assertEqual(self.verify(workspace, "--output", prior["response_entity_body"]).returncode, 2)
            self.assertEqual(self.verify(workspace, "--output", prior_form["response_entity_body"]).returncode, 2)
            self.assertEqual(self.verify(workspace, "--output", prior_json["response_entity_body"]).returncode, 2)

    def test_web_verifier_rejects_tampered_attested_capture(self) -> None:
        with local_server(TargetHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.external_url = origin
            workspace = self.make_workspace(Path(temp), "web-tamper", origin)
            self.init_web_state(workspace)
            captured = json.loads(self.request(
                workspace, origin + "/gzip", "--progress", "new fact: capture for tamper"
            ).stdout)
            provenance = json.loads(Path(captured["provenance"]).read_text(encoding="utf-8"))
            Path(provenance["capture"]["output"]).write_bytes(b"FLAG{tampered}")

            self.assertEqual(self.verify(workspace, "--output", captured["response_entity_body"]).returncode, 2)

    def test_oversized_or_unsupported_encoded_body_is_recorded_but_unattested(self) -> None:
        with local_server(EncodingHandler) as (_, origin), tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "web-encoding", origin)
            self.init_web_state(workspace)
            bomb = json.loads(self.request(
                workspace, origin + "/bomb", "--progress", "new fact: compressed expansion"
            ).stdout)
            unsupported = json.loads(self.request(
                workspace, origin + "/unsupported", "--progress", "new fact: unsupported encoding"
            ).stdout)

            for captured in (bomb, unsupported):
                provenance = json.loads(Path(captured["provenance"]).read_text(encoding="utf-8"))
                self.assertIsNone(captured["attestation"])
                self.assertNotIn("capture", provenance)
                rejected = self.verify(workspace, "--output", captured["response_entity_body"])
                self.assertEqual(rejected.returncode, 2)
                self.assertEqual(json.loads(rejected.stdout)["status"], "error")

    def test_deflate_verifies_but_malformed_and_trailing_encodings_are_unattested(self) -> None:
        with local_server(EncodingHandler) as (_, origin), tempfile.TemporaryDirectory() as temp:
            workspace = self.make_workspace(Path(temp), "web-codecs", origin)
            self.init_web_state(workspace)
            valid = json.loads(self.request(
                workspace, origin + "/deflate", "--progress", "new fact: deflate target"
            ).stdout)
            malformed_gzip = json.loads(self.request(
                workspace, origin + "/malformed-gzip", "--progress", "new fact: bad gzip"
            ).stdout)
            malformed_deflate = json.loads(self.request(
                workspace, origin + "/malformed-deflate", "--progress", "new fact: bad deflate"
            ).stdout)
            trailing = json.loads(self.request(
                workspace, origin + "/trailing", "--progress", "new fact: trailing data"
            ).stdout)

            verified = self.verify(workspace, "--output", valid["response_entity_body"])
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(json.loads(verified.stdout)["status"], "verified")
            for captured in (malformed_gzip, malformed_deflate, trailing):
                provenance = json.loads(Path(captured["provenance"]).read_text(encoding="utf-8"))
                self.assertIsNone(captured["attestation"])
                self.assertNotIn("capture", provenance)
                rejected = self.verify(workspace, "--output", captured["response_entity_body"])
                self.assertEqual(rejected.returncode, 2)
                self.assertEqual(json.loads(rejected.stdout)["status"], "error")

    def test_web_validation_rejects_forged_capture_cross_links(self) -> None:
        with local_server(TargetHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.external_url = origin
            workspace = self.make_workspace(Path(temp), "web-links", origin)
            self.init_web_state(workspace)
            first = json.loads(self.request(workspace, origin + "/gzip", "--progress", "new fact: first link").stdout)
            second = json.loads(self.request(workspace, origin + "/gzip", "--progress", "new fact: second link").stdout)
            provenance_path = Path(first["provenance"])
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
            second_record = json.loads(Path(second["provenance"]).read_text(encoding="utf-8"))
            provenance["request_url"] = origin + "/forged"
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
            bad_url = self.verify(workspace, "--output", first["response_entity_body"])
            provenance["request_url"] = origin + "/gzip"
            provenance["capture"]["output"] = second_record["capture"]["output"]
            provenance["capture"]["output_sha256"] = second_record["capture"]["output_sha256"]
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
            bad_link = self.verify(workspace, "--output", first["response_entity_body"])

            self.assertEqual(json.loads(bad_url.stdout)["status"], "error")
            self.assertEqual(json.loads(bad_link.stdout)["status"], "error")

    def test_same_session_concurrent_requests_preserve_both_history_entries(self) -> None:
        with local_server(BarrierHandler) as (server, origin), tempfile.TemporaryDirectory() as temp:
            server.order = []
            server.first_seen = threading.Event()
            server.second_seen = threading.Event()
            server.release = threading.Event()
            workspace = self.make_workspace(Path(temp), "web-concurrent", origin)
            self.init_web_state(workspace)
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(
                    self.request, workspace, origin + "/first?input=before", "--progress", "new fact: first"
                )
                self.assertTrue(server.first_seen.wait(timeout=5))
                second = start_ready_request(
                    workspace,
                    origin + "/second",
                    Path(temp) / "second-ready",
                    "--progress",
                    "new fact: second",
                )
                try:
                    wait_for_ready(second, Path(temp) / "second-ready", timeout=5)
                    self.assertFalse(server.second_seen.wait(timeout=3))
                    self.assertEqual(server.order, ["first"])
                finally:
                    server.release.set()
                    try:
                        second_stdout, second_stderr = second.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        second.kill()
                        second_stdout, second_stderr = second.communicate(timeout=5)

                first_result = first.result(timeout=10)
                second_result = subprocess.CompletedProcess(
                    second.args, second.returncode, second_stdout, second_stderr
                )

            self.assertEqual(first_result.returncode, 0, first_result.stderr)
            self.assertEqual(second_result.returncode, 0, second_result.stderr)
            self.assertEqual(server.order, ["first", "second"])
            history = json.loads((workspace / "web" / "history.json").read_text(encoding="utf-8"))
            self.assertEqual(len(history["requests"]), 2)
            second_capture = json.loads(second_result.stdout)
            second_provenance = json.loads(Path(second_capture["provenance"]).read_text(encoding="utf-8"))
            self.assertIn(b"query:input=before", Path(second_provenance["capture"]["sent"]).read_bytes())

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
