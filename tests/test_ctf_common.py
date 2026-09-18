import contextlib
import hashlib
import importlib.util
import io
import json
import os
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

from ctf_intake import (  # noqa: E402
    MAX_FIELD_BYTES,
    MAX_STATEMENT_BYTES,
    IntakeError,
    IntakeRequest,
    read_request_json,
    render_resolved_manifest,
    resolve_intake,
)
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


def run_common_script(
    name: str,
    *args: str,
    input: str | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / name), *args],
        text=True,
        capture_output=True,
        check=False,
        input=input,
        timeout=timeout,
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

    @staticmethod
    def snapshot_tree(root: Path) -> dict[str, tuple[str, bytes | str]]:
        snapshot: dict[str, tuple[str, bytes | str]] = {}
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                snapshot[relative] = ("symlink", os.readlink(path))
            elif path.is_dir():
                snapshot[relative] = ("directory", "")
            elif path.is_file():
                snapshot[relative] = ("file", path.read_bytes())
            else:
                snapshot[relative] = ("other", "")
        return snapshot

    def test_flat_and_fileless_intake_does_not_mutate_challenge_inputs(self) -> None:
        flat = Path(self.temp.name) / "flat-event"
        pwn = flat / "babypwn"
        rev = flat / "crackme"
        web = flat / "admin-panel"
        for challenge in (pwn, rev, web):
            challenge.mkdir(parents=True)
        (pwn / "chall").write_bytes(b"ELF fixture")
        (rev / "checker").write_bytes(b"PE fixture")
        before = {path.name: self.snapshot_tree(path) for path in (pwn, rev, web)}

        pwn_row = create_session(
            pwn, "pwn", intake=IntakeRequest(statement="local pwn", binary="chall")
        )
        rev_row = create_session(
            rev, "rev", intake=IntakeRequest(statement="local rev", binary="checker")
        )
        request = IntakeRequest(
            statement="관리자 페이지에서 플래그를 찾아라\nhttps://box.example:8443/start?q=1",
            target="https://box.example:8443/start?q=1",
        )
        web_row = create_session(web, "web", intake=request)

        self.assertEqual(
            {path.name: self.snapshot_tree(path) for path in (pwn, rev, web)}, before
        )
        self.assertEqual(pwn_row["intake"]["target_status"], "bound")
        self.assertEqual(rev_row["intake"]["target_status"], "bound")
        stored = json.loads(
            (web_row["workspace"] / "challenge-request.json").read_text(encoding="utf-8")
        )
        resolved = (web_row["workspace"] / "challenge.resolved.yaml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(stored["statement"], request.statement)
        self.assertEqual(stored["normalized"]["origin"], "https://box.example:8443")
        self.assertIn("origin: https://box.example:8443", resolved)
        self.assertNotIn(request.statement, resolved)
        self.assertEqual(web_row["intake"]["target_status"], "bound")

    def test_event_root_itself_is_not_a_challenge_but_direct_child_is(self) -> None:
        managed = Path(self.temp.name) / "CTF"
        (managed / ".tools").mkdir(parents=True)
        (managed / ".tools" / "env.sh").write_text("export SAFE=1\n", encoding="utf-8")
        (managed / ".venv").mkdir()
        (managed / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
        problem = managed / "direct-problem"
        problem.mkdir()

        with self.assertRaisesRegex(InvalidInput, "event root"):
            create_session(managed, "web", managed)

        row = create_session(
            problem,
            "web",
            managed,
            intake=IntakeRequest(target="https://box.example/"),
        )
        self.assertTrue((managed / "runs").is_dir())
        self.assertEqual(row["workspace"].parents[4], managed)

    def test_request_json_stdin_is_inert_lossless_and_single_document(self) -> None:
        challenge = Path(self.temp.name) / "stdin-web"
        challenge.mkdir()
        marker = Path(self.temp.name) / "must-not-exist"
        statement = (
            "관리자 페이지\nEnglish `quoted` \"text\" "
            f"$(touch {marker}) {{{{ template.value }}}}"
        )
        payload = json.dumps(
            {"statement": statement, "target": "https://box.example:443/start?q=1"},
            ensure_ascii=False,
        )

        result = run_common_script(
            "init_session.py",
            str(challenge),
            "--category",
            "web",
            "--request-json",
            "-",
            input=payload,
        )

        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertEqual(len(result.stdout.splitlines()), 1)
        row = json.loads(result.stdout)
        self.assertEqual(row["intake"]["target_status"], "bound")
        stored = json.loads(Path(row["intake"]["request_path"]).read_text(encoding="utf-8"))
        self.assertEqual(stored["statement"], statement)
        self.assertEqual(stored["normalized"]["origin"], "https://box.example")
        self.assertFalse(marker.exists())

    def test_request_json_wire_bound_allows_a_maximum_escaped_statement(self) -> None:
        statement = "\\" * MAX_STATEMENT_BYTES
        encoded = json.dumps({"statement": statement}).encode("utf-8")

        request = read_request_json(io.BytesIO(encoded))

        self.assertEqual(request.statement, statement)

    def test_manifest_renderer_quotes_yaml_indicators_and_implicit_types(self) -> None:
        values = {
            "leading_at": "@FLAG",
            "leading_anchor": "&FLAG",
            "date_like": "2026-09-19",
        }
        intake = resolve_intake("web", IntakeRequest(), {})
        intake["manifest"].update(values)

        rendered = render_resolved_manifest("quoted-scalars", "web", intake)
        serialized = {
            line.split(":", 1)[0]: line.split(":", 1)[1].strip()
            for line in rendered.splitlines()
        }

        for key, expected in values.items():
            with self.subTest(key=key):
                self.assertTrue(serialized[key].startswith('"'))
                self.assertEqual(json.loads(serialized[key]), expected)

    def test_legacy_scalar_manifest_preserves_quotes_comments_and_escapes(self) -> None:
        event = Path(self.temp.name) / "quoted-legacy-event"
        challenge = event / "challenge"
        challenge.mkdir(parents=True)
        (challenge / "chall#one").write_bytes(b"fixture")
        (challenge / "challenge.yaml").write_text(
            'id: "quoted\\u002did"\n'
            "binary: 'chall#one' # selected executable\n"
            'flag_pattern: "FLAG\\\\{quoted#value\\\\}"\n'
            'wall_time_seconds: "900"   \n'
            "mode: race # trailing comment\n",
            encoding="utf-8",
        )

        result = run_common_script(
            "init_session.py", str(challenge), "--category", "rev"
        )

        self.assertEqual(result.returncode, 0, result.stdout)
        row = json.loads(result.stdout)
        stored = json.loads(
            Path(row["intake"]["request_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(row["challenge_id"], "quoted-id")
        self.assertEqual(stored["manifest"]["binary"], "chall#one")
        self.assertEqual(
            stored["manifest"]["flag_pattern"], r"FLAG\{quoted#value\}"
        )
        state = json.loads((Path(row["workspace"]) / "state.json").read_text())
        self.assertEqual(state["wall_time_seconds"], 900)

    def test_legacy_manifest_rejects_unsupported_yaml_structures(self) -> None:
        manifests = (
            "id: nested\nmetadata:\n  owner: admin\n",
            "id: sequence\ntags: [one, two]\n",
            "id: block\ndescription: |\n  multiline\n",
        )
        for index, manifest in enumerate(manifests):
            with self.subTest(index=index):
                event = Path(self.temp.name) / f"unsupported-yaml-{index}"
                challenge = event / "challenge"
                challenge.mkdir(parents=True)
                (challenge / "challenge.yaml").write_text(manifest, encoding="utf-8")

                result = run_common_script(
                    "init_session.py", str(challenge), "--category", "web"
                )

                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)["status"], "error")
                self.assertFalse((event / "runs").exists())

    def test_conflicting_legacy_target_representations_fail_before_allocation(self) -> None:
        cases = (
            (
                "web",
                "id: web-conflict\n"
                "origin: https://box.example\n"
                "start_url: https://box.example/one\n"
                "target: https://box.example/two\n",
            ),
            (
                "pwn",
                "id: pwn-conflict\n"
                "target: tcp://one.example:31337\n"
                "protocol: tcp\n"
                "host: two.example\n"
                "port: 31337\n",
            ),
            (
                "pwn",
                "id: pwn-protocol-conflict\n"
                "target: tcp://one.example:31337\n"
                "protocol: udp\n"
                "host: one.example\n"
                "port: 31337\n",
            ),
        )
        for index, (category, manifest) in enumerate(cases):
            with self.subTest(category=category, index=index):
                event = Path(self.temp.name) / f"legacy-target-conflict-{index}"
                challenge = event / "challenge"
                challenge.mkdir(parents=True)
                (challenge / "challenge.yaml").write_text(manifest, encoding="utf-8")

                result = run_common_script(
                    "init_session.py", str(challenge), "--category", category
                )

                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)["status"], "error")
                self.assertFalse((event / "runs").exists())

    def test_legacy_intake_fields_use_prompt_size_and_control_limits(self) -> None:
        cases = (
            ("web", {"target": "https://" + ("x" * MAX_FIELD_BYTES)}),
            ("rev", {"binary": "chall\x00outside"}),
            ("web", {"flag_pattern": "x" * (MAX_FIELD_BYTES + 1)}),
        )
        for category, legacy in cases:
            with self.subTest(category=category, field=next(iter(legacy))):
                with self.assertRaises(IntakeError):
                    resolve_intake(category, IntakeRequest(), legacy)

    def test_request_json_rejects_invalid_shape_size_and_mixed_flags(self) -> None:
        cases = (
            (json.dumps({"unknown": "value"}), ()),
            (json.dumps({"target": 31337}), ()),
            (json.dumps(["not", "an", "object"]), ()),
            (json.dumps({"statement": "x" * (1024 * 1024)}), ()),
            (json.dumps({"statement": "ok"}), ("--statement", "mixed")),
        )
        for index, (payload, extra) in enumerate(cases):
            with self.subTest(index=index):
                challenge = Path(self.temp.name) / f"invalid-json-{index}"
                challenge.mkdir()
                result = run_common_script(
                    "init_session.py",
                    str(challenge),
                    "--category",
                    "web",
                    "--request-json",
                    "-",
                    *extra,
                    input=payload,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stderr, "")
                self.assertEqual(len(result.stdout.splitlines()), 1)
                self.assertEqual(json.loads(result.stdout)["status"], "error")
                self.assertFalse((challenge.parent / "runs").exists())

    def test_request_json_path_is_bounded_regular_and_nofollow(self) -> None:
        challenge = Path(self.temp.name) / "json-path-web"
        challenge.mkdir()
        request_file = Path(self.temp.name) / "request.json"
        request_file.write_text(
            json.dumps({"target": "https://box.example/"}), encoding="utf-8"
        )
        success = run_common_script(
            "init_session.py",
            str(challenge),
            "--category",
            "web",
            "--request-json",
            str(request_file),
        )
        self.assertEqual(success.returncode, 0, success.stdout)

        link = Path(self.temp.name) / "request-link.json"
        link.symlink_to(request_file)
        rejected = run_common_script(
            "init_session.py",
            str(challenge),
            "--category",
            "web",
            "--request-json",
            str(link),
        )
        self.assertEqual(rejected.returncode, 2)

    def test_target_normalization_and_category_rejections(self) -> None:
        pwn_targets = {
            "nc pwn.example 31337": ("pwn.example", 31337),
            "pwn.example:31337": ("pwn.example", 31337),
            "tcp://pwn.example:31337": ("pwn.example", 31337),
        }
        for index, (target, expected) in enumerate(pwn_targets.items()):
            with self.subTest(target=target):
                challenge = Path(self.temp.name) / f"pwn-{index}"
                challenge.mkdir()
                row = create_session(challenge, "pwn", intake=IntakeRequest(target=target))
                stored = json.loads(
                    (row["workspace"] / "challenge-request.json").read_text(encoding="utf-8")
                )
                self.assertEqual(
                    (stored["normalized"]["host"], stored["normalized"]["port"]), expected
                )
                self.assertEqual(stored["normalized"]["target"], "tcp://pwn.example:31337")

        ipv6 = Path(self.temp.name) / "pwn-ipv6"
        ipv6.mkdir()
        ipv6_row = create_session(
            ipv6,
            "pwn",
            intake=IntakeRequest(target="tcp://[2001:db8::1]:31337"),
        )
        ipv6_manifest = (
            ipv6_row["workspace"] / "challenge.resolved.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn('host: "[2001:db8::1]"', ipv6_manifest)
        ipv6_stored = json.loads(
            (ipv6_row["workspace"] / "challenge-request.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            ipv6_stored["normalized"]["target"],
            "tcp://[2001:db8::1]:31337",
        )

        invalid = {
            "web": (
                "https://user:pass@box.example/",
                "https://box.example/path#fragment",
                "https://box.example/path#",
                "ftp://box.example/file",
            ),
            "pwn": (
                "tcp://pwn.example:31337/path",
                "tcp://pwn.example:31337?",
                "tcp://pwn.example:31337#",
                "pwn.example:0",
                "pwn.example:65536",
            ),
            "rev": ("https://box.example/", "pwn.example:31337"),
        }
        for category, targets in invalid.items():
            for target in targets:
                with self.subTest(category=category, target=target):
                    challenge = Path(self.temp.name) / f"bad-{category}-{abs(hash(target))}"
                    challenge.mkdir()
                    with self.assertRaises(ValueError):
                        create_session(
                            challenge, category, intake=IntakeRequest(target=target)
                        )

    def test_prompt_and_legacy_conflicts_leave_no_usable_session(self) -> None:
        cases = (
            (
                "web",
                "id: conflict\norigin: https://legacy.example\nstart_url: https://legacy.example/\n",
                IntakeRequest(target="https://prompt.example/"),
            ),
            (
                "rev",
                "id: conflict\nbinary: legacy\n",
                IntakeRequest(binary="prompt"),
            ),
            (
                "web",
                "id: conflict\ntarget: https://legacy.example/one\n",
                IntakeRequest(target="https://legacy.example/two"),
            ),
            (
                "rev",
                "id: conflict\nbinary: prompt\nauthorized: false\n",
                IntakeRequest(binary="prompt"),
            ),
        )
        for index, (category, manifest, request) in enumerate(cases):
            with self.subTest(category=category):
                event = Path(self.temp.name) / f"conflict-{index}"
                challenge = event / "challenge"
                challenge.mkdir(parents=True)
                (challenge / "challenge.yaml").write_text(manifest, encoding="utf-8")
                (challenge / "legacy").write_bytes(b"legacy")
                (challenge / "prompt").write_bytes(b"prompt")
                result = run_common_script(
                    "init_session.py",
                    str(challenge),
                    "--category",
                    category,
                    "--statement",
                    request.statement,
                    *(("--target", request.target) if request.target is not None else ()),
                    *(("--binary", request.binary) if request.binary is not None else ()),
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)["status"], "error")
                sessions = (
                    list((event / "runs").glob("**/sessions/*"))
                    if (event / "runs").exists()
                    else []
                )
                self.assertEqual(sessions, [])

    def test_selected_binary_is_contained_regular_and_not_size_limited(self) -> None:
        event = Path(self.temp.name) / "binary-event"
        challenge = event / "chall"
        challenge.mkdir(parents=True)
        binary = challenge / "chall"
        with binary.open("wb") as stream:
            stream.truncate(MAX_ARTIFACT_BYTES + 1)

        row = create_session(
            challenge, "rev", intake=IntakeRequest(statement="reverse it", binary="chall")
        )
        stored = json.loads(
            (row["workspace"] / "challenge-request.json").read_text(encoding="utf-8")
        )
        self.assertEqual(stored["binary"], "chall")
        self.assertIn("binary: chall", (row["workspace"] / "challenge.resolved.yaml").read_text())

    def test_unsafe_binary_values_fail_without_blocking_or_reading_outside(self) -> None:
        event = Path(self.temp.name) / "unsafe-binary-event"
        challenge = event / "chall"
        challenge.mkdir(parents=True)
        outside = event / "outside"
        outside.write_bytes(b"outside")
        (challenge / "directory").mkdir()
        os.mkfifo(challenge / "fifo")
        (challenge / "link").symlink_to(outside)
        cases = (str(outside), "../outside", "directory", "fifo", "link")

        for value in cases:
            with self.subTest(binary=value):
                try:
                    result = run_common_script(
                        "init_session.py",
                        str(challenge),
                        "--category",
                        "rev",
                        "--binary",
                        value,
                        timeout=1,
                    )
                except subprocess.TimeoutExpired:
                    self.fail(f"binary validation blocked for {value!r}")
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stdout)["status"], "error")
        self.assertEqual(outside.read_bytes(), b"outside")
        self.assertFalse((event / "runs").exists())

    def test_combined_fingerprint_uses_canonical_intake_and_keeps_file_digest(self) -> None:
        event = Path(self.temp.name) / "fingerprint-event"
        challenge = event / "empty-web"
        challenge.mkdir(parents=True)
        request = IntakeRequest(
            statement="same statement", target="https://box.example:443/start?q=1"
        )

        same_a = create_session(challenge, "web", intake=request)
        same_b = create_session(
            challenge,
            "web",
            intake=IntakeRequest(
                statement=request.statement,
                target="https://box.example/start?q=1",
            ),
        )
        other = create_session(
            challenge,
            "web",
            intake=IntakeRequest(
                statement=request.statement,
                target="https://other.example/",
            ),
        )
        self.assertEqual(same_a["fingerprint"], same_b["fingerprint"])
        self.assertNotEqual(same_a["fingerprint"], other["fingerprint"])
        self.assertEqual(same_a["workspace"].parents[1], same_b["workspace"].parents[1])
        self.assertNotEqual(same_a["workspace"].parents[1], other["workspace"].parents[1])
        self.assertEqual(same_a["file_fingerprint"], same_b["file_fingerprint"])
        stored = json.loads(
            (same_a["workspace"] / "challenge-request.json").read_text(encoding="utf-8")
        )
        self.assertEqual(stored["file_fingerprint"], same_a["file_fingerprint"])
        self.assertEqual(stored["fingerprint"], same_a["fingerprint"])

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

    def test_publisher_rejects_oversized_evidence_before_creating_shared_copy(self) -> None:
        row = create_session(self.challenge, "web")
        evidence = row["workspace"] / "artifacts" / "oversized.bin"
        with evidence.open("wb") as stream:
            stream.truncate(MAX_ARTIFACT_BYTES + 1)

        with self.assertRaisesRegex(InvalidInput, "exceeds"):
            publish_finding(row["workspace"], "endpoint", evidence, "oversized evidence")

        destination = row["workspace"].parents[1] / "shared" / "findings" / row["session_id"]
        self.assertFalse(destination.exists())

    def test_publish_cli_rejects_fifo_evidence_without_blocking(self) -> None:
        row = create_session(self.challenge, "web")
        evidence = row["workspace"] / "artifacts" / "stream"
        os.mkfifo(evidence)

        try:
            result = run_common_script(
                "publish_finding.py",
                "--workspace", str(row["workspace"]),
                "--kind", "endpoint",
                "--evidence", str(evidence),
                "--summary", "fifo evidence",
                timeout=1,
            )
        except subprocess.TimeoutExpired:
            self.fail("publishing blocked on FIFO evidence")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "error")

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

    def test_verifier_rejects_fifo_capture_artifacts_without_blocking(self) -> None:
        for artifact in ("output", "sent", "attestation"):
            with self.subTest(artifact=artifact):
                row = create_session(self.challenge, "web")
                output, sent, attestation = self.make_capture(row, "capture-one", b"FLAG{fifo}\n")
                fifo = {"output": output, "sent": sent, "attestation": attestation}[artifact]
                fifo.unlink()
                os.mkfifo(fifo)

                try:
                    result = run_common_script(
                        "verify_flag.py",
                        "--workspace", str(row["workspace"]),
                        "--output", str(output),
                        "--sent", str(sent),
                        "--attestation", str(attestation),
                        "--pattern", r"FLAG\{[^}\r\n]+\}",
                        timeout=1,
                    )
                except subprocess.TimeoutExpired:
                    self.fail(f"verification blocked on FIFO {artifact}")

                self.assertEqual(result.returncode, 2)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["status"], "candidate_only")
                self.assertEqual(payload["reason"], "invalid_capture_attestation")

    def test_verifier_rejects_more_than_sixteen_capture_paths(self) -> None:
        row = create_session(self.challenge, "web")
        output, sent, attestation = self.make_capture(row, "capture-one", b"FLAG{too_many}\n")

        result = verify_outputs(
            [output] * 17,
            [sent],
            (rb"FLAG\{[^}\r\n]+\}",),
            strict=False,
            workspace=row["workspace"],
            attestations=[attestation] * 17,
        )

        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(result["reason"], "verification_request_exceeds_budget")

    def test_verifier_rejects_capture_bytes_above_aggregate_budget(self) -> None:
        row = create_session(self.challenge, "web")
        first = self.make_capture(row, "capture-one", b"FLAG{first}\n")
        second = self.make_capture(row, "capture-two", b"FLAG{second}\n")
        artifacts = (*first, *second)
        budget = sum(path.stat().st_size for path in artifacts) - 1

        with patch("ctf_workspace.MAX_VERIFICATION_BYTES", budget, create=True):
            result = verify_outputs(
                [first[0], second[0]],
                [first[1], second[1]],
                (rb"FLAG\{[^}\r\n]+\}",),
                strict=False,
                workspace=row["workspace"],
                attestations=[first[2], second[2]],
            )

        self.assertEqual(result["status"], "candidate_only")
        self.assertEqual(result["reason"], "verification_request_exceeds_budget")

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

    def test_initializer_skips_fifo_shared_finding_record_without_blocking(self) -> None:
        row = create_session(self.challenge, "web")
        evidence = row["workspace"] / "artifacts" / "response.txt"
        evidence.write_bytes(b"original")
        finding = publish_finding(row["workspace"], "endpoint", evidence, "verified endpoint")
        finding.unlink()
        os.mkfifo(finding)

        try:
            result = run_common_script(
                "init_session.py", str(self.challenge), "--category", "web", timeout=1
            )
        except subprocess.TimeoutExpired:
            self.fail("finding indexing blocked on FIFO record")

        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["skipped_findings"]["reasons"], {"malformed_record": 1})

    def test_initializer_skips_fifo_shared_finding_evidence_without_blocking(self) -> None:
        row = create_session(self.challenge, "web")
        evidence = row["workspace"] / "artifacts" / "response.txt"
        evidence.write_bytes(b"original")
        finding = publish_finding(row["workspace"], "endpoint", evidence, "verified endpoint")
        payload = json.loads(finding.read_text(encoding="utf-8"))
        shared_evidence = Path(payload["evidence"])
        shared_evidence.unlink()
        os.mkfifo(shared_evidence)

        try:
            result = run_common_script(
                "init_session.py", str(self.challenge), "--category", "web", timeout=1
            )
        except subprocess.TimeoutExpired:
            self.fail("finding indexing blocked on FIFO evidence")

        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["skipped_findings"]["reasons"], {"evidence_missing": 1})

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
