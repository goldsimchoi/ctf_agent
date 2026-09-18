# Zero-config CTF Intake Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let users give a category skill one dedicated problem directory, the event's free-form problem statement, and an optional address while Codex creates a contained, target-bound session without user-authored YAML.

**Architecture:** Codex interprets free-form prose, then sends a small normalized JSON request over stdin to a deterministic common initializer. A focused `ctf_intake.py` module validates category-specific target data, merges compatible legacy manifest fields, renders the session-local manifest, and contributes canonical intake bytes to the run fingerprint; existing category adapters continue trusting only that resolved manifest. Pwn, web, and rev skills expose the workflow independently, and an idempotent installer registers all three as user-scoped Codex skills.

**Tech Stack:** Python 3.12 standard library (`argparse`, `dataclasses`, `hashlib`, `json`, `urllib.parse`), existing no-follow workspace helpers, Bash, `unittest`, Codex `SKILL.md` instructions.

**Spec:** `docs/superpowers/specs/2026-09-19-zero-config-ctf-intake-design.md`

## Global Constraints

- A challenge is one dedicated directory below `/home/normalone/CTF`; flat `/home/normalone/CTF/<problem>/` and event-organized layouts are both supported, but `/home/normalone/CTF` itself is not an input challenge.
- The challenge directory is read-only from the intake workflow; generated configuration exists only in the owning session.
- Free-form statements are at most 256 KiB; target, binary, and flag-pattern values are at most 4 KiB each.
- The normal agent transport is exactly one bounded JSON object on stdin via `--request-json -`; statement text never appears in a shell command.
- Web targets bind one exact HTTP(S) origin, pwn targets bind one exact TCP tuple, and rev rejects network targets.
- An existing manifest and prompt intake may fill one another's missing fields, but conflicting targets, binaries, categories, or authorization policy fail closed.
- Empty directories are valid black-box web inputs.
- Existing callers without intake arguments and all current capture/finding/verification security properties remain compatible.
- Implementation follows red-green TDD and every task ends in a focused commit.

---

### Task 1: Deterministic common intake and fingerprint contract

**Files:**
- Create: `ctf-common/scripts/ctf_intake.py`
- Modify: `ctf-common/scripts/ctf_workspace.py`
- Modify: `ctf-common/scripts/init_session.py`
- Modify: `ctf-common/references/workspace.md`
- Test: `tests/test_ctf_common.py`

**Interfaces:**
- Produces: `IntakeRequest(statement: str = "", target: str | None = None, binary: str | None = None, flag_pattern: str | None = None)`.
- Produces: `read_request_json(stream: BinaryIO) -> IntakeRequest` with a bounded read and exact-key/type validation.
- Produces: `resolve_intake(category: str, request: IntakeRequest, legacy: Mapping[str, str]) -> dict[str, Any]` containing `source`, `target_status`, `manifest`, and lossless request fields.
- Produces: `render_resolved_manifest(slug: str, category: str, intake: Mapping[str, Any]) -> str`.
- Changes: `create_session(..., *, intake: IntakeRequest | None = None) -> dict[str, Any]`; all existing positional parameters retain their meanings.
- Changes: `init_session.py` accepts `--request-json {-|PATH}` or individual intake flags, rejects mixing the two forms, and emits an `intake` object in its existing JSON result.
- Consumed by: Tasks 2–4 category entry points and adapters.

- [ ] **Step 1: Add common red tests for flat and fileless intake**

Add imports for `IntakeRequest` and tests that snapshot the challenge directory before initialization, initialize a flat no-YAML pwn/rev directory and an empty web directory, then assert the input snapshot is unchanged. The web assertion must bind the supplied path to an exact origin:

```python
request = IntakeRequest(
    statement="관리자 페이지에서 플래그를 찾아라\nhttps://box.example:8443/start?q=1",
    target="https://box.example:8443/start?q=1",
)
row = create_session(empty_challenge, "web", intake=request)
stored = json.loads((row["workspace"] / "challenge-request.json").read_text())
resolved = (row["workspace"] / "challenge.resolved.yaml").read_text()
self.assertEqual(stored["statement"], request.statement)
self.assertEqual(stored["normalized"]["origin"], "https://box.example:8443")
self.assertIn("origin: https://box.example:8443", resolved)
self.assertEqual(row["intake"]["target_status"], "bound")
```

Create a managed-root fixture containing `.tools/env.sh` and `.venv/pyvenv.cfg`
and assert that passing that root itself as the challenge fails, while a direct
child problem directory succeeds and places `runs/` beside that child.

- [ ] **Step 2: Add common red tests for transport, normalization, and conflicts**

Exercise `init_session.py --request-json -` through `subprocess.run(input=...)` with multiline Korean/English prose containing backticks, `$()`, quotes, and template syntax. Assert one JSON document is returned, no marker command runs, unknown/non-string keys and payloads beyond the bound exit 2, and individual flags cannot be mixed with JSON. Add table-driven cases for:

```python
pwn_targets = {
    "nc pwn.example 31337": ("pwn.example", 31337),
    "pwn.example:31337": ("pwn.example", 31337),
    "tcp://pwn.example:31337": ("pwn.example", 31337),
}
```

Also assert web rejects userinfo/fragments/non-HTTP schemes, pwn rejects paths and out-of-range ports, rev rejects every network target, and prompt/legacy target or binary conflicts exit 2 without leaving a usable session.

- [ ] **Step 3: Add common red tests for safe binary selection and fingerprints**

Create one contained regular binary and assert `binary="chall"` binds it. Assert absolute, `..`, directory, FIFO, and symlink values fail without blocking or reading outside the challenge. Verify file-only digest plus canonical intake behavior:

```python
same_a = create_session(challenge, "web", intake=request)
same_b = create_session(challenge, "web", intake=request)
other = create_session(challenge, "web", intake=IntakeRequest(
    statement=request.statement,
    target="https://other.example/",
))
self.assertEqual(same_a["fingerprint"], same_b["fingerprint"])
self.assertNotEqual(same_a["fingerprint"], other["fingerprint"])
self.assertEqual(same_a["workspace"].parents[1], same_b["workspace"].parents[1])
```

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_ctf_common -v`

Expected: new tests fail because the intake module, keyword parameter, stored request, and CLI option do not exist.

- [ ] **Step 4: Implement the pure intake module**

Create `ctf_intake.py` with `IntakeError`, the frozen `IntakeRequest` dataclass, bounded JSON loading, field-length/control-character validation, and category normalizers. Use `urllib.parse.urlsplit`/`urlunsplit` for web and TCP parsing; reject credentials and fragments; normalize default web ports; preserve the web query in `start_url`; bracket IPv6 in rendered origins/tuples. Keep full statement text only in JSON, not YAML.

The normalized mapping must have stable JSON-compatible values and an effective scalar manifest such as:

```python
{
    "source": "prompt",
    "target_status": "bound",
    "statement": request.statement,
    "target_input": request.target,
    "binary": request.binary,
    "flag_pattern": request.flag_pattern,
    "normalized": {"origin": origin, "start_url": start_url},
    "manifest": {
        "category": "web",
        "authorized": "true",
        "network_access": "agent_allowed",
        "origin": origin,
        "start_url": start_url,
        "mode": legacy.get("mode", "race"),
    },
}
```

Serialize manifest scalars with one YAML-safe quoting function; never concatenate unescaped prompt text into YAML.

- [ ] **Step 5: Integrate intake with safe workspace creation**

Extend `create_session` with the keyword-only `intake`. Safely parse the legacy manifest, validate a selected binary through descriptor-relative `O_NOFOLLOW` traversal without imposing the 4 MiB verification-artifact limit, and calculate:

```python
file_fingerprint = challenge_fingerprint(challenge)
intake_bytes = json.dumps(fingerprint_fields, ensure_ascii=False,
                          sort_keys=True, separators=(",", ":")).encode()
fingerprint = hashlib.sha256(bytes.fromhex(file_fingerprint) + intake_bytes).hexdigest()
```

Write `challenge-request.json`, rendered `challenge.resolved.yaml`, `session.json`, state, and notes only after a session directory is allocated. Store both `file_fingerprint` and combined `fingerprint`. Return absolute request/manifest paths and target status. On any error, remove the partial session with the existing cleanup path.

- [ ] **Step 6: Implement bounded CLI JSON input**

Extend `init_session.py` with a mutually exclusive input group. For `--request-json -`, pass `sys.stdin.buffer` to `read_request_json`; for a path, open one no-follow regular file and enforce the same read bound. Construct `IntakeRequest` from individual flags only when JSON is absent. Catch `IntakeError` together with existing input/collision errors and preserve the one-JSON-document exit-2 contract.

- [ ] **Step 7: Run focused and regression tests**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_ctf_common -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Expected: all common tests and the pre-existing full suite pass.

- [ ] **Step 8: Document and commit the common contract**

Update `ctf-common/references/workspace.md` with stdin JSON schema, target-status meanings, flat input layout, empty web input, immutable request record, and combined fingerprint. Commit:

```bash
git add ctf-common tests/test_ctf_common.py
git commit -m "feat: add zero-config CTF session intake"
```

---

### Task 2: Pwn free-form intake workflow

**Files:**
- Modify: `pwn-agent/scripts/init_run.py`
- Modify: `pwn-agent/SKILL.md`
- Modify: `pwn-agent/references/workflow.md`
- Modify: `pwn-agent/references/safety.md`
- Test: `tests/test_pwn_agent_scripts.py`

**Interfaces:**
- Consumes: Task 1 `init_session.py --request-json -` and generated scalar fields `protocol`, `host`, `port`, `binary`, `authorized`, and `network_access`.
- Produces: `init_run.py` forwarding stdin JSON unchanged to the common pwn initializer while retaining all legacy root/run flags.
- Produces: pwn skill instructions that extract one TCP candidate and one clear local binary candidate from natural-language context without requiring labels or probing candidates.

- [ ] **Step 1: Add failing pwn wrapper and capture tests**

Extend the test subprocess helper to accept `input`. Initialize a no-YAML challenge through:

```python
payload = json.dumps({
    "statement": "The service is available with nc pwn.example 31337",
    "target": "nc pwn.example 31337",
    "binary": "chall",
})
result = run_script(INIT_RUN, challenge, "--request-json", "-", input=payload)
```

Assert the wrapper returns one JSON object, preserves the exact statement, writes the expected TCP manifest, and `publish_capture.py` accepts only `tcp://pwn.example:31337` plus the exact bound local path. Add a malformed/missing stdin case and ensure legacy wrapper flags still pass.

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_pwn_agent_scripts -v`

Expected: new calls fail because `init_run.py` does not accept or forward request JSON.

- [ ] **Step 2: Implement pwn request forwarding**

Add `--request-json`, `--statement`, `--target`, `--binary`, and `--flag-pattern` options matching the common CLI. Reject mixing JSON and individual fields before starting the child. When `--request-json -` is used, read at most the common maximum plus one byte from `sys.stdin.buffer`, reject overflow, and pass the unchanged bytes through `subprocess.run(input=...)`; otherwise forward arguments exactly as separate argv elements.

- [ ] **Step 3: Rewrite pwn start instructions around pasted event text**

Make `pwn-agent/SKILL.md` lead with: identify the dedicated problem folder, preserve the entire event statement, recognize `nc host port`/`host:port`/`tcp://host:port`, read-only triage candidate ELF/PE/scripts, and send normalized JSON over stdin. State that no YAML or labeled fields are required, no address means local-only, multiple plausible tuples require one question, and target candidates are never probed to choose among them. Retain the existing race-first capture and verification finish contract.

- [ ] **Step 4: Run pwn tests and commit**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_pwn_agent_scripts tests.test_pwn_agent_layout -v
```

Expected: all pwn tests pass.

Commit:

```bash
git add pwn-agent tests/test_pwn_agent_scripts.py
git commit -m "feat: accept free-form pwn challenge intake"
```

---

### Task 3: Fileless black-box web workflow

**Files:**
- Modify: `web-agent/SKILL.md`
- Modify: `web-agent/references/workflow.md`
- Modify: `web-agent/references/safety.md`
- Modify: `web-agent/references/state-and-verification.md`
- Test: `tests/test_web_agent.py`

**Interfaces:**
- Consumes: Task 1 generated `origin`, `start_url`, `authorized`, and `network_access` fields.
- Produces: a tested web path from an empty input directory to isolated web state and an exact-origin request capture.
- Preserves: existing `manifest_origin`, redirect checks, bounded response handling, sent history, capture provenance, and verifier behavior.

- [ ] **Step 1: Add a failing end-to-end black-box web test**

Create an empty challenge directory and a local test HTTP server. Initialize it with `IntakeRequest(statement=..., target=server_url + "/entry?x=1")`, assert no file was added to the challenge, run `init_web_state`, then call `assets/request.py` against the supplied same-origin start URL. Verify request/response/capture files exist only below the returned session and `verify_web_flag.py` can verify a non-echoed response candidate. Add a second intake with another port/origin and assert its run root differs.

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_web_agent.WebAgentTests.test_fileless_black_box_intake_is_isolated -v`

Expected: FAIL until Task 1's generated manifest is consumed correctly and the test fixture uses it.

- [ ] **Step 2: Add web target-boundary regression tests**

From a generated manifest rather than a hand-written YAML fixture, assert the adapter rejects a scheme/host/port change before traffic, rejects a redirect outside the origin, and accepts other paths under the same origin. Assert an absent web target returns `needs_selection` and `request.py` performs no traffic.

- [ ] **Step 3: Update web instructions for unstructured, fileless input**

Make the skill start sequence explicitly accept an empty problem directory and pasted event prose. Codex selects exactly one HTTP(S) target from the user's current request, passes full prose plus normalized target through stdin JSON, begins at `start_url`, and uses the manifest origin for every subsequent request. Event-page/docs URLs that are not the live challenge must not be selected; when two origins remain plausible, ask rather than probing both.

- [ ] **Step 4: Run web tests and commit**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_web_agent -v
```

Expected: all web tests pass.

Commit:

```bash
git add web-agent tests/test_web_agent.py
git commit -m "feat: support fileless black-box web intake"
```

---

### Task 4: Reversing free-form intake workflow

**Files:**
- Modify: `rev-agent/SKILL.md`
- Modify: `rev-agent/references/workflow.md`
- Modify: `rev-agent/references/safety.md`
- Modify: `rev-agent/references/state-and-verification.md`
- Test: `tests/test_rev_agent.py`

**Interfaces:**
- Consumes: Task 1 challenge-relative `binary` binding and `target_status`.
- Produces: a no-YAML rev flow whose generated manifest is accepted by the existing oracle.
- Preserves: clue/hypothesis ledgers, raw oracle evidence, capture attestation, state lock, and WAL recovery.

- [ ] **Step 1: Add a failing generated-manifest oracle test**

Create a dedicated no-YAML challenge with one executable test oracle, initialize with:

```python
row = create_session(
    challenge,
    "rev",
    intake=IntakeRequest(
        statement="Find the correct serial and return H4C{...}",
        binary="chall",
        flag_pattern=r"H4C\{[^}\r\n]+\}",
    ),
)
```

Initialize rev state and run `assets/solver.py` against that exact binary. Assert raw sent/output evidence and capture attestation are created. Assert a foreign file, symlink, or network target is rejected before execution. Add a no-binary case returning `needs_selection` without creating oracle output.

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_rev_agent.RevAgentTests.test_yaml_free_intake_binds_oracle -v`

Expected: FAIL until the Task 1 manifest binding is used by the existing oracle.

- [ ] **Step 2: Update rev instructions for natural-language problem statements**

Make the skill perform cheap read-only magic/permission/format triage before initialization, choose a single clear challenge-relative executable, and pass the exact pasted statement plus selection through stdin JSON. State that archives are unpacked only inside session artifacts, extracted files retain archive/digest evidence, and an unclear executable choice produces one precise question instead of guessing. Keep network targets forbidden.

- [ ] **Step 3: Run rev tests and commit**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_rev_agent -v
```

Expected: all rev tests pass.

Commit:

```bash
git add rev-agent tests/test_rev_agent.py
git commit -m "feat: accept free-form reversing intake"
```

---

### Task 5: Skill registration, user documentation, and final verification

**Files:**
- Create: `tools/install-ctf-skills.sh`
- Modify: `tools/check-ctf-tools.sh`
- Modify: `README.md`
- Modify: `tests/test_tool_scripts.py`

**Interfaces:**
- Produces: `bash tools/install-ctf-skills.sh` registering `pwn-agent`, `web-agent`, and `rev-agent` beneath `${CTF_SKILLS_HOME:-$HOME/.agents/skills}` as symlinks to the current repository.
- Produces: checker `skills` records for all three user-visible skills without changing unrelated tool probes.
- Refuses: replacing a regular file/directory or a symlink to another source; rerunning against identical links is idempotent.

- [ ] **Step 1: Add failing skill-installer tests**

Run the installer with `CTF_SKILLS_HOME` set to a temporary directory. Assert all three links resolve to the repository skill directories and each target contains `SKILL.md`. Rerun and assert success with unchanged inode/link text. Precreate a regular collision and an unrelated symlink in separate subtests; assert nonzero exit and no replacement. Add the installer to the Bash syntax test and verify the checker emits structured availability for each skill.

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_tool_scripts -v`

Expected: new tests fail because the installer and checker skill records do not exist.

- [ ] **Step 2: Implement the idempotent user-skill installer**

Resolve the repository root from `${BASH_SOURCE[0]}` and validate all three source `SKILL.md` files before creating anything. Create the destination root, then use `ln -s` only for absent destinations. For an existing symlink, compare `readlink -f` with the intended source; accept an exact match and reject every other target. Print one JSON result with source, destination, and per-skill status so tests and users can verify installation.

- [ ] **Step 3: Extend the capability checker**

Add a top-level `skills` object with `pwn-agent`, `web-agent`, and `rev-agent`; each record reports available only when the configured link resolves to a directory containing a regular `SKILL.md`. Keep one valid JSON document even when all links are missing. Count these records in the summary or add a separate `skill_summary`, and update tests to assert the chosen stable schema.

- [ ] **Step 4: Rewrite the top-level quick start**

Document only the user-facing sequence:

```bash
mkdir -p /home/normalone/CTF/babypwn
cp ~/Downloads/chall /home/normalone/CTF/babypwn/
bash tools/install-ctf-skills.sh
source /home/normalone/CTF/.tools/env.sh
codex -C /home/normalone/CTF
```

Show `$pwn-agent`, `$web-agent`, and `$rev-agent` prompts containing pasted real event prose, with an empty-directory black-box web example. State that `/skills` confirms discovery, a fresh Codex session may be needed, the user never writes YAML, and generated work lives under sibling `runs/` rather than the input directory.

- [ ] **Step 5: Run installer in the real user scope and verify links**

From the completed worktree run:

```bash
bash tools/install-ctf-skills.sh
readlink -f /home/normalone/.agents/skills/pwn-agent
readlink -f /home/normalone/.agents/skills/web-agent
readlink -f /home/normalone/.agents/skills/rev-agent
```

Expected: all three resolve to this worktree's agent directories and contain their committed `SKILL.md`. Do not replace unrelated existing destinations.

- [ ] **Step 6: Run complete verification**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
bash -n tools/install-ctf-tools.sh tools/check-ctf-tools.sh tools/install-ctf-skills.sh
git diff --check 80ebeb5..HEAD
bash tools/check-ctf-tools.sh
```

Expected: the full suite is green, shell syntax and diff checks exit 0, the checker emits one JSON document, and all three skill entries are available. Existing optional host-tool degradation remains explicit rather than failing skill registration.

- [ ] **Step 7: Commit user activation and documentation**

```bash
git add README.md tools tests/test_tool_scripts.py
git commit -m "feat: install zero-config CTF skills"
```
