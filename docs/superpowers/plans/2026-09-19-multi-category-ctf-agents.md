# Multi-category CTF Agents Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adapt the existing pwn skill and add independent web and reversing skills with collision-free, race-first workspaces for concurrent CTF sessions.

**Architecture:** A shared `ctf-common` command layer owns deterministic challenge fingerprints, unique session creation, immutable cross-session findings, attempt budgets, and race/strict flag verification. `pwn-agent`, `web-agent`, and `rev-agent` remain separate Codex skills and own only category-specific instructions, templates, and state helpers.

**Tech Stack:** Python 3.12 managed by `uv`, Python standard library, unittest, Bash, Codex skills, GDB MCP, idalib MCP, pwntools, requests/httpx, Playwright, radare2, angr, ffuf, sqlmap, nmap, nuclei.

**Spec:** `docs/superpowers/specs/2026-09-19-multi-category-ctf-agents-design.md`

## Global Constraints

- Preserve the existing `pwn-agent/` directory and adapt it in place.
- Keep `pwn-agent/`, `web-agent/`, and `rev-agent/` as separate skill directories.
- Store problem inputs under `/home/normalone/CTF/<event>/challenges/<challenge>/` and never modify them.
- Store runs under `<event>/runs/<category>/<slug>-<fingerprint12>/sessions/<session-id>/`.
- Share cross-session facts only through immutable files below `shared/findings/<session-id>/`.
- Default to race mode; strict two-run reproduction is opt-in.
- Use `python3` or `/home/normalone/CTF/.venv/bin/python`, never bare `python`.
- Use the notebook MCP names `gdb` and `idalib`; remove Windows/WSL paths.
- Do not access remote endpoints without `authorized: true` and `network_access: agent_allowed`.

---

### Task 1: Collision-free common workspace and verification

**Files:**
- Create: `ctf-common/scripts/ctf_workspace.py`
- Create: `ctf-common/scripts/init_session.py`
- Create: `ctf-common/scripts/publish_finding.py`
- Create: `ctf-common/scripts/record_attempt.py`
- Create: `ctf-common/scripts/verify_flag.py`
- Create: `ctf-common/references/workspace.md`
- Create: `tests/test_ctf_common.py`

**Interfaces:**
- Consumes: an event challenge directory and category `pwn`, `web`, or `rev`.
- Produces: `create_session(challenge: Path, category: str, event_root: Path | None, session_id: str | None) -> dict`.
- Produces: `publish_finding(workspace: Path, kind: str, evidence: Path, summary: str) -> Path`.
- Produces: `record_attempt(workspace: Path, signature: str, progress: str | None) -> dict`.
- Produces: `verify_outputs(outputs: list[Path], sent: list[Path], patterns: tuple[bytes, ...], strict: bool) -> dict`.

- [ ] **Step 1: Write failing common tests**

Add tests that create two problems in one event, start 16 concurrent sessions
for one problem, start all three categories for the same problem, publish
findings from two sessions, reject `../` IDs, reject an explicit duplicate ID,
enforce two no-progress attempts, and distinguish race from strict verification.

```python
def test_concurrent_sessions_are_unique(self):
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(lambda _: create_session(self.challenge, "web"), range(16)))
    paths = {row["workspace"] for row in rows}
    self.assertEqual(len(paths), 16)
```

- [ ] **Step 2: Run the common tests and confirm red state**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_ctf_common -v`

Expected: import failure for `ctf_workspace` because the common scripts do not exist.

- [ ] **Step 3: Implement the workspace module**

Implement safe slugs, a sorted SHA-256 content fingerprint, event-root
validation, atomic session-directory creation, atomic JSON writes, manifest
scalar parsing, immutable finding creation, and per-session state updates.

```python
def new_session_id(category: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return f"{category}-{stamp}-{os.getpid()}-{secrets.token_hex(4)}"
```

`state.json` starts with `attempts: []`, `no_progress: 0`,
`max_no_progress: 2`, `started_at`, and the manifest wall-time budget.
Duplicate normalized attempt signatures fail unless `progress` names a new fact,
primitive, endpoint, clue, or flag candidate.

- [ ] **Step 4: Implement thin JSON CLI entry points**

Each CLI imports from `ctf_workspace.py`, prints one JSON object, and exits `2`
for invalid input/collision/unverified results and `3` for exhausted budgets.
`verify_flag.py` accepts repeatable `--output`, repeatable `--sent`, repeatable
`--pattern`, and `--strict`.

- [ ] **Step 5: Run common tests**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_ctf_common -v`

Expected: all common tests pass.

- [ ] **Step 6: Commit common foundation**

```bash
git add ctf-common tests/test_ctf_common.py
git commit -m "feat: add collision-free CTF session core"
```

### Task 2: Adapt the existing pwn skill

**Files:**
- Modify: `pwn-agent/SKILL.md`
- Modify: `pwn-agent/agents/openai.yaml`
- Modify: `pwn-agent/assets/challenge.yaml`
- Modify: `pwn-agent/assets/exploit.py`
- Modify: `pwn-agent/references/runtime.md`
- Modify: `pwn-agent/references/workflow.md`
- Modify: `pwn-agent/references/state-and-verification.md`
- Modify: `pwn-agent/scripts/init_run.py`
- Modify: `pwn-agent/scripts/verify_flag.py`
- Modify: `tests/test_pwn_agent_scripts.py`
- Create: `tests/test_pwn_agent_layout.py`

**Interfaces:**
- Consumes: Task 1 CLIs at `../ctf-common/scripts/`.
- Produces: existing `$pwn-agent` trigger with GDB MCP, idalib MCP, native Ubuntu fallbacks, and race-first termination.

- [ ] **Step 1: Write failing pwn adaptation tests**

Assert that metadata declares `gdb` and `idalib`, no skill file contains the old
Windows user paths, command examples use `python3`, pwn initialization creates a
`runs/pwn/` session, and race verification accepts one non-echoed target output.

```python
def test_notebook_mcp_names(self):
    text = (ROOT / "pwn-agent/agents/openai.yaml").read_text()
    self.assertIn('value: "gdb"', text)
    self.assertIn('value: "idalib"', text)
```

- [ ] **Step 2: Run pwn tests and confirm red state**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_pwn_agent_layout -v`

Expected: failures for old MCP names, old paths, and old workspace layout.

- [ ] **Step 3: Adapt pwn instructions and metadata**

Keep one lead solver, but read shared findings before triage, call the common
initializer, use `gdb`/`idalib`, stop polishing after a source-attributable
remote flag, and reserve strict two-run verification for `mode: strict`.

- [ ] **Step 4: Convert old scripts to compatibility wrappers**

`pwn-agent/scripts/init_run.py` and `verify_flag.py` resolve
`../../ctf-common/scripts`, forward arguments, and preserve useful legacy flags
where unambiguous. Update the exploit template to Python 3 and the managed
pwntools environment.

- [ ] **Step 5: Run all pwn tests**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_pwn_agent_scripts tests.test_pwn_agent_layout -v`

Expected: all pwn tests pass.

- [ ] **Step 6: Commit pwn adaptation**

```bash
git add pwn-agent tests/test_pwn_agent_scripts.py tests/test_pwn_agent_layout.py
git commit -m "feat: adapt pwn agent to local race workflow"
```

### Task 3: Add the web skill

**Files:**
- Create: `web-agent/SKILL.md`
- Create: `web-agent/agents/openai.yaml`
- Create: `web-agent/assets/challenge.yaml`
- Create: `web-agent/assets/request.py`
- Create: `web-agent/references/safety.md`
- Create: `web-agent/references/runtime.md`
- Create: `web-agent/references/workflow.md`
- Create: `web-agent/references/state-and-verification.md`
- Create: `web-agent/scripts/init_web_state.py`
- Create: `web-agent/scripts/record_coverage.py`
- Create: `tests/test_web_agent.py`

**Interfaces:**
- Consumes: Task 1 workspace and attempt/finding/verification CLIs.
- Produces: `$web-agent`, an isolated cookie jar/browser profile, `coverage.json`, and raw HTTP evidence.

- [ ] **Step 1: Write failing web tests**

Test required metadata, source article attribution, unique cookie/profile paths
for two sessions, coverage records keyed by method/location/parameter/technique,
and atomic transitions among `untested`, `tested`, `promising`, `confirmed`, and
`discarded`.

```python
def test_sessions_do_not_share_browser_state(self):
    first = init_web_state(self.workspace_a)
    second = init_web_state(self.workspace_b)
    self.assertNotEqual(first["cookie_jar"], second["cookie_jar"])
    self.assertNotEqual(first["browser_profile"], second["browser_profile"])
```

- [ ] **Step 2: Run web tests and confirm red state**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_web_agent -v`

Expected: missing `web-agent` files.

- [ ] **Step 3: Implement web state helpers**

Create per-session `web/cookies.json`, `web/browser-profile/`,
`web/coverage.json`, `web/requests/`, and `web/responses/`. Coverage updates
must require the full tuple and an evidence path for `confirmed`.

- [ ] **Step 4: Write the web skill and request template**

The skill must inspect query/form/JSON/header/cookie/path/storage/WebSocket
inputs, preserve full response evidence, track capabilities separately from the
flag objective, reject repeated normalized requests, and restrict all traffic
to the authorized manifest origin. The request template uses
`requests.Session`, a session-owned cookie jar, explicit timeouts, and raw
request/response files.

- [ ] **Step 5: Run web tests**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_web_agent -v`

Expected: all web tests pass.

- [ ] **Step 6: Commit web skill**

```bash
git add web-agent tests/test_web_agent.py
git commit -m "feat: add stateful race-first web agent"
```

### Task 4: Add the reversing skill

**Files:**
- Create: `rev-agent/SKILL.md`
- Create: `rev-agent/agents/openai.yaml`
- Create: `rev-agent/assets/challenge.yaml`
- Create: `rev-agent/assets/solver.py`
- Create: `rev-agent/references/safety.md`
- Create: `rev-agent/references/runtime.md`
- Create: `rev-agent/references/workflow.md`
- Create: `rev-agent/references/state-and-verification.md`
- Create: `rev-agent/scripts/init_rev_state.py`
- Create: `rev-agent/scripts/record_clue.py`
- Create: `tests/test_rev_agent.py`

**Interfaces:**
- Consumes: Task 1 workspace and attempt/finding/verification CLIs.
- Produces: `$rev-agent`, `clues.json`, per-session IDA/GDB artifacts, and an executable solver/oracle workflow.

- [ ] **Step 1: Write failing reversing tests**

Test required metadata and article attribution, per-session IDA/GDB paths, clue
records with evidence/xrefs/functions/next action, hypothesis records with a
falsifying test, and rejection after two no-progress experiments.

```python
def test_clue_requires_next_action(self):
    with self.assertRaises(ValueError):
        record_clue(self.workspace, evidence="strings.txt", summary="AES constants")
```

- [ ] **Step 2: Run reversing tests and confirm red state**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_rev_agent -v`

Expected: missing `rev-agent` files.

- [ ] **Step 3: Implement reversing state helpers**

Create `rev/clues.json`, `rev/hypotheses.json`, `rev/ida/`, `rev/gdb/`, and
`rev/oracle/`. Clues require evidence and a next action. Hypotheses require a
falsifying test and track no-progress counts.

- [ ] **Step 4: Write the reversing skill and solver template**

The skill performs clue-first triage, follows idalib call/data flow, treats
decompilation as a hypothesis, changes to runtime evidence when packing or
anti-debug behavior appears, and creates a solver/keygen/emulator/patch early.
The target binary is the oracle; prose-only algorithm identification is not
completion.

- [ ] **Step 5: Run reversing tests**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_rev_agent -v`

Expected: all reversing tests pass.

- [ ] **Step 6: Commit reversing skill**

```bash
git add rev-agent tests/test_rev_agent.py
git commit -m "feat: add clue-driven reversing agent"
```

### Task 5: Install tools, document usage, and integrate

**Files:**
- Create: `tools/install-ctf-tools.sh`
- Create: `tools/check-ctf-tools.sh`
- Create: `tests/test_tool_scripts.py`
- Modify: `README.md`

**Interfaces:**
- Consumes: Ubuntu 26.04, `uv`, Docker, Node.js, and network/package-manager access.
- Produces: `/home/normalone/CTF/.venv`, installed CLI tools, a capability report, and documented skill invocations.

- [ ] **Step 1: Write failing installer/checker tests**

Assert shell syntax, idempotent directory creation, Python 3.12 venv location,
the required package/tool inventory, and README examples for all three skills.

```python
def test_checker_lists_required_tools(self):
    text = CHECKER.read_text()
    for name in ("gdb", "radare2", "ffuf", "sqlmap", "nmap", "nuclei"):
        self.assertIn(name, text)
```

- [ ] **Step 2: Run tool-script tests and confirm red state**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_tool_scripts -v`

Expected: missing installer and checker scripts.

- [ ] **Step 3: Implement idempotent tool installation**

Use apt for native packages available on Ubuntu, `uv` with Python 3.12 for
pwntools/angr/capstone/unicorn/z3/LIEF/requests/httpx/Playwright, Playwright's
Chrome support for browser automation, and pinned upstream release or Go-based
installation for ffuf/httpx/nuclei when apt does not provide them. Install
sqlmap through the distro package or an isolated checkout. Do not overwrite the
existing GDB or idalib MCP configuration.

- [ ] **Step 4: Implement capability checker and README**

The checker emits JSON containing path/version/status for each CLI, Python
module, MCP name, and Chrome. README documents event/challenge placement,
three skill invocations, session layout, race/strict modes, sharing findings,
installation, checking, and test commands.

- [ ] **Step 5: Run static script tests**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_tool_scripts -v`

Expected: all tool-script tests pass.

- [ ] **Step 6: Run the installer and checker**

Run: `bash tools/install-ctf-tools.sh`

Run: `bash tools/check-ctf-tools.sh`

Expected: checker reports required tools as available or emits an exact
degraded capability with the failed install command and fallback.

- [ ] **Step 7: Run the complete test suite**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`

Expected: all tests pass with no failures or errors.

- [ ] **Step 8: Validate all skill metadata and repository state**

Run: `rg -n "RYZEN1|boblab04|Ubuntu-24.04|value: \"pwndbg\"|value: \"idapro\"|(^|[^3])python " pwn-agent web-agent rev-agent README.md`

Expected: no stale runtime assumptions or bare Python commands.

Run: `git diff --check && git status --short`

Expected: no whitespace errors; only intended task files are changed.

- [ ] **Step 9: Commit integration**

```bash
git add README.md tools tests/test_tool_scripts.py
git commit -m "docs: add CTF agent setup and tool checks"
```
