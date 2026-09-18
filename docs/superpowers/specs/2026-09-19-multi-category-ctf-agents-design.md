# Multi-category CTF agents design

## Objective

Extend the existing `pwn-agent` repository with separate `web-agent` and
`rev-agent` skills, adapt the pwn skill to this Ubuntu notebook, and make every
challenge/session workspace collision-free. The default mode prioritizes time
to flag over exhaustive analysis while preserving exact evidence needed to
resume work or reject false positives.

The repository remains a set of Codex skills and deterministic helper scripts,
not a standalone model orchestration service.

## Design inputs

- TeamH4C web-agent analysis: <https://h4c.team/posts/74>
- TeamH4C reversing-agent analysis: <https://h4c.team/posts/49>
- Existing `pwn-agent` behavior and tests in this repository
- Current host: Ubuntu 26.04 x86_64, 18 logical CPUs, 14 GiB RAM
- Existing tools: Python 3, `uv`, Docker, GDB, binutils, `strace`, Chrome,
  Node.js, `curl`, `requests`
- Existing Codex MCP servers: `gdb` and `idalib`

Missing category tools will be installed as part of implementation. Python
commands in skills and scripts must use `python3` or the managed virtual
environment, never assume a `python` executable exists.

## Selected architecture

Use three independent skill directories backed by one non-skill common helper
directory:

```text
ctf_agent/
├── ctf-common/
│   ├── scripts/
│   └── references/
├── pwn-agent/                 # existing skill, adapted in place
├── web-agent/                 # new skill
├── rev-agent/                 # new skill
└── tests/
```

This avoids duplicating collision-sensitive workspace code while preserving
separate skill triggers, prompts, references, assets, and tool dependencies.
The three skills can be installed as sibling directories together with
`ctf-common`.

Rejected alternatives:

1. Duplicating workspace helpers into every skill makes each skill portable but
   invites behavior drift and inconsistent collision fixes.
2. A single category-switching skill has less duplication but conflicts with
   the requested folder separation and makes concurrent category sessions less
   explicit.

## Challenge and run layout

Users place every problem in its own directory under one event:

```text
/home/normalone/CTF/<event>/
├── challenges/
│   ├── babyheap/
│   ├── web-login/
│   └── crackme/
└── runs/
```

`challenge.yaml` is optional. When absent, the initializer derives a minimal
manifest from the problem directory and the selected skill. Source files are
treated as read-only.

Each run is namespaced by category, a safe challenge slug, a content
fingerprint, and a unique session ID:

```text
runs/<category>/<slug>-<fingerprint12>/
├── shared/
│   └── findings/
│       └── <session-id>/
│           └── <timestamp>-<random>.json
└── sessions/
    └── <session-id>/
        ├── session.json
        ├── challenge.resolved.yaml
        ├── state.json
        ├── notes.md
        ├── artifacts/
        ├── logs/
        └── transcripts/
```

The fingerprint is deterministic for the challenge inputs. The session ID uses
category, UTC time with microseconds, process ID, and cryptographic random
bytes. Directory creation is atomic and refuses explicit duplicate IDs.

There is no shared mutable `state.json`. Every session owns its state and
artifacts. Cross-session discoveries are shared only as immutable, atomically
created finding files. A new session indexes existing findings before triage,
so it can reuse verified facts without inheriting old hypotheses as facts.

## Race-first common behavior

Default mode is `race`; `strict` is opt-in through the manifest.

- Read shared verified findings before issuing new analysis commands.
- Run one cheap category-specific triage pass, skipping facts already supported
  by reusable evidence for the same fingerprint.
- Create an executable exploit/request/solver artifact early.
- Record normalized attempt signatures and do not repeat an unchanged failed
  attempt.
- After two meaningful attempts without a new fact, primitive, endpoint,
  clue, or candidate, change strategy rather than adding more analysis.
- Enforce manifest wall-time and no-progress budgets in helper code.
- Report an exact flag candidate from the authorized target immediately with
  its evidence path. Continue validation only when its source or echo status is
  ambiguous.
- `strict` mode requires two clean reproductions; `race` mode requires one
  source-attributable target result and rejects user-input echo.
- Generate a short writeup only after the flag is obtained or a terminal
  blocker is reached.

The skill may use a short-lived explorer only for distinct unresolved
hypotheses. Explorers must have separate sessions and must not edit another
session's workspace.

## Existing pwn agent

Keep `pwn-agent/` and adapt it rather than rebuilding it.

- Rename declared MCP dependencies from the old `pwndbg`/`idapro` assumptions
  to the notebook's `gdb` and `idalib` servers.
- Replace Windows/WSL-specific paths with native Ubuntu paths and capability
  detection.
- Prefer GDB MCP and idalib MCP; fall back to native GDB, binutils, and
  `strace`.
- Install pwntools and supporting binary-analysis packages in the managed CTF
  environment.
- Use the common session initializer and race/strict verifier.
- Stop polishing once an authorized remote response yields a non-echoed flag;
  local reliability work beyond that point is optional.

## Web agent

The web agent turns the web article's failure modes into explicit state:

- Maintain an `endpoint × method × input location × parameter × technique`
  coverage ledger with `untested`, `tested`, `promising`, `confirmed`, and
  `discarded` states.
- Track query, form, JSON, headers, cookies, path components, browser storage,
  and WebSocket/message inputs instead of concentrating only on visible forms.
- Give every agent session an independent cookie jar and Chrome profile.
- Save complete raw requests/responses separately from compact summaries.
- Preserve redirects, status, length, timing, cookie changes, and parsing/tool
  errors so response differences remain observable.
- Track acquired capabilities separately from the final objective. After a
  file read, authentication bypass, SSRF, injection, or code execution is
  obtained, choose the shortest remaining action to retrieve the flag.
- Only access manifest-scoped authorized origins. Do not scan adjacent hosts.
- Validate success from target-attributable response/browser evidence, not the
  agent's own shell output.

The managed tool set includes `requests`/`httpx`, Playwright with Chrome,
`ffuf`, `sqlmap`, `nmap`, `httpx` (ProjectDiscovery), and `nuclei`. Tools are
optional accelerators; the skill must still work with HTTP/browser primitives
when a scanner is unavailable.

## Reversing agent

The reversing agent follows clue-driven, executable-result-first analysis:

- Start with file metadata, strings, imports, constants, entry points, and one
  controlled execution.
- Build a clue register containing evidence, xrefs, relevant functions, and the
  next cheapest discriminating action.
- Use idalib call graphs, xrefs, and data-flow tracing to connect input through
  transformations to the final comparison. Do not summarize the whole binary.
- Treat decompiler output and inferred algorithms as hypotheses until assembly
  or runtime behavior supports them.
- Detect packing, runtime decoding, anti-debug behavior, and self-modifying code
  early; switch to GDB traces or memory artifacts when static evidence diverges.
- Produce a candidate input, solver, keygen, emulator, or patch early and use
  the target binary as the executable oracle.
- Every active hypothesis must include a falsifying test. Two no-progress tests
  force rejection or a materially different approach.
- Store IDA databases and debugger artifacts inside the owning session to avoid
  cross-session mutation.

The managed tool set includes radare2, pwntools, angr, capstone, unicorn, z3,
LIEF, binwalk, `ltrace`, and QEMU user-mode tools, in addition to existing GDB,
idalib, binutils, and `strace`.

## Common helper interfaces

The common scripts provide stable category-neutral operations:

```text
init_session.py <challenge-dir> --category {pwn,web,rev}
                [--event-root PATH] [--session-id ID]
publish_finding.py --workspace PATH --kind KIND --evidence PATH --summary TEXT
record_attempt.py --workspace PATH --signature TEXT [--progress KIND]
verify_flag.py --workspace PATH --output FILE [--sent FILE] [--strict]
```

All commands emit machine-readable JSON and nonzero exit codes for invalid
input, collisions, exhausted budgets, and unverified flags. Writes use temporary
files plus atomic rename. Paths are resolved and checked to prevent traversal
outside the event root and session workspace.

## Error handling

- Ambiguous problem inputs produce a minimal manifest template and an exact
  error instead of guessing the target.
- Missing optional tools trigger the documented fallback immediately.
- A stale or malformed shared finding is ignored with a logged reason; it does
  not block the session.
- Explicit session-ID collisions fail; autogenerated IDs retry with fresh
  randomness.
- Tool timeouts are recorded as attempts and normalized so identical retries
  are rejected unless inputs or strategy changed.
- A target mismatch or authorization failure stops all remote interaction.

## Testing

Implementation follows TDD. Tests cover:

1. multiple challenges under one event without path collisions;
2. concurrent initializers for the same challenge producing unique sessions;
3. pwn, web, and rev category namespaces remaining separate;
4. deterministic challenge fingerprints and reuse of immutable findings;
5. rejection of traversal, unsafe IDs, and explicit duplicate sessions;
6. race and strict flag-verification behavior with echo rejection;
7. no-progress and wall-time budget enforcement;
8. each skill's metadata, references, assets, and notebook-specific tool names;
9. web cookie/profile isolation and coverage-ledger serialization;
10. reversing clue/hypothesis state and executable-oracle result recording.

Installation checks report every available tool and version. Missing tools
after installation are reported as explicit degraded capabilities, not hidden.

## Implementation ownership

After the common workspace contract and tests are established, use three
subagents with non-overlapping write ownership:

- pwn subagent: only `pwn-agent/` and pwn-specific tests;
- web subagent: only `web-agent/` and web-specific tests;
- reversing subagent: only `rev-agent/` and reversing-specific tests.

The primary agent owns `ctf-common/`, shared tests, tool installation,
integration review, and final verification.
