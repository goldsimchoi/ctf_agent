# ctf_agent

Codex skills and deterministic helpers for authorized CTF pwn, web, and
reversing challenges on this Ubuntu notebook.

## Layout

Place source artifacts under the exact event layout; challenge inputs stay
read-only:

```text
/home/normalone/CTF/<event>/challenges/<challenge>/
```

Each initialization creates a separate run under:

```text
/home/normalone/CTF/<event>/runs/<category>/<slug>-<fingerprint12>/
├── shared/findings/<session-id>/       # immutable, evidence-backed facts
└── sessions/<session-id>/              # private state, logs, artifacts, profiles
```

Sessions never share mutable state. A later session may read matching immutable
findings, but it must not treat old hypotheses as facts.

## Install and check capabilities

From this repository on Ubuntu, bootstrap the fixed managed Python environment
and native tooling:

```bash
bash tools/install-ctf-tools.sh
bash tools/check-ctf-tools.sh
```

The installer creates `/home/normalone/CTF/.venv` with uv-managed Python 3.12,
plus Python analysis/browser packages and available native tools. It does not
alter existing `gdb` or `idalib` MCP configuration. Preview the commands
without changing the host with `bash tools/install-ctf-tools.sh --dry-run`.

The checker always writes one JSON capability document. A `degraded` item has a
specific reason and a safe fallback, so unavailable optional scanners or
accelerators do not become silent failures.

The installer keeps its pinned sqlmap and radare2 entries under the dedicated
CTF manager directory, without modifying shell profiles or `~/.local/bin`.
Enable those entries for one shell after installation:

```bash
source /home/normalone/CTF/.tools/env.sh
```

## Use the skills

Install `pwn-agent`, `web-agent`, `rev-agent`, and `ctf-common` as sibling
Codex skills/support directories, then give Codex the authorized artifact or
manifest-scoped endpoint. Typical prompts are:

```text
Use $pwn-agent to solve this authorized pwn challenge and return a verified flag.
Use $web-agent to solve this authorized web challenge and return a verified flag.
Use $rev-agent to solve this authorized reversing challenge and return a verified flag.
```

The default `race` mode reports the first source-attributable, non-echoed flag
with its evidence. Set `mode: strict` in `challenge.yaml` only when two fresh
clean reproductions are required. Agents record evidence in their own session
and publish reusable facts solely through immutable `shared/findings/` files.

## Test

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_tool_scripts -v
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

## Safety

Use these skills only with user-supplied challenge artifacts and explicitly
authorized CTF endpoints. They must not scan targets outside the resolved
manifest scope. Challenge binaries, flags, transcripts, debugger databases,
and session workspaces are intentionally not included in this repository.
