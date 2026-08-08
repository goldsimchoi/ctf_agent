---
name: pwn-agent
description: Use when the user asks Codex to solve an authorized CTF pwnable or binary-exploitation challenge, analyze an ELF, write or test a pwntools exploit, debug with IDA/idalib or GDB/pwndbg, or retrieve and verify a flag from a supplied local or manifest-scoped target.
---

# Pwn Agent

Solve one authorized challenge end to end. Keep one persistent Lead Solver as the
owner; use short-lived explorers only to resolve genuine ambiguity. A draft
exploit, crash, leak, or shell is not the requested result when the user asked for
the flag.

## Start

1. Accept only user-supplied local artifacts and manifest-scoped endpoints. Treat
   missing `network_access` as `user_only`. Connect only when the manifest has
   both `authorized: true` and `network_access: agent_allowed`, the challenge is
   a pwnable, and the event permits AI Agent access. Never scan for targets.
2. Read [references/safety.md](references/safety.md).
3. Before analysis writes any files, pass a challenge directory, direct ELF, or
   existing manifest to:

   ```text
   python <skill>/scripts/init_run.py <challenge> --runs-root <project>/runs
   ```

   When no manifest exists, the initializer creates a minimal resolved manifest
   inside the run workspace. If multiple ELFs make the target ambiguous, create
   the manifest there from [assets/challenge.yaml](assets/challenge.yaml).
4. Work only in the returned workspace. Preserve the supplied inputs.

## Solve

Read [references/runtime.md](references/runtime.md), then use the best available
route: pwntools for interaction, pwndbg/GDB for runtime truth, and IDA/idalib for
semantic static analysis. MCP is preferred when present; use the documented local
fallbacks immediately when it is absent.

Follow [references/workflow.md](references/workflow.md):

- perform low-cost triage and one normal execution;
- create a runnable `exploit.py` early;
- convert each unknown into a falsifiable hypothesis and a discriminating test;
- preserve raw command, crash, debugger, and process-I/O evidence;
- advance capability by capability toward the shortest reliable exploit.

Develop and test locally first. For `agent_allowed`, send requests only to the
manifest's exact host, port, and protocol within its budget. For `user_only`,
remote delivery is performed by the user. The final `exploit.py` must not read
`/proc`, procfs-derived maps, `auxv`, `environ`, or file-descriptor entries, and
must not call helpers such as `process.libs()` to obtain runtime addresses.
Derive runtime values from supplied ELF/libc files and exploit-earned leaks. GDB
and pwndbg may use procfs internally during development, but the final exploit
and its success path must not depend on it.

Do not divide routine stages across agents. If two meaningful experiments fail or
the exploit family remains ambiguous, use at most two isolated, read-only
explorers. Give them different hypotheses and tight budgets. The Lead Solver alone
selects a path and edits the canonical exploit and state.

Maintain `state.json` and `notes.md` using
[references/state-and-verification.md](references/state-and-verification.md).
Keep reasoning compact; store large raw output under the artifact directories.

## Finish

On the first clean local exploit success, notify the user immediately even when
other batch challenges are still running. Save the local transcript. For
`agent_allowed`, run one fresh remote session, save sent and received bytes
separately, reject echoed input, and report a matching flag. Repeat only when the
result is ambiguous or the exploit is flaky. For `user_only`, provide the exact
local command plus a generic user-operated remote command using runtime `HOST`
and `PORT` values.

Create `WRITEUP.md` in the run workspace after solving. Keep it concise and
include the challenge summary, mitigations, root vulnerability, exploit stages,
important offsets, notable failed approaches and fixes, exact exploit commands,
and the complete verified flag only when it is available from permitted local
evidence. Otherwise state that remote execution and flag confirmation are
user-operated.

Return the verified flag first when `agent_allowed`; otherwise return local
exploit success first. Follow with the workspace, exploit, transcript, execution
command, and writeup paths. Clearly distinguish local exploit completion from
user-operated remote flag confirmation. If local success is impossible, return
the exact terminal blocker and strongest evidence reached; do not disguise
partial progress as completion.
