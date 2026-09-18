---
name: pwn-agent
description: Use when the user asks Codex to solve an authorized CTF pwnable, analyze an ELF, write or test a pwntools exploit, debug with GDB or idalib, or retrieve and verify a flag from a supplied local or manifest-scoped target.
---

# Pwn Agent

Solve one authorized pwn challenge end to end. One persistent Lead Solver owns the
session, exploit, and strategy; a draft exploit, crash, leak, or shell is progress,
not a flag result.

## Start

1. Accept only user-supplied local artifacts and manifest-scoped endpoints. Missing
   `network_access` means `user_only`; connect only when `authorized: true` and
   `network_access: agent_allowed`. Never scan for targets.
2. Read [references/safety.md](references/safety.md), then initialize a challenge
   directory before analysis writes:

   ```text
   python3 <skill>/scripts/init_run.py <challenge-dir> --event-root <event-root>
   ```

   The JSON result identifies an isolated `runs/pwn/` session and existing immutable
   findings. Keep challenge inputs read-only. If needed, put the minimal manifest
   from [assets/challenge.yaml](assets/challenge.yaml) in the challenge directory.
3. Read shared findings before triage. Reuse only evidence-backed facts for this
   fingerprint, never old hypotheses. Work only in the returned session.

## Solve

Read [references/runtime.md](references/runtime.md) and
[references/workflow.md](references/workflow.md). Prefer the `gdb` MCP for runtime
truth and `idalib` MCP for semantic static analysis; immediately fall back to
native GDB, binutils, `strace`, and Python 3 tooling when needed.

- Do one cheap triage pass and controlled execution, then create runnable
  `exploit.py` early in the managed pwntools environment.
- Make every unknown a falsifiable hypothesis and discriminating test.
- Record meaningful attempts with the common CLI. After two attempts without a new
  fact, primitive, clue, endpoint, or candidate, change strategy.
- Keep raw target I/O, debugger data, and crashes in session artifacts. Publish
  reusable facts only as immutable findings. The helper owns `state.json`.

For `agent_allowed`, interact only with the manifest's exact host, port, and
protocol. For `user_only`, give the user the remote command. The final exploit must
not obtain runtime addresses from `/proc`, procfs-derived maps, `auxv`, `environ`,
file descriptors, or helpers such as `process.libs()`.

## Finish

Save sent and received bytes separately. In default `mode: race`, verify and report
the first source-attributable, non-echoed target flag immediately:

```text
python3 <skill>/scripts/verify_flag.py --workspace <workspace> \
  --output transcripts/target.recv.bin --sent transcripts/target.sent.bin
```

Stop polishing once it verifies. Only `mode: strict` requires two fresh outputs and
`--strict`; continue validation only if attribution or echo status is ambiguous.
Create `WRITEUP.md` after a verified flag or terminal blocker, and return the flag
first with workspace, exploit, and evidence paths.
