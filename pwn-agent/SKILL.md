---
name: pwn-agent
description: Use when the user asks Codex to solve an authorized CTF pwnable, analyze an ELF, write or test a pwntools exploit, debug with GDB or idalib, or retrieve and verify a flag from a supplied local or manifest-scoped target.
---

# Pwn Agent

Solve one authorized pwn challenge end to end. One persistent Lead Solver owns the
session, exploit, and strategy; a draft exploit, crash, leak, or shell is progress,
not a flag result.

## Start

1. Identify the one dedicated problem folder from the request. It may have no
   `challenge.yaml`; no YAML, labels such as `description:` or `address:`, or fixed
   problem-statement layout is required. Never treat `/home/normalone/CTF` itself
   or a folder containing multiple problems as the challenge directory.
2. Preserve the entire pasted event statement exactly. Interpret its natural-language
   meaning and recognize TCP candidates written as `nc host port`, `host:port`, or
   `tcp://host:port`. Select exactly one clear candidate without connecting to any
   candidate; if multiple plausible host/port tuples remain, ask one precise question.
   No address means local-only analysis.
3. Read [references/safety.md](references/safety.md), then inspect supplied files
   read-only by type/magic to identify one clear challenge-relative ELF, PE, or script
   candidate. Do not execute a candidate during selection. If multiple local
   executables are equally plausible, ask one precise question instead of guessing.
4. Send one normalized JSON object as standard input, never as shell arguments, to:

   ```text
   python3 <skill>/scripts/init_run.py <challenge-dir> \
     --event-root <event-root> --request-json -
   ```

   Use `/home/normalone/CTF` as `<event-root>` whenever the challenge is below that
   root. Otherwise use the containing event root. The stdin object has `statement`
   set to the exact full prose and includes `target`, `binary`, and `flag_pattern`
   only when selected. For example, its data shape is:

   ```json
   {
     "statement": "<entire exact pasted event statement>",
     "target": "tcp://pwn.example:31337",
     "binary": "chall"
   }
   ```

   Pass those JSON bytes through stdin using a process API; never interpolate,
   quote, or otherwise place free-form statement prose in a shell command. The
   initializer validates the selections and produces the session-local resolved
   manifest. Do not add YAML to the challenge directory.
5. The one-line JSON result identifies an isolated `runs/pwn/` session and existing
   immutable findings. Read those findings before solve triage, reuse only
   evidence-backed facts for this fingerprint, and work only in the returned session.

Accept only user-supplied local artifacts and the endpoint bound by the resolved
manifest. Direct connection requires `authorized: true` and
`network_access: agent_allowed`; missing `network_access` means `user_only`. Never
scan for targets.

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

Save exact sent and received bytes separately in the session, then attest the target
capture before verification. The pwn adapter, not the verifier, is responsible for
binding `local:<process>` or `tcp://<host>:<port>` to the interaction:

```text
python3 <skill>/scripts/publish_capture.py --workspace <workspace> \
  --capture-id run-1 --source-target tcp://challenge.example:31337 \
  --output transcripts/run-1.recv.bin --sent transcripts/run-1.sent.bin
```

In default `mode: race`, verify and report the first source-attributable,
non-echoed target flag immediately:

```text
python3 <skill>/scripts/verify_flag.py --workspace <workspace> \
  --output transcripts/run-1.recv.bin --sent transcripts/run-1.sent.bin \
  --attestation artifacts/captures/run-1.json
```

Stop polishing once it verifies. Only `mode: strict` requires two fresh outputs and
`--strict`; continue validation only if attribution or echo status is ambiguous.
Create `WRITEUP.md` after a verified flag or terminal blocker, and return the flag
first with workspace, exploit, and evidence paths.
