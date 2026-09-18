---
name: rev-agent
description: Use when the user asks Codex to solve an authorized CTF reversing challenge, analyze a supplied binary, recover a checker input, or build and verify a local solver, keygen, emulator, or patch.
---

# Reversing Agent

Solve one authorized reversing challenge with clue-driven evidence and an
executable result. A plausible decompilation or algorithm label is not a solve:
the target binary is the oracle.

## Start

1. Read [references/safety.md](references/safety.md). Accept only user-supplied
   local artifacts and manifest-authorized CTF execution. Keep challenge inputs
   read-only.
2. Create the common session and session-local reversing state:

   ```text
   python3 <ctf-common>/scripts/init_session.py <challenge-dir> --category rev \
     --event-root <event-root>
   python3 <skill>/scripts/init_rev_state.py --workspace <workspace>
   ```

   Work only in the returned `runs/rev/` session. Read returned immutable
   findings before analysis; never promote an old hypothesis to fact.
3. Read [references/runtime.md](references/runtime.md),
   [references/workflow.md](references/workflow.md), and
   [references/state-and-verification.md](references/state-and-verification.md).

## Solve

Start clue-first: collect file metadata, strings, imports, constants, entry
points, and one controlled execution. Record every material clue with its
evidence, xrefs, functions, and cheapest discriminating next action:

```text
python3 <skill>/scripts/record_clue.py clue --workspace <workspace> \
  --evidence artifacts/strings.txt --summary 'candidate compare constant' \
  --xref 0x4012ab --function check_input \
  --next-action 'trace input bytes to final comparison'
```

Use `idalib` MCP for call graphs, xrefs, and data-flow from input to comparison;
use the `gdb` MCP when static evidence must be tested. Fall back immediately to
native GDB, binutils, `strings`, and `strace` if an MCP is unavailable. Treat
decompiler output as a hypothesis until assembly or runtime evidence confirms it.

Maintain a falsifiable hypothesis register and contradiction evidence. Packing,
runtime decoding, anti-debug behavior, or self-modifying code is a signal to
switch to controlled traces and memory artifacts, not to keep interpreting stale
pseudocode. Two no-progress hypothesis experiments reject that path and require
a materially different approach.

Build a solver, keygen, emulator, patch, or candidate early. Run it against the
manifest-authorized local target and retain its sent/output evidence and capture
attestation; prose-only algorithm identification is incomplete. Before every
meaningful interaction, use the common attempt ledger, and after two no-progress
attempts change strategy.

## Finish

Verify only an adapter-created, attested capture with the common flag verifier.
In race mode, report the first clean non-echoed flag immediately; strict mode
alone needs two independent output/sent/attestation triples. Then create a short
writeup or report the terminal blocker with the workspace, executable artifact,
and evidence paths.
