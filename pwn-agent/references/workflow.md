# Solver workflow

Use one persistent Lead Solver per challenge. The Lead Solver owns `exploit.py`,
`state.json`, and the final decision.

1. Ingest only a local challenge directory or an explicitly authorized manifest.
2. Create a run workspace with `scripts/init_run.py`; never write beside the
   supplied binary.
3. Perform cheap triage: file type, architecture, mitigations, imports, strings,
   protocol, supplied libc/loader, and one normal execution.
4. Write the smallest runnable `exploit.py` early. Turn every unknown into a
   hypothesis and one discriminating experiment.
5. Prefer this evidence ladder:
   static inspection → controlled local run → debugger → exploit primitive →
   local chain → manifest-scoped remote reproduction.
6. Update compact state after meaningful evidence. Put large debugger output and
   process I/O in artifact files, not in the reasoning record.
7. Verify the candidate in two fresh sessions with `scripts/verify_flag.py`.

## Conditional exploration

Do not split routine stages among agents. Add at most two read-only explorers only
when the exploit family is genuinely ambiguous or the same strategy has stalled
after two meaningful experiments.

Give each explorer a separate directory under `explorers/`, a distinct hypothesis,
at most two discriminating experiments, and an evidence-only output contract.
They must not edit the Lead Solver's exploit or state. Do not concurrently share
one stateful debugger or writable IDA database; use isolated sessions or run the
explorers sequentially with a hard reset. The Lead Solver selects the path with
the strongest reproducible primitive, records why, and releases the others. After
selection, switch to the runner-up at most once and only after two more meaningful
experiments fail to advance a capability.

Reserve the final 15% of an explicit time budget for two clean reproductions and
verification.

## Terminal conditions

Continue until one of these is true:

- a flag passes strict reproduction and echo rejection;
- the authorized target is unavailable;
- a required artifact or credential is absent;
- the environment cannot execute the target after documented fallbacks;
- an explicit user budget expires.

An exploit draft, crash, leak, shell, or plausible flag string is progress, not
completion.
