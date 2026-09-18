# Reversing state and verification

`init_rev_state.py` creates `rev/clues.json`, `rev/hypotheses.json`,
`rev/contradictions.json`, `rev/ida/`, `rev/gdb/`, and `rev/oracle/` in one
common reversing session. They are session-local; the common helper remains the
sole owner of `state.json` and shared findings are immutable.

Each clue has evidence, summary, xrefs, relevant functions, and a next action.
Each hypothesis has a falsifying test, status, no-progress count, experiments,
and linked contradictions. Do not erase evidence that contradicts an appealing
theory: record it, then reject an active hypothesis after its second no-progress
experiment.

Use the target binary as the oracle. Save candidate input separately when it may
contain a flag, and preserve the target output under `rev/oracle/`. Verify a
candidate only against target-attributable output with the common verifier:

```text
python3 <ctf-common>/scripts/verify_flag.py --workspace <workspace> \
  --output <workspace>/rev/oracle/oracle.out
```

Race mode accepts one clean target result; strict mode needs two clean outputs
with `--strict`. Do not submit a candidate merely because a decompiler suggests
the algorithm.
