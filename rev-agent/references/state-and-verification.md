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

Use only the `authorized: true` challenge-relative `binary` in
`challenge.resolved.yaml` as the oracle. The solver binds `--binary` to that
regular, non-symlink file, preserves exact sent and raw combined stdout/stderr
bytes as new files in `rev/oracle/`, and publishes an immutable capture
attestation at capture time. Arbitrary or unattested files remain
`candidate_only`; the verifier never creates an attestation.

Verify a captured run with all three evidence paths:

```text
python3 <ctf-common>/scripts/verify_flag.py --workspace <workspace> \
  --output <workspace>/rev/oracle/oracle.out \
  --sent <workspace>/rev/oracle/oracle.sent \
  --attestation <workspace>/artifacts/captures/oracle-<id>.json
```

`solver.py --verify` performs one race-mode check only. Strict verification
requires at least two independently captured output/sent pairs through the
common verifier:

```text
python3 <ctf-common>/scripts/verify_flag.py --workspace <workspace> \
  --output <workspace>/rev/oracle/run1.out --sent <workspace>/rev/oracle/run1.sent \
  --attestation <workspace>/artifacts/captures/run1.json \
  --output <workspace>/rev/oracle/run2.out --sent <workspace>/rev/oracle/run2.sent \
  --attestation <workspace>/artifacts/captures/run2.json \
  --strict
```

Do not submit a candidate merely because a decompiler suggests the algorithm.
