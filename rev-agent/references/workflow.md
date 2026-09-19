# Clue-driven reversing workflow

1. Identify one dedicated challenge directory below `/home/normalone/CTF` and
   retain the complete pasted event statement. Before initialization, inspect
   supplied files only with cheap read-only magic, format, and permission checks.
   Select one clear challenge-relative executable without running it. If several
   candidates remain plausible, ask one precise question instead of guessing.
2. Initialize one common `rev` session by sending a single stdin JSON object to:

   ```text
   python3 <ctf-common>/scripts/init_session.py <challenge-dir> --category rev \
     --event-root /home/normalone/CTF --request-json -
   ```

   Set `statement` to the exact pasted prose and include the selected `binary`
   and optional `flag_pattern`; never put prose in command-line arguments and
   never add YAML. Reversing intake accepts no network target. If the result is
   `target_status: needs_selection`, stop before oracle execution.
3. Run `init_rev_state.py`, then read valid immutable shared findings before a
   single cheap triage pass: file metadata, architecture, imports, strings,
   constants, entry points, and one controlled execution of only the bound
   executable.
4. Add only high-value observations to `clues.json`: each clue needs evidence,
   relevant xrefs and functions, and the cheapest next action that could
   discriminate it. Do not summarize the whole binary.
5. Use `idalib` call graphs, xrefs, and data flow to join user input through each
   transformation to the final comparison. Follow actual calls and global data,
   not a plausible function name. Treat decompiler/algorithm claims as active
   hypotheses until assembly or runtime evidence supports them.
6. Give every hypothesis an explicit falsifying test. Record each test and its
   evidence in `hypotheses.json`; record conflicting evidence in
   `contradictions.json`. Two experiments with no progress reject the hypothesis
   and require a materially different approach.
7. Create a candidate input, solver, keygen, emulator, or patch early. Run it
   against the manifest-authorized local binary as the oracle and save output in
   `rev/oracle/`. The solver creates sent/output evidence and an attestation in
   the same capture; do not verify arbitrary files.
   Identifying an algorithm in prose is not completion.
8. Before meaningful target interaction, call the common attempt ledger. After
   two no-progress attempts, change strategy; publish reusable verified facts
   only with the common finding CLI.

```text
python3 <skill>/scripts/record_clue.py hypothesis --workspace <workspace> \
  --statement '<claim>' --falsifying-test '<disproof test>'
python3 <skill>/scripts/record_clue.py experiment --workspace <workspace> \
  --hypothesis-id hypothesis-0001 --evidence gdb/trace.txt --result '<outcome>'
python3 <skill>/scripts/record_clue.py contradiction --workspace <workspace> \
  --hypothesis-id hypothesis-0001 --evidence gdb/alternate.txt --summary '<conflict>'
python3 <ctf-common>/scripts/record_attempt.py --workspace <workspace> \
  --signature '<candidate or runtime test>' --progress 'new clue: <detail>'
python3 <skill>/assets/solver.py --workspace <workspace> --binary <binary> \
  --candidate '<candidate>' --output <workspace>/rev/oracle/oracle.out --verify
```

The lead solver owns its session. A short-lived explorer, when necessary for a
distinct hypothesis, uses its own common session and shares only immutable,
evidence-backed findings.
