# Clue-driven reversing workflow

1. Initialize one common `rev` session, then run `init_rev_state.py`. Read valid
   immutable shared findings before a single cheap triage pass: file metadata,
   architecture, imports, strings, constants, entry points, and one controlled
   execution.
2. Add only high-value observations to `clues.json`: each clue needs evidence,
   relevant xrefs and functions, and the cheapest next action that could
   discriminate it. Do not summarize the whole binary.
3. Use `idalib` call graphs, xrefs, and data flow to join user input through each
   transformation to the final comparison. Follow actual calls and global data,
   not a plausible function name. Treat decompiler/algorithm claims as active
   hypotheses until assembly or runtime evidence supports them.
4. Give every hypothesis an explicit falsifying test. Record each test and its
   evidence in `hypotheses.json`; record conflicting evidence in
   `contradictions.json`. Two experiments with no progress reject the hypothesis
   and require a materially different approach.
5. Create a candidate input, solver, keygen, emulator, or patch early. Run it
   against the target binary as the oracle and save output in `rev/oracle/`.
   Identifying an algorithm in prose is not completion.
6. Before meaningful target interaction, call the common attempt ledger. After
   two no-progress attempts, change strategy; publish reusable verified facts
   only with the common finding CLI.

```text
python3 <ctf-common>/scripts/record_attempt.py --workspace <workspace> \
  --signature '<candidate or runtime test>' --progress 'new clue: <detail>'
python3 <skill>/assets/solver.py --workspace <workspace> --binary <binary> \
  --candidate '<candidate>' --output <workspace>/rev/oracle/oracle.out
```

The lead solver owns its session. A short-lived explorer, when necessary for a
distinct hypothesis, uses its own common session and shares only immutable,
evidence-backed findings.
