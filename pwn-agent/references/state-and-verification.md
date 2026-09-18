# State and flag verification

The common initializer creates session-local `session.json`, `state.json`,
`challenge.resolved.yaml`, `notes.md`, `artifacts/`, `logs/`, and `transcripts/`.
The helper owns `state.json`; record attempts through its CLI. Keep notes compact:
facts with evidence paths, falsifiable hypotheses, experiments, capabilities, and
the current strategy. Publish only immutable evidence from the current session.

Save bytes sent separately from bytes received. Race mode accepts one flag matching
the configured/default pattern from authorized target output when it is not in sent
bytes:

```text
python3 scripts/verify_flag.py --workspace <workspace> \
  --output transcripts/target.recv.bin --sent transcripts/target.sent.bin
```

For `mode: strict`, require two clean outputs:

```text
python3 scripts/verify_flag.py --workspace <workspace> \
  --output transcripts/run1.recv.bin --output transcripts/run2.recv.bin --strict
```

Both modes reject echoes. Exit code 0 is verified; exit code 2 is unverified with
a JSON `reason`.
