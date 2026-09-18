# State and flag verification

The common initializer creates session-local `session.json`, `state.json`,
`challenge.resolved.yaml`, `notes.md`, `artifacts/`, `logs/`, and `transcripts/`.
The helper owns `state.json`; record attempts through its CLI. Keep notes compact:
facts with evidence paths, falsifiable hypotheses, experiments, capabilities, and
the current strategy. Publish only immutable evidence from the current session.

Save bytes sent separately from bytes received, then have the pwn adapter publish
one immutable attestation per target interaction. The verifier never creates an
attestation from arbitrary files:

```text
python3 <skill>/scripts/publish_capture.py --workspace <workspace> \
  --capture-id run-1 --source-target tcp://challenge.example:31337 \
  --output transcripts/run-1.recv.bin --sent transcripts/run-1.sent.bin
```

For a remote capture, `source-target` must be the exact manifest-authorized
`tcp://<host>:<port>` and requires `authorized: true`,
`network_access: agent_allowed`, and `protocol: tcp` when a protocol is declared.
For a local capture, use `local:<canonical binary path>` for the regular,
challenge-contained file named by manifest `binary`. A supplied loader or libc may
shape local execution but does not replace that authoritative program identity.

Race mode accepts one flag matching the configured/default pattern from an attested
authorized target output when it is not in sent bytes:

```text
python3 scripts/verify_flag.py --workspace <workspace> \
  --output transcripts/run-1.recv.bin --sent transcripts/run-1.sent.bin \
  --attestation artifacts/captures/run-1.json
```

For `mode: strict`, require two clean outputs:

```text
python3 scripts/verify_flag.py --workspace <workspace> \
  --output transcripts/run1.recv.bin --sent transcripts/run1.sent.bin \
  --attestation artifacts/captures/run1.json --output transcripts/run2.recv.bin \
  --sent transcripts/run2.sent.bin --attestation artifacts/captures/run2.json --strict
```

Both modes reject echoes. Exit code 0 is verified; exit code 2 is unverified with
a JSON `reason`.
