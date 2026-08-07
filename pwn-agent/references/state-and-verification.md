# State and flag verification

Keep `state.json` small and machine-readable.

- **Fact:** directly observed, with an artifact or command reference.
- **Hypothesis:** falsifiable claim, confidence, and next discriminating test.
- **Experiment:** command or action, expected observation, actual result, and
  artifact path.
- **Capability:** concrete primitive such as controlled RIP, arbitrary read,
  libc base, arbitrary write, stack pivot, shell, or flag-file read.
- **Strategy:** the one currently selected exploit path and its blockers.

Demote or remove contradicted hypotheses. Never promote a decompiler guess,
offset, address, or libc match to fact without evidence.

## Binary-safe evidence

Save bytes sent to the process separately from bytes received. Do not rely only
on terminal rendering: NUL bytes, ANSI control sequences, and decoding errors can
hide or invent apparent output. Hash raw transcripts.

## Strict success rule

A candidate flag is verified only when:

1. the same byte sequence appears in output from at least two fresh sessions;
2. it matches a manifest-supplied or explicit flag pattern;
3. it was not present in bytes sent by the exploit or user;
4. each transcript is saved and attributable to the authorized target.

Run:

```text
python scripts/verify_flag.py \
  --output transcripts/run1.recv.bin \
  --output transcripts/run2.recv.bin \
  --sent transcripts/sent.bin \
  --pattern 'FLAG\{[^}\r\n]+\}' \
  --result flag-result.json
```

Exit code 0 means verified. Exit code 2 means unverified; inspect `reason`. Do not
report a flag as final unless this check or an equivalent stricter check passes.
