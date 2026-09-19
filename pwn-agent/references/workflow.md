# Solver workflow

The Lead Solver owns the canonical exploit and final decision.

1. Identify one dedicated challenge directory below `/home/normalone/CTF` and retain
   the complete pasted event statement. Extract TCP candidates only from supplied
   context in `nc host port`, `host:port`, or `tcp://host:port` form; never connect
   to candidates to choose one. Missing TCP context means local-only. Ask one precise
   question when multiple plausible tuples remain.
2. Inspect supplied files read-only by type/magic and select one clear
   challenge-relative ELF, PE, or script as `binary`. Ask one precise question when
   multiple executable candidates remain; do not run them to decide.
3. Initialize by passing the exact statement and selected `target`, `binary`, and
   optional `flag_pattern` as one JSON object over stdin to
   `init_run.py --request-json -`. Free-form prose must never appear in shell argv.
   No YAML or labeled fields are required, and challenge inputs remain unchanged.
   Always pass `--event-root /home/normalone/CTF`. Read returned immutable findings
   before solve triage.
4. Triage file type, architecture, mitigations, imports, strings, protocol,
   supplied libc/loader, and one normal execution.
5. Create a small runnable `exploit.py`; make each unknown a hypothesis with one
   discriminating experiment.
6. Use static inspection → controlled local run → GDB → primitive → local chain →
   manifest-scoped remote reproduction.
7. Record every meaningful target interaction:

   ```text
   python3 <common>/record_attempt.py --workspace <workspace> --signature '<attempt>'
   ```

   Add `--progress 'new fact: <detail>'` only for new evidence. The common helper
   rejects unchanged failures and ends the no-progress budget after two attempts.
8. Keep compact evidence references in `notes.md`; save raw I/O and debugger output
   under session artifacts. Publish a verified reusable fact with:

   ```text
   python3 <common>/publish_finding.py --workspace <workspace> --kind fact \
     --evidence artifacts/<file> --summary '<verified fact>'
   ```

9. After each target interaction, keep exact sent and received files in the session
   and publish its immutable attestation before verification:

   ```text
   WORKSPACE='/absolute/path/to/session'
   SOURCE_TARGET="$(
     python3 - "$WORKSPACE" <<'PY'
import json
import pathlib
import re
import sys

workspace = pathlib.Path(sys.argv[1]).resolve(strict=True)
session = json.loads((workspace / "session.json").read_text(encoding="utf-8"))
manifest = (workspace / "challenge.resolved.yaml").read_text(encoding="utf-8")
match = re.search(r"^\s*binary\s*:\s*([^#\n]+)", manifest, re.MULTILINE)
if match is None:
    raise SystemExit("resolved manifest has no binary")
binary = pathlib.Path(match.group(1).strip().strip("'\""))
if binary.is_absolute() or ".." in binary.parts:
    raise SystemExit("resolved manifest binary is not challenge-relative")
print("local:" + str((pathlib.Path(session["challenge"]) / binary).resolve(strict=True)))
PY
   )"
   python3 <skill>/scripts/publish_capture.py --workspace "$WORKSPACE" \
     --capture-id run-1 --source-target "$SOURCE_TARGET" \
     --output "$WORKSPACE/transcripts/run-1.recv.bin" \
     --sent "$WORKSPACE/transcripts/run-1.sent.bin"
   python3 <skill>/scripts/verify_flag.py --workspace "$WORKSPACE" \
     --output "$WORKSPACE/transcripts/run-1.recv.bin" \
     --sent "$WORKSPACE/transcripts/run-1.sent.bin" \
     --attestation "$WORKSPACE/artifacts/captures/run-1.json"
   ```

   Race mode reports the first attested non-echoed flag. Use strict verification
   only for `mode: strict`, with two distinct output/sent/attestation triples.

Do not split routine stages across agents. A short-lived explorer, if genuinely
needed, uses a separate session and publishes evidence only.
