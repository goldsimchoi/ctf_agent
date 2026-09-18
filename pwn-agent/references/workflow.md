# Solver workflow

The Lead Solver owns the canonical exploit and final decision.

1. Initialize the supplied challenge directory and read returned immutable findings
   before triage.
2. Triage file type, architecture, mitigations, imports, strings, protocol,
   supplied libc/loader, and one normal execution.
3. Create a small runnable `exploit.py`; make each unknown a hypothesis with one
   discriminating experiment.
4. Use static inspection → controlled local run → GDB → primitive → local chain →
   manifest-scoped remote reproduction.
5. Record every meaningful target interaction:

   ```text
   python3 <common>/record_attempt.py --workspace <workspace> --signature '<attempt>'
   ```

   Add `--progress 'new fact: <detail>'` only for new evidence. The common helper
   rejects unchanged failures and ends the no-progress budget after two attempts.
6. Keep compact evidence references in `notes.md`; save raw I/O and debugger output
   under session artifacts. Publish a verified reusable fact with:

   ```text
   python3 <common>/publish_finding.py --workspace <workspace> --kind fact \
     --evidence artifacts/<file> --summary '<verified fact>'
   ```

7. After each target interaction, keep exact sent and received files in the session
   and publish its immutable attestation before verification:

   ```text
   WORKSPACE='/absolute/path/to/session'
   SOURCE_TARGET="$(python3 -c '
import json, pathlib, re, sys
workspace = pathlib.Path(sys.argv[1]).resolve(strict=True)
session = json.loads((workspace / "session.json").read_text(encoding="utf-8"))
manifest = (workspace / "challenge.resolved.yaml").read_text(encoding="utf-8")
match = re.search(r"^\s*binary\s*:\s*([^#\n]+)", manifest, re.MULTILINE)
if match is None:
    raise SystemExit("resolved manifest has no binary")
binary = pathlib.Path(match.group(1).strip().strip("'\\\""))
if binary.is_absolute() or ".." in binary.parts:
    raise SystemExit("resolved manifest binary is not challenge-relative")
print("local:" + str((pathlib.Path(session["challenge"]) / binary).resolve(strict=True)))
' "$WORKSPACE")"
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
