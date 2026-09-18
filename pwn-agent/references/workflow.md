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
   python3 <skill>/scripts/publish_capture.py --workspace <workspace> \
     --capture-id run-1 --source-target local:chall --output transcripts/run-1.recv.bin \
     --sent transcripts/run-1.sent.bin
   python3 <skill>/scripts/verify_flag.py --workspace <workspace> \
     --output transcripts/run-1.recv.bin --sent transcripts/run-1.sent.bin \
     --attestation artifacts/captures/run-1.json
   ```

   Race mode reports the first attested non-echoed flag. Use strict verification
   only for `mode: strict`, with two distinct output/sent/attestation triples.

Do not split routine stages across agents. A short-lived explorer, if genuinely
needed, uses a separate session and publishes evidence only.
