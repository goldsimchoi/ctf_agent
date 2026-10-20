# Phased web workflow

1. **Intake.** Identify one dedicated challenge directory below
   `/home/normalone/CTF`; an empty directory is valid for a fileless challenge.
   Preserve the full pasted statement and select exactly one clear HTTP(S)
   remote challenge URL without connecting. Pass the statement, normalized
   `target`, and an optional user-owned `callback` as one JSON object over stdin
   to:

   ```text
   init_session.py <challenge-dir> --category web \
     --event-root /home/normalone/CTF --request-json -
   ```

   Free-form prose never appears in shell argv. With no clear target, keep
   `needs_selection` and send no traffic.
2. **Initialize state.** Run `init_web_state.py`, read the generated `start_url`
   and `origin`, and read shared verified findings for this fingerprint.
3. **Analyze.** Fill `analysis.md` following `analysis.md` in this directory:
   flag location and barrier first, then attack surface, vulnerability, and
   exploit path. In white-box challenges, trace input to sink with `file:line`.
4. **Map coverage.** Capture the baseline at `start_url`. Map endpoint × method
   × input location × parameter × technique tuples rather than only forms, and
   add new endpoints after every response.
5. **Lab (optional).** If source or Docker files are supplied, build the
   exploit locally under the rules in `lab.md`. A local flag is a placeholder.
6. **Test hypotheses on the target.** Use the common `record_attempt.py` guard
   (done by `request.py`) before each interaction. Pick the cheapest test that
   separates two explanations and compare status, body, redirects, timing,
   length, cookies, and parser or tool errors. Read full saved bodies.
7. **Advance coverage.** Mark tuples `tested`, `promising`, `confirmed`, or
   `discarded` with `record_coverage.py`; confirmation requires a
   provenance-verified response body.
8. **Use capabilities.** On a new capability, update `web/capabilities.json`
   with capability, evidence, and the next shortest action toward the flag
   location. Do not keep broadening probes after a direct path appears.
9. **Reset on no progress.** After two attempts without a new fact, endpoint,
   primitive, clue, or flag candidate, write a reset note in `notes.md` listing
   facts separately from interpretations, then choose a new hypothesis from the
   facts alone.
10. **Verify.** Run `verify_web_flag.py` on the remote response body. Only
    `verified` is a solve; act on any other status as described in `SKILL.md`.
    Publish reusable verified evidence only through `publish_finding.py`.

The lead solver owns the canonical session. A short-lived explorer, if truly
needed for a distinct hypothesis, gets a separate common session and a
facts-only handoff, and may share only immutable evidence.
