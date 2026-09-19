# Race-first web workflow

1. Identify one dedicated challenge directory below `/home/normalone/CTF`; an
   empty directory is valid for a fileless challenge. Preserve the full pasted
   statement and select exactly one clear HTTP(S) live-challenge URL from the
   user's current request. Normalize that selection while preserving its path and
   query. Ignore event-page and documentation links that are not the live service.
   Do not connect while selecting. If two origins remain plausible, ask one
   precise question instead of probing both.
2. Pass the exact statement and normalized `target` as one JSON object over stdin
   to:

   ```text
   init_session.py <challenge-dir> --category web \
     --event-root /home/normalone/CTF --request-json -
   ```

   Free-form prose must never appear in shell argv. Do not create YAML or other
   files in the challenge directory. If no target is clear, retain
   `needs_selection` and make no request.
3. Initialize web state in the returned session, read the generated `start_url`
   and `origin`, and read shared verified findings for this fingerprint. Capture
   the baseline at `start_url`; bind all later requests and redirects to the exact
   manifest `origin`. Map endpoint/method/input tuples rather than only forms.
4. Test a cheapest discriminating hypothesis across query, form, JSON, headers,
   cookies, path, browser storage, and WebSocket/message inputs. Compare raw
   status, body, redirects, timing, length, parser failures, and cookie changes.
5. Before each target interaction, use the common `record_attempt.py` signature
   guard. Mark a tuple `tested`, `promising`, `confirmed`, or `discarded` with
   `record_coverage.py`; confirmation requires a provenance-verified response
   entity-body evidence path. Supported captures publish the bounded common
   attestation immediately; verification never creates it.
6. On a capability, update `web/capabilities.json` with capability, evidence,
   and next shortest action. Do not keep broadening probes after a direct path
   to the objective appears.
7. After two attempts without a new fact, endpoint, primitive, clue, or flag
   candidate, change the hypothesis. Publish reusable verified evidence only
   through the common `publish_finding.py` command.

The lead solver owns the canonical session. A short-lived explorer, if truly
needed for a distinct hypothesis, must have a separate common session and may
share only immutable evidence.
