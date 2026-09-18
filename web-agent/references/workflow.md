# Race-first web workflow

1. Read shared verified findings, resolve the authorized origin, capture one
   baseline request, and map endpoint/method/input tuples rather than only forms.
2. Test a cheapest discriminating hypothesis across query, form, JSON, headers,
   cookies, path, browser storage, and WebSocket/message inputs. Compare raw
   status, body, redirects, timing, length, parser failures, and cookie changes.
3. Before each target interaction, use the common `record_attempt.py` signature
   guard. Mark a tuple `tested`, `promising`, `confirmed`, or `discarded` with
   `record_coverage.py`; confirmation requires a provenance-verified response
   entity-body evidence path. Supported captures publish the bounded common
   attestation immediately; verification never creates it.
4. On a capability, update `web/capabilities.json` with capability, evidence,
   and next shortest action. Do not keep broadening probes after a direct path
   to the objective appears.
5. After two attempts without a new fact, endpoint, primitive, clue, or flag
   candidate, change the hypothesis. Publish reusable verified evidence only
   through the common `publish_finding.py` command.

The lead solver owns the canonical session. A short-lived explorer, if truly
needed for a distinct hypothesis, must have a separate common session and may
share only immutable evidence.
