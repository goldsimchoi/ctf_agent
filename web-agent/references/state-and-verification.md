# Web state and verification

The common initializer accepts an empty dedicated challenge directory below
`/home/normalone/CTF`. With `--event-root /home/normalone/CTF --request-json -`,
it preserves the full statement in `challenge-request.json` and emits only
validated adapter fields to `challenge.resolved.yaml`. A selected web target
produces `start_url`, exact `origin`, `authorized: true`, and
`network_access: agent_allowed`; `start_url` is the first request and `origin` is
the boundary for every subsequent request and redirect. Without a selected target,
`intake.target_status` is `needs_selection` and no web traffic is allowed.

`init_web_state.py` creates `web/cookies.json`, `web/browser-profile/`,
`web/coverage.json`, `web/capabilities.json`, `web/requests/`, `web/responses/`,
`web/provenance/`, `web/lab/`, and the `analysis.md` template inside one common
web workspace. These paths are session-owned;
the shared workspace's `state.json` remains owned by the common helpers.

The coverage ledger has a full endpoint/method/location/parameter/technique key.
Its legal forward transitions are `untested → tested → promising → confirmed`
or `discarded`; the two terminal states cannot be reopened. A confirmed entry
must point to an unchanged response entity body with an authorized provenance
record in this session. Summaries and captured errors are not confirmation evidence.

Race verification accepts one flag in a recorded authorized target response only
if it was not present in its capture-time bounded sent-history evidence. Strict
mode requires at least two submitted outputs and every output must have a
different authorized request-chain ID and capture ID. Run
`scripts/verify_web_flag.py`, not the common verifier directly; it validates
provenance and forwards only the existing common attestation/output/sent trio.

Before a candidate can become a flag, the web verifier also checks, in order:

| Check | Result when it fails |
|---|---|
| Manifest origin is not loopback, this machine, or a Docker bridge network | `lab_only` / `target_origin_is_local` |
| Every `analysis.md` section has real content | `unverified` / `analysis_incomplete` |
| Candidate does not appear in the supplied challenge files, including nested zip/tar/gzip | `unverified` / `candidate_in_supplied_files` |
| Candidate was not observed under `web/lab/` | `unverified` / `candidate_matches_lab_flag` |

Responses from the declared `callback_origin` are verifiable like target
responses, so an out-of-band delivery polled with `request.py` can complete a
solve. Supplied-file rejection is web-only; reversing flags legitimately live in
the supplied binary.

Requests in one session serialize their history transaction so each later
capture includes earlier submissions. Prepared evidence is committed before
each outbound dispatch; failed or timed-out sends remain incomplete history
entries and are still included in later echo checks. This lock is session-local;
separate web sessions remain independent.
