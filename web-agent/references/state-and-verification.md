# Web state and verification

`init_web_state.py` creates `web/cookies.json`, `web/browser-profile/`,
`web/coverage.json`, `web/capabilities.json`, `web/requests/`, `web/responses/`,
and `web/provenance/` inside one common web workspace. These paths are session-owned;
the shared workspace's `state.json` remains owned by the common helpers.

The coverage ledger has a full endpoint/method/location/parameter/technique key.
Its legal forward transitions are `untested → tested → promising → confirmed`
or `discarded`; the two terminal states cannot be reopened. A confirmed entry
must point to an unchanged response entity body with an authorized provenance
record in this session. Summaries and captured errors are not confirmation evidence.

Race verification accepts one flag in a recorded authorized target response only
if it was not present in its capture-time bounded sent-history evidence. Strict
mode requires two distinct authorized request and capture IDs. Run
`scripts/verify_web_flag.py`, not the common verifier directly; it validates
provenance and forwards only the existing common attestation/output/sent trio.
