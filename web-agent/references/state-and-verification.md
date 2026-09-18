# Web state and verification

`init_web_state.py` creates `web/cookies.json`, `web/browser-profile/`,
`web/coverage.json`, `web/capabilities.json`, `web/requests/`, and
`web/responses/` inside one common web workspace. These paths are session-owned;
the shared workspace's `state.json` remains owned by the common helpers.

The coverage ledger has a full endpoint/method/location/parameter/technique key.
Its legal forward transitions are `untested → tested → promising → confirmed`
or `discarded`; the two terminal states cannot be reopened. A confirmed entry
must point to an existing raw response in this session.

Race verification accepts one flag in authorized target output only if it was
not present in the saved sent request. Strict mode requires it in two clean
outputs. Run the common verifier against raw response/request files, not a
terminal transcript or agent-generated text.
