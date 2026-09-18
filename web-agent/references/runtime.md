# Runtime and evidence tools

Use `python3`; do not assume a `python` command. `requests` is the primary
portable HTTP primitive. [assets/request.py](../assets/request.py) keeps one
`requests.Session` per workspace, serializes its cookie jar, requires an exact
authorized origin, uses explicit timeouts, and saves prepared-request evidence
plus undecoded response entity-body bytes. Requests does not expose literal HTTP
wire framing or original header serialization; provenance marks both capture
boundaries with `wire_exact: false`.

For supported identity, gzip, and deflate bodies, capture writes a bounded
decoded scan body and bounded sent-history artifact, then publishes the common
capture attestation immediately. The sent history retains prior session traffic,
redirect hops, prepared bytes, and supported URL/form/JSON semantic values.

Decoding is incremental and capped at the common artifact limit. Oversized
entity bodies, trailing compressed data, malformed streams, and unsupported
content encodings remain recorded but intentionally receive no verification
attestation.

Use Playwright with Chrome only with `--user-data-dir <workspace>/web/browser-profile`.
For browser storage or WebSockets, save exported storage/message bytes beneath
the owning `web/responses/` directory. `ffuf`, `sqlmap`, `httpx`, and `nuclei`
are optional accelerators, never authorization expansion; record the precise
command and raw output when used.
