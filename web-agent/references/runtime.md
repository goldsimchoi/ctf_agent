# Runtime and evidence tools

Use `python3`; do not assume a `python` command. `requests` is the primary
portable HTTP primitive. [assets/request.py](../assets/request.py) keeps one
`requests.Session` per workspace, serializes its cookie jar, requires an exact
authorized origin, uses explicit timeouts, and saves prepared-request evidence
plus undecoded response entity-body bytes. Requests does not expose literal HTTP
wire framing or original header serialization; provenance marks both capture
boundaries with `wire_exact: false`.

Use Playwright with Chrome only with `--user-data-dir <workspace>/web/browser-profile`.
For browser storage or WebSockets, save exported storage/message bytes beneath
the owning `web/responses/` directory. `ffuf`, `sqlmap`, `httpx`, and `nuclei`
are optional accelerators, never authorization expansion; record the precise
command and raw output when used.
