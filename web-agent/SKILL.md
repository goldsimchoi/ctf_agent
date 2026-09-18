---
name: web-agent
description: Use when the user asks Codex to solve an authorized CTF web challenge, test a manifest-scoped web application, inspect HTTP/browser behavior, or retrieve and verify a web flag.
---

# Web Agent

Solve one authorized web challenge with one persistent lead session. This workflow
adapts the coverage-ledger and state-discipline lessons from TeamH4C's
[web-agent analysis](https://h4c.team/posts/74) to compact, reproducible CTF work.

## Start

1. Read [references/safety.md](references/safety.md). Accept live traffic only
   when the resolved manifest says `authorized: true`,
   `network_access: agent_allowed`, and supplies one exact `origin`.
2. Initialize the common workspace, then browser/request state:

   ```text
   python3 <ctf-common>/scripts/init_session.py <challenge-dir> --category web --event-root <event-root>
   python3 <skill>/scripts/init_web_state.py --workspace <workspace>
   ```

   Keep inputs read-only. The returned session owns `web/cookies.json`,
  `web/browser-profile/`, `web/requests/`, `web/responses/`, and response
  provenance, plus the coverage ledger and capabilities. Never share a cookie
  jar or browser profile.
3. Read existing immutable findings before one cheap triage pass. Reuse only
   evidence-backed facts from the matching fingerprint.

## Solve

Read [references/runtime.md](references/runtime.md) and
[references/workflow.md](references/workflow.md). Track every endpoint as the
full tuple `endpoint × method × input location × parameter × technique` in
`coverage.json`; record transitions with `record_coverage.py`. Input locations
include query, form, JSON, headers, cookies, path components, browser storage,
and WebSocket/message payloads.

- Save prepared-request evidence and undecoded response entity-body bytes;
  provenance retains parsed status/headers, redirects, length, timing, cookie
  changes, and parsing/tool errors. These are not literal HTTP wire captures.
- Record normalized requests through the common attempt ledger before sending;
  unchanged failures are rejected. After two no-progress attempts, change the
  hypothesis/strategy rather than repeat it.
- Maintain acquired capabilities (authentication bypass, file read, SSRF,
  injection, or execution) in `web/capabilities.json`, separate from the flag
  objective. Once a capability exists, choose the shortest evidence-backed path
  to the flag.
- Only advance `promising` to `confirmed` with a provenance-verified target
  response entity body under this session's `web/responses/`. `confirmed` and
  `discarded` are terminal.

Use [assets/request.py](assets/request.py) for ordinary HTTP probes; it uses a
session-owned `requests.Session`, explicit timeout, an exact-origin check,
prepared/entity-body evidence, and the normalized attempt guard. Use the same constraints for
Playwright or WebSocket work, passing this session's browser profile.

## Finish

Default `mode: race` reports the first non-echoed flag attributable to a
recorded authorized target response immediately. Use the web verifier; it
rejects shell files, summaries, errors, and unprovenanced artifacts before it
delegates candidate checking:

```text
python3 <skill>/scripts/verify_web_flag.py --workspace <workspace> \
  --output web/responses/<response>.body
```

For `mode: strict`, submit two clean target response files and add `--strict`.
Read [references/state-and-verification.md](references/state-and-verification.md).
Stop polishing once verification succeeds; then write a short `WRITEUP.md` or
report the terminal blocker with workspace and entity-body evidence paths.
