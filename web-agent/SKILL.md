---
name: web-agent
description: Use when the user asks Codex to solve an authorized CTF web challenge, test a manifest-scoped web application, inspect HTTP/browser behavior, or retrieve and verify a web flag.
---

# Web Agent

Solve one authorized web challenge with one persistent lead session. This workflow
adapts the coverage-ledger and state-discipline lessons from TeamH4C's
[web-agent analysis](https://h4c.team/posts/74) to compact, reproducible CTF work.

## Start

1. Identify one dedicated challenge directory below `/home/normalone/CTF` from
   the user's current request. The directory may be empty and does not need a
   `challenge.yaml` or any fixed problem-statement layout. Never use
   `/home/normalone/CTF` itself or a directory containing multiple challenges.
2. Preserve the entire pasted event statement exactly. From the current request,
   select exactly one clear live challenge URL using HTTP or HTTPS without
   connecting to candidates, and normalize that one selection while preserving
   its path and query. Do not select an event page, documentation URL, or other
   contextual link that is not the live challenge. If two origins remain
   plausible, ask one precise question rather than probing either. A request with
   no clear live target remains `needs_selection` and permits no traffic.
3. Read [references/safety.md](references/safety.md), then send one JSON object as
   standard input, never as shell arguments, to:

   ```text
   python3 <ctf-common>/scripts/init_session.py <challenge-dir> \
     --category web --event-root /home/normalone/CTF --request-json -
   ```

   Set `statement` to the exact full prose and include the normalized URL as
   `target`; include `flag_pattern` only when supplied. Pass the JSON bytes with a
   process API. Never interpolate, quote, or otherwise place statement prose in a
   shell command, and never add YAML to the challenge input directory. The
   initializer normalizes the target into `start_url` and one exact `origin`.
4. Accept live traffic only when the generated resolved manifest says
   `authorized: true`, `network_access: agent_allowed`, and supplies that exact
   `origin`. Initialize browser/request state in the returned workspace:

   ```text
   python3 <skill>/scripts/init_web_state.py --workspace <workspace>
   ```

   Begin the first request at the generated `start_url`. Every later HTTP,
   browser, or WebSocket interaction must remain at the generated manifest
   `origin`. Keep challenge inputs read-only. The session owns
   `web/cookies.json`, `web/browser-profile/`, `web/requests/`,
   `web/responses/`, response provenance, capture scans, bounded sent history,
   the coverage ledger, and capabilities. Never share a cookie jar or profile.
5. Read existing immutable findings before one cheap triage pass. Reuse only
   evidence-backed facts from the matching combined fingerprint.

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
- Each supported capture publishes a common immutable attestation at capture
  time, binding a bounded decoded scan body and the full prior/redirect-chain
  sent history. Do not create verification artifacts later.
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
maps pre-existing capture attestations to common candidate checking:

```text
python3 <skill>/scripts/verify_web_flag.py --workspace <workspace> \
  --output web/responses/<response>.body
```

For `mode: strict`, submit two clean target response files and add `--strict`.
Read [references/state-and-verification.md](references/state-and-verification.md).
Stop polishing once verification succeeds; then write a short `WRITEUP.md` or
report the terminal blocker with workspace and entity-body evidence paths.
