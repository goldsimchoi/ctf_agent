# Analysis before attack

`analysis.md` in the session workspace is the working model of the challenge.
Update it as facts arrive. The verifier refuses a solve while any of its four
sections is missing or still only the template comment.

## Flag location

Start here, because it defines the goal and the barrier:

- Where does the real flag live on the remote target? Typical places are an
  environment variable, a file such as `/flag` or `/app/flag.txt`, a database
  row, an admin-only page, or a cookie held by an admin bot.
- What prevents an ordinary user from reading it? Examples: an authentication
  check, a role check, a path filter, a sandbox, or "only the bot visits it".
- In supplied source, the flag value is a placeholder. Note where it is read,
  not what it says.

## Attack surface

List routes with their methods and every input each one reads:

- query, form, JSON body, headers, cookies, path components, uploaded files,
  browser storage, and WebSocket or message payloads;
- framework middleware, proxies, and parsers in front of the handler;
- mismatches where a check reads one input and the handler reads another (for
  example, middleware validates `?id=` while the handler reads `id` from JSON).

For black-box targets, build the same list from recorded responses: links,
forms, JavaScript bundles, API calls, and cookies set by the server.

## Vulnerability

State the flaw and its evidence:

- the sink (query, template, file path, deserializer, command, redirect, bot
  visit) and the exact `file:line` or `web/responses/` path that shows it;
- the filters or checks in front of it, and why they do not stop the input;
- whether the hypothesis is confirmed by a response or still a hypothesis.

## Exploit path

Write the ordered steps from a fresh, unauthenticated session to the flag:

1. each request or action;
2. the capability it earns (session, token, file read, SSRF, execution);
3. how the last step reaches the flag location above.

If a step depends on state (login cookie, CSRF token, WebSocket connection),
say where that state is held so a fresh session can reproduce the path.

## Habits that avoid known failure modes

- **Missed input locations:** after each response, add new endpoints and inputs
  to `coverage.json`. Re-check entries marked `discarded` whose test was weak.
- **Capability not applied:** once a primitive works, aim it at the flag
  location immediately instead of trying more bypasses.
- **Truncated observation:** decide from the full saved body under
  `web/responses/`, not from terminal output or a summary.
- **Wrong success:** confirm that the evidence came from the remote target and
  not from this machine, the lab, or the supplied files.
