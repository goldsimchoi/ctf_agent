---
name: web-agent
description: Use when the user asks to solve an authorized CTF or wargame web challenge, test a manifest-scoped web application, inspect HTTP/browser behavior, or retrieve and verify the real flag from the remote challenge.
---

# Web Agent

Solve one authorized web challenge with one persistent lead session. The design
follows TeamH4C's [web-agent analysis](https://h4c.team/posts/74): agents fail by
missing input locations, losing session state, earning a capability without
applying it to the flag, repeating a wrong hypothesis, judging from truncated
output, and declaring success from evidence that did not come from the target.
Each phase below closes one of those gaps.

**The objective is the real flag from the remote challenge origin.** A
placeholder such as `flag{fake}` from supplied source, a Dockerfile, or a local
container proves only that an exploit works locally. It is never a solve, and the
verifier rejects it.

## Phase 0: Intake

1. Identify one dedicated challenge directory below `/home/normalone/CTF` from
   the user's current request. It may be empty and needs no `challenge.yaml`.
   Never use `/home/normalone/CTF` itself or a directory holding several
   challenges.
2. Preserve the entire pasted event statement exactly. Select exactly one clear
   live challenge URL (HTTP or HTTPS) without connecting to candidates, keeping
   its path and query. Do not select event pages, documentation, or other
   context links. If two origins remain plausible, ask one precise question. If
   only source or a Docker setup was supplied and no remote instance URL is
   given, ask for the instance URL; local work may proceed in the lab meanwhile.
3. Read [references/safety.md](references/safety.md), then send one JSON object
   on standard input, never as shell arguments, to:

   ```text
   python3 <ctf-common>/scripts/init_session.py <challenge-dir> \
     --category web --event-root /home/normalone/CTF --request-json -
   ```

   Set `statement` to the full prose and `target` to the normalized remote URL;
   add `flag_pattern` only when supplied, and `callback` only when the user gives
   their own out-of-band receiver URL. Pass the JSON bytes with a process API.
4. Accept live traffic only when the resolved manifest says `authorized: true`,
   `network_access: agent_allowed`, and gives that exact `origin`. Then run:

   ```text
   python3 <skill>/scripts/init_web_state.py --workspace <workspace>
   ```

   This creates the session-owned cookie jar, browser profile, evidence
   directories, coverage ledger, `web/lab/`, and `analysis.md`. Read existing
   immutable findings for the same fingerprint before triage.

## Phase 1: Analyze before attacking

Fill `analysis.md` as you learn; the verifier refuses a solve while any section
is empty. Follow [references/analysis.md](references/analysis.md).

- **Flag location first.** Find where the real flag lives on the target (env
  variable, file, DB row, admin-only page, bot cookie) and what normally stops an
  ordinary user from reading it. That barrier is the challenge.
- **White-box (source supplied):** trace each route from input to sink: which
  middleware reads which input, which handler reads which input (they can
  differ), where filters run, and what the sink does. Cite `file:line`.
- **Black-box:** map routes, JavaScript bundles, forms, API calls, cookies,
  storage, and WebSocket traffic from recorded responses before fuzzing.
- Record every endpoint × method × input location × parameter × technique tuple
  in `coverage.json` with `record_coverage.py`. Input locations include query,
  form, JSON, headers, cookies, path components, browser storage, and
  WebSocket/message payloads. Add newly seen endpoints after every response.

## Phase 2: Build the exploit in the lab (optional)

When source or a Dockerfile is supplied, a local copy is the fastest place to
iterate. Follow [references/lab.md](references/lab.md):

- Run the container and save its outputs under `<workspace>/web/lab/`.
- Do not read the flag out of the container or image (`docker exec`, `docker cp`,
  mounted volumes, image layers, or source files). Only the exploit's HTTP path
  counts, and even then a local flag is a placeholder.
- When the exploit works locally, write it as `exploit.py` that takes the base
  URL as a parameter. A lab success means "exploit ready", not "solved".

## Phase 3: Attack the remote target

Use [assets/request.py](assets/request.py) for every target request. It keeps
one `requests.Session`, enforces the exact origin, records prepared requests and
undecoded response bodies, and guards against repeating an unchanged attempt.
Follow [references/workflow.md](references/workflow.md):

- Test the cheapest hypothesis that separates two explanations. Compare status,
  body, redirects, timing, length, cookies, and parser or tool errors; a tool
  error is not a server response.
- Read the full saved body under `web/responses/` before concluding; terminal
  output and summaries are truncated indexes, not evidence.
- Keep multi-step state (login, CSRF token, WebSocket or DDP connection) inside
  one session or one script that holds the connection.
- When a capability appears (auth bypass, file read, SSRF, injection, code
  execution), record it in `web/capabilities.json` and immediately aim it at the
  flag location from `analysis.md`. Do not keep broadening probes.
- After two attempts with no new fact, stop and write a short reset note in
  `notes.md` separating observed facts from interpretations, then pick a new
  hypothesis from the facts only. A short-lived explorer may be used for a
  genuinely distinct hypothesis, with facts-only handoff and its own session.
- For bot, XSS, or blind SSRF challenges, deliver results to the user's declared
  `callback` receiver and poll it with `request.py`. With no callback declared,
  ask the user for one; never pick a third-party receiver yourself.

When using Burp Suite, follow [references/burp.md](references/burp.md). Burp
requests use the same session, origin check, ledger, and evidence.

## Phase 4: Verify and finish

Only the verifier decides whether the challenge is solved:

```text
python3 <skill>/scripts/verify_web_flag.py --workspace <workspace> \
  --output web/responses/<response>.body
```

Read [references/state-and-verification.md](references/state-and-verification.md).
Report according to the verifier status:

- `verified`: report the flag first, then the workspace, the evidence body, and
  `WRITEUP.md` with vulnerability, code or response evidence, and exploit steps.
- `lab_only`: the manifest origin is this machine or a local container. Say the
  exploit works locally, and ask for or rerun against the remote instance.
- `candidate_in_supplied_files` or `candidate_matches_lab_flag`: the value is a
  placeholder. Continue against the remote target; do not report it as a flag.
- `analysis_incomplete`: fill the listed sections from evidence, then verify.
- Anything else: report the terminal blocker with the strongest evidence paths.
  Never present partial progress, a local flag, or an unverified string as the
  solution.

Use `--strict` with two clean target responses when the manifest says
`mode: strict`. Stop polishing once verification succeeds.
