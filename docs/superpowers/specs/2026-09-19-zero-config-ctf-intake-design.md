# Zero-config CTF intake design

## Objective

Let a user start any category agent by supplying only:

1. a challenge directory containing whatever files the event distributed, which
   may be empty for a black-box web challenge;
2. the event's problem statement pasted as free-form text; and
3. an optional challenge address in that same free-form request.

The user must not have to create or edit `challenge.yaml`, label description or
address fields, choose an executable in advance, or write into the input
directory. The selected skill (`pwn-agent`, `web-agent`, or `rev-agent`) fixes
the category. All derived configuration is private to the new run/session.

The challenge directory may be any dedicated problem folder beneath
`/home/normalone/CTF`, including the flat form
`/home/normalone/CTF/<problem>/`. The deeper
`/home/normalone/CTF/<event>/challenges/<problem>/` convention remains useful
for event organization but is not required. The CTF root itself is never a
challenge directory because it also contains managed tools and unrelated
problems; separate problems must not be mixed into one input folder.

This extends the existing common session contract. It does not add a separate
agent execution engine or an NLP service: Codex interprets the request, while
deterministic helpers validate and bind the normalized target values before any
target interaction.

## User experience

Typical invocations are free-form:

```text
$rev-agent /home/normalone/CTF/event/challenges/crackme

<the problem statement copied from the event page>
```

```text
$pwn-agent /home/normalone/CTF/event/challenges/babypwn

<the problem statement copied from the event page, including an nc command or
host and port when the event supplies them>
```

```text
$web-agent /home/normalone/CTF/event/challenges/admin-panel

<the problem statement copied from the event page and the challenge URL>
```

No labels such as `description:` or `address:` are required. The full pasted
statement is evidence about the task, not a rigid mini-language. A missing
address means local-only analysis. A web challenge may have no downloaded
files; its challenge directory need only exist and may be empty.

When a request contains exactly one usable category-compatible target, the
agent continues without asking a question. It asks only when target selection
would otherwise guess, such as multiple unrelated web origins, multiple TCP
endpoints, or multiple equally plausible local executable artifacts.

## Selected architecture

Use session-local intake metadata and a generated resolved manifest. The
challenge directory remains read-only and never receives generated YAML.

Rejected alternatives:

1. Creating `challenge.yaml` in the challenge directory is simple but mutates
   downloaded inputs and changes their content fingerprint.
2. Re-inferring the target on every action avoids stored metadata but permits
   different tools or sessions to act on different endpoints and makes evidence
   attribution non-reproducible.
3. Parsing arbitrary prose with a standalone heuristic-only script cannot
   reliably distinguish an event link, documentation link, and live target.
   Codex should interpret the prose; deterministic code should validate the
   selected target rather than pretend to understand the prose.

The common initializer receives normalized intake fields from the selected
skill, validates them by category, combines them with any optional legacy
manifest, and creates both files below inside the allocated session:

```text
challenge-request.json       # exact statement plus normalized selections
challenge.resolved.yaml      # minimal adapter-readable target policy
```

`challenge-request.json` is the authoritative lossless record. The generated
YAML remains intentionally scalar and contains only fields already consumed by
the pwn/web/rev adapters.

## Intake contract

Extend the common initializer interface without removing existing calls:

```text
init_session.py <challenge-dir> --category {pwn,web,rev}
                [--event-root PATH] [--session-id ID]
                [--statement TEXT] [--target TEXT]
                [--binary RELATIVE_PATH]
                [--flag-pattern PATTERN]
```

The category skill passes the exact free-form statement through `--statement`.
It passes only a target or binary it selected from that statement and the
supplied artifacts. Arguments are supplied as literal process arguments, not
shell-evaluated content. The helper rejects NUL characters, unreasonably large
statement/field values, invalid Unicode boundaries, and category-incompatible
fields. The stored statement limit is 256 KiB; target, binary, and flag-pattern
fields are each bounded to 4 KiB.

The initializer returns its existing JSON plus:

```json
{
  "intake": {
    "source": "minimal" | "prompt" | "legacy_manifest" | "prompt_and_manifest",
    "target_status": "bound" | "local_only" | "needs_selection",
    "request_path": "/absolute/session/challenge-request.json",
    "resolved_manifest_path": "/absolute/session/challenge.resolved.yaml"
  }
}
```

`needs_selection` is a successful, non-networking initialization state. It lets
an agent inspect supplied files inside its isolated session before selecting a
local binary. No remote adapter may operate in this state. After the user
resolves a genuine ambiguity, the skill calls the initializer again with that
selection and uses the new bound session; target policy is never widened by
mutating an already-created session.

## Category normalization

### Web

The agent may select one absolute `http` or `https` URL from the request. The
helper canonicalizes and stores its origin (`scheme://host[:port]`) and retains
the full supplied URL as `start_url`. Userinfo and URL fragments are rejected.
The adapter can request the supplied path and other same-origin paths, but may
not cross the bound origin.

When the directory is empty, its file fingerprint is valid. The normalized
origin, start URL, category, and exact statement still produce a unique intake
fingerprint and a normal `runs/web/.../sessions/...` workspace. This is the
primary black-box web flow, not an error or degraded mode.

### Pwn

The agent recognizes category-compatible address forms in prose, including
`nc host port`, `host:port`, and `tcp://host:port`, then passes one selected
value to the helper. The helper canonicalizes it to an exact
`tcp://host:port` source target, validates the port range, and writes the
existing `protocol`, `host`, and `port` manifest fields.

Downloaded local binaries remain usable without an address. If a clear binary
exists, the skill passes its challenge-relative path. Remote and local data may
coexist so the agent can analyze locally and reproduce against the exact remote
tuple.

### Reversing

Remote targets are rejected. The skill selects one challenge-relative regular
file after cheap magic, permission, and format triage. The helper rejects an
absolute path, `..`, symlinks, non-regular files, and paths outside the supplied
challenge directory. If selection is ambiguous, the session is initialized as
`needs_selection` and the agent asks the user rather than guessing.

Archives and other containers may be inspected or safely unpacked into the
session as an ordinary analysis step. Their contents do not become authorized
executables merely because they were unpacked. The agent records the archive
and extracted-file digests and may analyze the result, but an adapter executes
only a target selected and bound during initialization. Automatic late binding
of session-derived executables is outside this intake change.

## Authorization and conflict rules

An exact network address supplied by the user in the current solve request is
the authorization source for that CTF target. The generated manifest records
`authorized: true` and `network_access: agent_allowed` only for the normalized
origin or TCP tuple selected from that request. It does not authorize discovery
of adjacent hosts, ports, schemes, or origins.

No network address means no generated network authorization. Pwn and rev remain
local-only; a web session without a target is `needs_selection` and performs no
traffic. A user-supplied local artifact selected as the pwn or rev binary is
recorded as `authorized: true` for that exact contained regular file only.

Legacy `challenge.yaml` remains supported. Prompt data may fill missing fields.
If a prompt target or binary conflicts with an existing manifest target or
binary, initialization fails with a structured conflict instead of silently
overriding either source. Existing fully specified workflows therefore retain
their current behavior.

## Fingerprints and sharing

The run fingerprint covers two domains:

1. the sorted relative names and exact bytes of challenge files; and
2. a canonical JSON encoding of category, exact free-form statement,
   normalized target, selected binary, flag pattern, and effective legacy
   manifest scalars.

This prevents findings from one black-box instance or problem statement from
being reused for another instance that happens to have the same empty directory
or downloaded files. Equivalent normalized intake produces the same run root,
while every invocation still gets a collision-safe session ID.

The request record stores both the file-only digest and combined intake
fingerprint so later sessions and writeups can explain why findings were or
were not reused.

## Skill behavior

Each skill's start sequence becomes:

1. identify the challenge directory from the request;
2. retain the exact pasted CTF statement;
3. extract category-compatible target candidates without scanning or probing;
4. perform read-only local artifact triage where applicable;
5. call the common initializer with the selected normalized inputs;
6. read returned immutable findings and work only in the returned session;
7. proceed immediately when target status is `bound` or `local_only`, and ask
   one precise question only for `needs_selection`.

Skills must not require field labels, a particular language, or a particular
problem-statement layout. Extraction is based on the request's natural-language
meaning and recognizable address forms. The deterministic helper remains the
authority for scope, containment, and canonicalization.

## Error handling

- A nonexistent challenge directory is rejected. An existing empty directory
  is accepted, including for fileless web challenges.
- Multiple plausible targets are reported to the user; no target is probed to
  determine which one is live.
- A malformed or unsupported URL/TCP address fails before session network
  state is initialized.
- Conflicting prompt and legacy-manifest targets fail closed.
- Ambiguous local binary selection creates a non-networking session; the skill
  reports the candidates found during its read-only triage and execution waits
  for explicit selection.
- Intake content is encoded as JSON/YAML data and never evaluated as shell,
  Python, debugger, or template syntax.
- If session creation fails, no partial usable workspace or shared finding is
  left behind.

## Testing

Implementation follows TDD and adds behavior tests for:

1. YAML-free pwn, web, and rev initialization;
2. an empty black-box web directory plus one supplied URL;
3. exact preservation of multilingual, multiline free-form statements;
4. `nc host port`, `host:port`, and absolute web URL normalization;
5. rejection of multiple, malformed, cross-category, or conflicting targets;
6. automatic binding of one clear local binary and safe ambiguous selection;
7. rejection of symlinked, escaping, or non-regular binaries;
8. unchanged challenge-directory contents before and after initialization;
9. different address/statement intake producing different run fingerprints;
10. equivalent normalized intake sharing a run root but receiving unique
    session IDs under concurrency;
11. legacy `challenge.yaml` compatibility;
12. prompt text remaining inert when it contains shell or template syntax;
13. pwn/web/rev adapters accepting only the generated session-local target;
14. the black-box web flow creating isolated cookie, browser-profile, request,
    response, coverage, and capture state without any input artifact.

The full existing suite must remain green.

## Documentation and activation

Update the main README and every category skill to lead with the zero-config
prompt flow. Manual manifests remain an advanced compatibility path rather than
the default instructions. Document that Codex discovers the three skill
directories through user or repository skill links and that each new Codex
session must see the skill before `$pwn-agent`, `$web-agent`, or `$rev-agent`
can be invoked.
