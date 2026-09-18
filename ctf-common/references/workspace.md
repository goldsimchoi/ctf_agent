# Common CTF workspace

Initialize every challenge from its own directory under an event. The helper
creates `runs/<category>/<slug>-<fingerprint12>/sessions/<session-id>` and
never shares mutable session state. Session IDs are collision-safe by default;
an explicit ID must be a safe single path component and cannot replace an
existing session.

Use `init_session.py` with `--category pwn`, `web`, or `rev`. It copies a
minimal resolved manifest into the session and creates `artifacts`, `logs`,
and `transcripts`. New sessions return valid shared findings from the matching
category/challenge fingerprint only.

## Zero-config intake

A challenge may be a dedicated flat problem directory directly below the event
root or an event-organized `challenges/<problem>` directory. Pass the managed
event root with `--event-root`; the root itself is never accepted as a
challenge. The initializer does not write to the challenge directory, and an
empty directory is valid for a fileless web challenge.

The normal agent transport is one bounded JSON object on standard input:

```sh
python3 init_session.py /home/normalone/CTF/event/problem \
  --event-root /home/normalone/CTF --category web --request-json -
```

```json
{
  "statement": "the exact multiline event statement",
  "target": "https://box.example/start?q=1",
  "binary": "optional/challenge-relative-file",
  "flag_pattern": "FLAG\\{[^}]+\\}"
}
```

All four keys are optional strings; unknown keys, non-string values, control
characters, invalid category fields, and oversized input are rejected. The
statement is limited to 256 KiB and each other field to 4 KiB. A no-follow
regular-file path can replace `-`. The individual `--statement`, `--target`,
`--binary`, and `--flag-pattern` options are also available, but cannot be
mixed with `--request-json`.

Every allocated session contains an immutable `challenge-request.json` with
the exact statement, normalized selection, effective scalar manifest,
file-only fingerprint, and combined fingerprint. The sibling
`challenge.resolved.yaml` contains only safely encoded adapter fields; free-form
statement text is never copied into YAML. A selected binary must be a regular,
non-symlink file reached through a challenge-relative no-follow path.

The returned `intake.target_status` is:

- `bound`: an exact web origin, TCP tuple, or local binary is selected;
- `local_only`: pwn intake has no network address or selected binary; or
- `needs_selection`: web or reversing intake needs an explicit compatible
  target before any target interaction.

`intake.source` reports `minimal`, `prompt`, `legacy_manifest`, or
`prompt_and_manifest`. Prompt fields can fill missing legacy manifest values,
but conflicting targets, binaries, categories, or authorization policy fail
closed. Web targets bind one HTTP(S) origin, pwn targets bind one TCP tuple,
and reversing intake rejects network targets.

The run directory uses a combined fingerprint: the file-only challenge digest
plus canonical JSON for the category, exact statement, normalized target,
selected binary, flag pattern, and effective legacy scalars. Equivalent
normalized intake shares a run root while each invocation still receives a
new collision-safe session ID. A different statement or target therefore
cannot reuse findings from an otherwise identical empty or file-backed input.

Publish only evidence files inside the originating session with
`publish_finding.py`. Findings are atomically created JSON records under the
common workspace's `shared/findings/<session-id>/`; they are never updated.

Use `record_attempt.py` after each meaningful target interaction. Equivalent
attempt signatures are rejected unless `--progress` identifies a new fact,
primitive, endpoint, clue, or flag candidate. Two consecutive no-progress
attempts (or a manifest wall-time expiry) return exit code 3 so the strategy
must change.

`verify_flag.py` defaults to race mode: one non-echoed candidate in a valid
capture is sufficient. `--strict` requires the same non-echoed candidate in
two distinct valid captures. Both modes reject a candidate present in `--sent`
input; an unverified result exits 2. Each command prints exactly one JSON
object.

## Capture attestation contract

The common verifier never attributes arbitrary files to a target. Every
`--output` needs a matching repeatable `--attestation` JSON object, and every
capture needs sent-input evidence supplied through `--sent`. The attestation
schema is:

```json
{
  "schema_version": 1,
  "workspace": "/absolute/session/path",
  "session_id": "web-...",
  "category": "web",
  "capture_id": "unique-run-id",
  "source_target": "https://authorized-target.example/",
  "output": {"path": "/absolute/session/path/transcripts/run.output", "sha256": "..."},
  "sent": {"path": "/absolute/session/path/transcripts/run.sent", "sha256": "..."}
}
```

The JSON record itself must be atomically created as
`artifacts/captures/<capture-id>.json` via
`publish_capture_attestation(workspace, record)`, then supplied by path with
`--attestation`. All record, output, and sent paths must be regular,
non-symlink files inside the supplied canonical session workspace. The common
verifier opens each file once through descriptor-relative `O_NOFOLLOW` walks;
all digests, candidate matching, and echo checks use exactly those bytes. It
also checks session/category identity, one source target, unique capture IDs,
canonical relative output paths, and `(st_dev, st_ino)` identities, so hardlink
or repeated-output aliases cannot satisfy strict reproduction.

A missing, malformed, unreadable, or invalid attestation yields
`candidate_only` rather than a verified flag; it is not a CLI syntax error.
Category adapters are the authority that binds `source_target` to their
authorized interaction. The common layer validates record integrity and
containment, but cannot authenticate a malicious local writer. Adapters must
create one immutable capture record per target interaction and pass its JSON
file with `--attestation`.

Every artifact read by the common layer (capture records, outputs, sent input,
shared finding records, and shared evidence) is limited to **4 MiB**. The
reader checks `fstat` before allocation and its cumulative streamed byte count,
so sparse or growing files cannot exceed this bound. Oversized verification
artifacts yield `candidate_only`; oversized shared records or evidence are
skipped with a reported reason.

One verification request accepts at most 16 `--output`, 16 `--sent`, and 16
`--attestation` paths. It retains at most **8 MiB** across unique opened
`(st_dev, st_ino)` artifacts; repeated references to the same opened file reuse
the first FD snapshot rather than counting or retaining its bytes again. A
request exceeding either limit yields `candidate_only` with
`verification_request_exceeds_budget`.
