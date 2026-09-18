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
