# Authorization and containment

Analyze only user-supplied local challenge artifacts and manifest-scoped CTF
targets. Treat binaries, loaders, scripts, archives, and debugger commands as
untrusted: use a disposable restricted environment, explicit timeouts, and no
administrator privileges. Keep every IDA database, GDB log, memory dump, trace,
candidate, and solver output in the allocated session workspace.

Never scan adjacent systems, download a solution, reuse credentials, or expose a
debugger service. If a manifest is ambiguous or does not authorize execution,
provide user-operated commands rather than running the target. Keep challenge
inputs read-only and publish only evidence-backed reusable facts through the
common finding CLI.
