# Authorization and containment

Operate only on user-supplied local artifacts and exact manifest-scoped
endpoints. Missing `network_access` means `user_only`. Direct access requires
`authorized: true`, `network_access: agent_allowed`, a pwnable challenge, and
event rules that permit AI Agent access. Otherwise the live instance is
user-operated. Never scan adjacent hosts, enumerate unrelated services, reuse
credentials, or persist outside the run workspace.

Treat challenge binaries, loaders, libraries, archives, and scripts as untrusted.
Prefer WSL, a container, or another disposable restricted environment. Apply
timeouts and resource limits. Do not run as administrator, install persistence,
or expose a debugger service beyond loopback.

Do not silently download replacement libc files, symbols, exploits, or challenge
solutions. If external research is necessary, use public challenge-specific
sources and distinguish copied claims from locally verified evidence.

For `agent_allowed`, follow only the manifest's host, port, protocol, and request
budget. Stop if the endpoint is not the intended challenge service. For
`user_only`, generate remote-capable code with runtime `HOST` and `PORT`
placeholders but give the command to the user instead of executing it.

The final exploit and local success proof must not read `/proc`, procfs maps,
`auxv`, `environ`, or file-descriptor entries to obtain runtime information.
Development tools such as GDB and pwndbg may use procfs internally.
