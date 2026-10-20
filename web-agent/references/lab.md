# Local lab

A challenge often ships its source with a `Dockerfile` or `docker-compose.yml`.
Running it locally is a fast way to read logs, add debugging, and try payloads
without spending remote attempts. The lab is for building an exploit, not for
getting the flag.

## Rules

- Build and run the supplied container from a copy in the session workspace,
  never from the challenge input directory itself.
- Save lab outputs (container logs, local responses, exploit runs) under
  `<workspace>/web/lab/`. The web verifier treats any flag-shaped string found
  there as a known placeholder and rejects it from remote evidence.
- Do not read the flag from the container or image: no `docker exec`,
  `docker cp`, mounted volumes, image layers, or reading the value from source.
  Reading it that way skips the vulnerability and proves nothing.
- A local exploit run may print the local placeholder. That confirms the exploit
  path, and nothing more.
- Do not register a local URL as the session target. The verifier reports
  `lab_only` for loopback, this machine's own addresses, and Docker bridge
  networks.

## From lab to remote

1. Write the working exploit as `exploit.py` taking the base URL as a parameter.
2. Note any lab-only assumptions: debug flags you enabled, a seeded admin
   account, a changed secret, or a different hostname the bot uses.
3. Replay the exploit's requests against the manifest origin through
   `assets/request.py`, so the remote responses are recorded with provenance.
4. If the remote behaves differently, record the difference in `notes.md` and
   update `analysis.md` before changing the exploit.

## When there is no remote URL

If the user supplied only source or a Docker setup, ask for the remote instance
URL. Until then, report "exploit ready locally, remote not run" and never
present a lab value as a flag.
