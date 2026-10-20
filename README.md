# ctf_agent

Skills for authorized CTF pwn, web, and reversing challenges. They run in Codex
and in Claude Code, which both read the same `SKILL.md` format.

## Quick start

Put each challenge in a flat directory under `/home/normalone/CTF`, register the
skills, and enable the managed tools for the current shell:

```bash
mkdir -p /home/normalone/CTF/babypwn
cp ~/Downloads/chall /home/normalone/CTF/babypwn/
bash tools/install-ctf-skills.sh        # Codex: ~/.agents/skills
CTF_SKILLS_HOME=~/.claude/skills bash tools/install-ctf-skills.sh   # Claude Code
source /home/normalone/CTF/.tools/env.sh
```

Then start the client from the challenge root:

- **Codex:** `codex -C /home/normalone/CTF`, then `/skills` to confirm that
  `pwn-agent`, `web-agent`, and `rev-agent` were discovered.
- **Claude Code:** `cd /home/normalone/CTF && claude`; the skills appear in the
  skill list. The `gdb` and `idalib` MCP servers are registered separately with
  `claude mcp add`.

If a skill does not appear immediately, start a fresh session after running the
installer.

Paste the real event listing directly into the prompt. You never need to write
YAML. Invoke a skill by name (`$pwn-agent` in Codex, `/pwn-agent` in Claude
Code). For example:

```text
pwn-agent The event listing says: "Our baby note service is finally ready for
production. Can you read the flag? Connect with nc pwn.example.ctf 31337."
The supplied binary is /home/normalone/CTF/babypwn/chall. Solve this authorized
challenge and return a verified flag with evidence.
```

```text
rev-agent The event listing says: "The license checker accepts exactly one
secret activation key. Find it." The supplied program is
/home/normalone/CTF/keycheck/keycheck. Solve this authorized reversing
challenge and return a verified flag with evidence.
```

A black-box web challenge does not need a downloaded artifact. Create an empty
problem directory, then paste the listing prose and its authorized endpoint:

```bash
mkdir -p /home/normalone/CTF/login-portal
```

```text
web-agent The event listing says: "We replaced passwords with a simpler login
flow. Can you reach the admin flag?" The authorized challenge endpoint is
https://login.example.ctf/. Use /home/normalone/CTF/login-portal as the empty
challenge directory, solve it, and return a verified flag with evidence.
```

The web skill treats a flag found only in supplied files or a local Docker lab
as a placeholder; it requires the real flag from the remote challenge origin.
For an out-of-band challenge (bot, XSS, blind SSRF), add your own receiver URL
to the prompt so the skill can deliver and poll results there.

The skills keep supplied inputs unchanged. Generated state, transcripts, and
evidence go under the sibling `/home/normalone/CTF/runs/` directory, not inside
the problem directory.

Use these skills only with user-supplied challenge artifacts and explicitly
authorized CTF endpoints.
