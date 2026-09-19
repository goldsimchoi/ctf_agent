# ctf_agent

Codex skills for authorized CTF pwn, web, and reversing challenges.

## Quick start

From this repository, put each challenge in a flat directory under
`/home/normalone/CTF`, register the skills, enable the managed tools for the
current shell, and start Codex:

```bash
mkdir -p /home/normalone/CTF/babypwn
cp ~/Downloads/chall /home/normalone/CTF/babypwn/
bash tools/install-ctf-skills.sh
source /home/normalone/CTF/.tools/env.sh
codex -C /home/normalone/CTF
```

Run `/skills` in Codex to confirm that `pwn-agent`, `web-agent`, and
`rev-agent` were discovered. If they do not appear immediately, start a fresh
Codex session after running the installer.

Paste the real event listing directly into the prompt. You never need to write
YAML. For example:

```text
$pwn-agent The event listing says: "Our baby note service is finally ready for
production. Can you read the flag? Connect with nc pwn.example.ctf 31337."
The supplied binary is /home/normalone/CTF/babypwn/chall. Solve this authorized
challenge and return a verified flag with evidence.
```

```text
$rev-agent The event listing says: "The license checker accepts exactly one
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
$web-agent The event listing says: "We replaced passwords with a simpler login
flow. Can you reach the admin flag?" The authorized challenge endpoint is
https://login.example.ctf/. Use /home/normalone/CTF/login-portal as the empty
challenge directory, solve it, and return a verified flag with evidence.
```

The skills keep supplied inputs unchanged. Generated state, transcripts, and
evidence go under the sibling `/home/normalone/CTF/runs/` directory, not inside
the problem directory.

Use these skills only with user-supplied challenge artifacts and explicitly
authorized CTF endpoints.
