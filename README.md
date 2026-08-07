# ctf_agent

Codex skill and supporting design documents for solving authorized CTF pwnable challenges.

## Contents

- `pwn-agent/`: installable Codex skill, scripts, references, and templates
- `docs/specs/`: original agent design
- `docs/plans/`: debugger integration plan
- `tests/`: deterministic tests for the skill scripts

## Install

Copy `pwn-agent` into your Codex skills directory:

```powershell
Copy-Item -Recurse .\pwn-agent "$env:USERPROFILE\.codex\skills\pwn-agent"
```

The runtime reference contains local IDA, WSL, and pwndbg paths from the environment for which this skill was built. Adjust those paths before using the skill on another machine.

## Test

```powershell
python -m unittest discover -s tests -v
```

## Safety

Use this skill only with user-supplied challenge artifacts and explicitly authorized CTF endpoints. Challenge binaries, flags, transcripts, debugger databases, and run workspaces are intentionally not included in this repository.
