#!/usr/bin/env bash
# Register the repository's user-facing CTF skills without replacing user data.
set -euo pipefail

REPOSITORY_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
SKILLS_HOME=${CTF_SKILLS_HOME:-"$HOME/.agents/skills"}
SKILLS=(pwn-agent web-agent rev-agent)
STATUSES=()

# Validate every repository source before creating the destination root.
for skill in "${SKILLS[@]}"; do
    source_directory="$REPOSITORY_ROOT/$skill"
    if [[ ! -d "$source_directory" || ! -f "$source_directory/SKILL.md" ]]; then
        printf 'missing skill source or SKILL.md: %s\n' "$source_directory" >&2
        exit 1
    fi
done

mkdir -p -- "$SKILLS_HOME"

# Refuse all collisions up front so a failed invocation creates no partial set.
for skill in "${SKILLS[@]}"; do
    source_directory="$REPOSITORY_ROOT/$skill"
    destination="$SKILLS_HOME/$skill"
    if [[ -L "$destination" ]]; then
        resolved_destination=$(readlink -f -- "$destination" 2>/dev/null || true)
        resolved_source=$(readlink -f -- "$source_directory")
        if [[ "$resolved_destination" != "$resolved_source" ]]; then
            printf 'refusing to replace unrelated symlink: %s\n' "$destination" >&2
            exit 1
        fi
    elif [[ -e "$destination" ]]; then
        printf 'refusing to replace existing path: %s\n' "$destination" >&2
        exit 1
    fi
done

for skill in "${SKILLS[@]}"; do
    source_directory="$REPOSITORY_ROOT/$skill"
    destination="$SKILLS_HOME/$skill"
    if [[ -L "$destination" ]]; then
        STATUSES+=(unchanged)
    else
        ln -s -- "$source_directory" "$destination"
        STATUSES+=(installed)
    fi
done

python3 - "$REPOSITORY_ROOT" "$SKILLS_HOME" "${STATUSES[@]}" <<'PY'
import json
import sys

source, destination, *statuses = sys.argv[1:]
names = ("pwn-agent", "web-agent", "rev-agent")
report = {
    "source": source,
    "destination": destination,
    "skills": {
        name: {
            "source": f"{source}/{name}",
            "destination": f"{destination}/{name}",
            "status": status,
        }
        for name, status in zip(names, statuses, strict=True)
    },
}
print(json.dumps(report, sort_keys=True, indent=2))
PY
