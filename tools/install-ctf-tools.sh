#!/usr/bin/env bash
# Install the local, user-scoped CTF capabilities used by the three skills.
# Re-running this script is safe: apt, uv, Playwright, and Go skip installed
# artifacts, while the virtual environment remains at the fixed CTF location.
set -uo pipefail

CTF_ROOT=/home/normalone/CTF
VENV="$CTF_ROOT/.venv"
LOCAL_BIN=/home/normalone/.local/bin
LOCAL_OPT=/home/normalone/.local/opt
DRY_RUN=false
DEGRADED=()

if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
elif [[ $# -ne 0 ]]; then
  echo "Usage: $0 [--dry-run]" >&2
  exit 2
fi

note() { printf '%s\n' "$*"; }

run() {
  if "$DRY_RUN"; then
    printf 'DRY RUN: '
    printf '%q ' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

try_run() {
  local label=$1
  shift
  if ! run "$@"; then
    DEGRADED+=("$label: command failed: $(printf '%q ' "$@")")
    note "DEGRADED: $label (continuing; see tools/check-ctf-tools.sh)" >&2
    return 0
  fi
}

ensure_uv_python() {
  if ! command -v uv >/dev/null 2>&1; then
    DEGRADED+=("managed Python: uv is not on PATH")
    note "DEGRADED: uv is required to create $VENV" >&2
    return 0
  fi

  if ! uv python find 3.12 >/dev/null 2>&1; then
    try_run "Python 3.12" uv python install 3.12
  fi

  if [[ ! -x "$VENV/bin/python" ]] || ! "$VENV/bin/python" --version 2>&1 | grep -q '^Python 3\.12\.'; then
    try_run "managed virtual environment" uv venv --clear --python 3.12 "$VENV"
  fi

  if [[ ! -x "$VENV/bin/python" ]]; then
    if "$DRY_RUN"; then
      return 0
    fi
    DEGRADED+=("Python packages: $VENV/bin/python was not created")
    return 0
  fi

  try_run "Python CTF packages" uv pip install --python "$VENV/bin/python" --upgrade \
    pwntools angr capstone unicorn z3-solver lief requests httpx playwright binwalk
  try_run "Playwright Chromium browser" "$VENV/bin/python" -m playwright install chromium
}

install_native_tools() {
  local -a packages=(gdb radare2 ffuf sqlmap nmap ltrace binwalk qemu-user gobuster)
  if ! command -v sudo >/dev/null 2>&1; then
    DEGRADED+=("native tools: sudo is unavailable for apt installation")
    return 0
  fi
  try_run "apt package index" sudo -n apt-get update
  try_run "native CTF tools" sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
}

install_go_tools() {
  if ! command -v go >/dev/null 2>&1; then
    DEGRADED+=("ProjectDiscovery tools: Go is not on PATH")
    return 0
  fi
  try_run "user-local tool directory" mkdir -p "$LOCAL_BIN"
  try_run "ffuf" env GOBIN="$LOCAL_BIN" go install github.com/ffuf/ffuf/v2@latest
  try_run "ProjectDiscovery httpx" env GOBIN="$LOCAL_BIN" go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  try_run "gobuster" env GOBIN="$LOCAL_BIN" go install github.com/OJ/gobuster/v3@latest
}

install_nuclei() {
  local api=https://api.github.com/repos/projectdiscovery/nuclei/releases/latest
  local temp_dir release asset checksum expected actual
  if command -v nuclei >/dev/null 2>&1; then
    return 0
  fi
  if "$DRY_RUN"; then
    note "DRY RUN: download the official ProjectDiscovery nuclei Linux archive and checksums, verify SHA-256, then install nuclei to $LOCAL_BIN"
    return 0
  fi
  if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1 || ! command -v sha256sum >/dev/null 2>&1; then
    DEGRADED+=("nuclei: curl, unzip, and sha256sum are required for the verified official release fallback")
    return 0
  fi
  temp_dir=$(mktemp -d)
  release=$(curl -fsSL "$api") || { DEGRADED+=("nuclei: could not read the official GitHub release metadata"); rm -rf "$temp_dir"; return 0; }
  asset=$(printf '%s' "$release" | python3 -c 'import json, sys; print(next((a["browser_download_url"] for a in json.load(sys.stdin)["assets"] if a["name"].endswith("linux_amd64.zip")), ""))')
  checksum=$(printf '%s' "$release" | python3 -c 'import json, sys; print(next((a["browser_download_url"] for a in json.load(sys.stdin)["assets"] if a["name"].endswith("checksums.txt")), ""))')
  if [[ -z "$asset" || -z "$checksum" ]]; then
    DEGRADED+=("nuclei: the official release omitted Linux amd64 archive or checksum metadata")
    rm -rf "$temp_dir"
    return 0
  fi
  if ! curl -fsSL --retry 2 -o "$temp_dir/nuclei.zip" "$asset" || ! curl -fsSL --retry 2 -o "$temp_dir/checksums.txt" "$checksum"; then
    DEGRADED+=("nuclei: official release download failed: $asset")
    rm -rf "$temp_dir"
    return 0
  fi
  expected=$(awk '$2 ~ /linux_amd64\\.zip$/ {print $1}' "$temp_dir/checksums.txt")
  actual=$(sha256sum "$temp_dir/nuclei.zip" | awk '{print $1}')
  if [[ -z "$expected" || "$expected" != "$actual" ]]; then
    DEGRADED+=("nuclei: SHA-256 verification failed for official release archive")
    rm -rf "$temp_dir"
    return 0
  fi
  if unzip -q "$temp_dir/nuclei.zip" -d "$temp_dir/unpacked" && install -d "$LOCAL_BIN" && install -m 0755 "$temp_dir/unpacked/nuclei" "$LOCAL_BIN/nuclei"; then
    note "Installed checksum-verified official nuclei release in $LOCAL_BIN"
  else
    DEGRADED+=("nuclei: verified archive could not be unpacked into $LOCAL_BIN")
  fi
  rm -rf "$temp_dir"
}

install_sqlmap() {
  local sqlmap_dir="$LOCAL_OPT/sqlmap"
  if command -v sqlmap >/dev/null 2>&1 || [[ -f "$sqlmap_dir/sqlmap.py" ]]; then
    return 0
  fi
  try_run "sqlmap directory" mkdir -p "$LOCAL_OPT" "$LOCAL_BIN"
  try_run "official sqlmap checkout" git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$sqlmap_dir"
  if "$DRY_RUN"; then
    note "DRY RUN: create $LOCAL_BIN/sqlmap wrapper for $sqlmap_dir/sqlmap.py"
  elif [[ -f "$sqlmap_dir/sqlmap.py" ]]; then
    printf '%s\n' '#!/usr/bin/env bash' "exec \"$VENV/bin/python\" \"$sqlmap_dir/sqlmap.py\" \"\$@\"" > "$LOCAL_BIN/sqlmap"
    chmod +x "$LOCAL_BIN/sqlmap"
  else
    DEGRADED+=("sqlmap: official checkout did not provide $sqlmap_dir/sqlmap.py")
  fi
}

install_radare2() {
  local r2_dir="$LOCAL_OPT/radare2"
  if command -v radare2 >/dev/null 2>&1 || [[ -x "$LOCAL_BIN/radare2" ]]; then
    return 0
  fi
  try_run "radare2 directory" mkdir -p "$LOCAL_OPT"
  if [[ ! -d "$r2_dir/.git" ]]; then
    try_run "official radare2 source" git clone --depth 1 https://github.com/radareorg/radare2.git "$r2_dir"
  fi
  if [[ -f "$r2_dir/sys/user.sh" ]]; then
    try_run "user-local radare2 build" bash "$r2_dir/sys/user.sh"
  elif ! "$DRY_RUN"; then
    DEGRADED+=("radare2: official source was unavailable at $r2_dir")
  fi
}

note "CTF tool bootstrap: venv=$VENV"
if "$DRY_RUN"; then
  note "DRY RUN: no package manager, filesystem, or browser changes will be made."
  note "DRY RUN: required Python capabilities: pwntools angr capstone unicorn z3-solver lief requests httpx playwright binwalk"
  note "DRY RUN: native/web/reversing CLIs: gdb radare2 ffuf sqlmap nmap nuclei httpx ltrace binwalk qemu-user gobuster"
fi

try_run "CTF root directory" mkdir -p "$CTF_ROOT"
install_native_tools
ensure_uv_python
install_go_tools
install_nuclei
install_sqlmap
install_radare2

if ((${#DEGRADED[@]})); then
  note "Installation completed with degraded capabilities:"
  printf ' - %s\n' "${DEGRADED[@]}"
  note "Run tools/check-ctf-tools.sh for per-capability fallback guidance."
else
  note "Installation completed. Run tools/check-ctf-tools.sh for the capability report."
fi
