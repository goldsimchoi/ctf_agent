#!/usr/bin/env bash
# Install the local, user-scoped CTF capabilities used by the three skills.
# Re-running this script is safe: apt, uv, Playwright, and Go skip installed
# artifacts, while the virtual environment remains at the fixed CTF location.
set -uo pipefail

CTF_ROOT=/home/normalone/CTF
VENV="$CTF_ROOT/.venv"
LOCAL_BIN=/home/normalone/.local/bin
LOCAL_OPT=/home/normalone/.local/opt
R2_REVISION=8e57aff6dc36517bbab2aff199154f099e3471ea
SQLMAP_REVISION=5365c7e53d03c268b14cfc924398340d1365e863
NUCLEI_VERSION=3.11.1
NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
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

  try_run "Python CTF packages" uv pip install --python "$VENV/bin/python" \
    pwntools==4.15.0 angr==10.0.0 capstone==5.0.9 unicorn==2.1.2 \
    z3-solver==5.1.0.0 lief==1.0.0 requests==2.34.2 httpx==0.28.1 playwright==1.63.0
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
  try_run "ffuf" env GOBIN="$LOCAL_BIN" go install github.com/ffuf/ffuf/v2@v2.1.0
  try_run "ProjectDiscovery httpx" env GOBIN="$LOCAL_BIN" go install github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0
  try_run "gobuster" env GOBIN="$LOCAL_BIN" go install github.com/OJ/gobuster/v3@v3.8.2
}

install_nuclei() {
  local temp_dir asset expected actual
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
  asset="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
  if ! curl -fsSL --retry 2 -o "$temp_dir/nuclei.zip" "$asset"; then
    DEGRADED+=("nuclei: official release download failed: $asset")
    rm -rf "$temp_dir"
    return 0
  fi
  expected=$NUCLEI_SHA256
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
  try_run "official sqlmap checkout" git clone https://github.com/sqlmapproject/sqlmap.git "$sqlmap_dir"
  if [[ -d "$sqlmap_dir/.git" ]]; then
    try_run "pinned sqlmap revision" git -C "$sqlmap_dir" checkout --detach "$SQLMAP_REVISION"
  fi
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
    try_run "official radare2 source" git clone https://github.com/radareorg/radare2.git "$r2_dir"
  fi
  if [[ -d "$r2_dir/.git" ]]; then
    try_run "pinned radare2 revision" git -C "$r2_dir" checkout --detach "$R2_REVISION"
  fi
  if [[ -f "$r2_dir/configure" ]]; then
    try_run "user-local radare2 build" bash -c 'cd "$1" && ./configure --prefix="$2" && make -j"$(nproc)" && make install' _ "$r2_dir" /home/normalone/.local
  elif ! "$DRY_RUN"; then
    DEGRADED+=("radare2: official source was unavailable at $r2_dir")
  fi
}

note "CTF tool bootstrap: venv=$VENV"
if "$DRY_RUN"; then
  note "DRY RUN: no package manager, filesystem, or browser changes will be made."
  note "DRY RUN: required Python capabilities: pwntools angr capstone unicorn z3-solver lief requests httpx playwright"
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
