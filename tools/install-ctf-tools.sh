#!/usr/bin/env bash
# Install the local, user-scoped CTF capabilities used by the three skills.
# Re-running this script is safe: apt, uv, Playwright, and Go skip installed
# artifacts, while the virtual environment remains at the fixed CTF location.
set -uo pipefail

CTF_ROOT=${CTF_TOOLS_ROOT:-/home/normalone/CTF}
VENV="$CTF_ROOT/.venv"
MANAGED_ROOT=${CTF_TOOLS_MANAGED_ROOT:-"$CTF_ROOT/.tools"}
MANAGED_BIN="$MANAGED_ROOT/bin"
MANAGED_SRC="$MANAGED_ROOT/src"
MARKER_DIR="$MANAGED_ROOT/state"
ENV_FILE="$MANAGED_ROOT/env.sh"
R2_REVISION=8e57aff6dc36517bbab2aff199154f099e3471ea
SQLMAP_REVISION=5365c7e53d03c268b14cfc924398340d1365e863
NUCLEI_VERSION=3.11.1
NUCLEI_SHA256=ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6
DRY_RUN=false
COMPONENT=all
DEGRADED=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --component) COMPONENT=${2:-}; shift 2 ;;
    *) echo "Usage: $0 [--dry-run] [--component {sqlmap|radare2}]" >&2; exit 2 ;;
  esac
done
if [[ "$COMPONENT" != all && "$COMPONENT" != sqlmap && "$COMPONENT" != radare2 ]]; then
  echo "Usage: $0 [--dry-run] [--component {sqlmap|radare2}]" >&2
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

pin_revision() {
  local label=$1 directory=$2 revision=$3 actual
  if ! run git -C "$directory" checkout --detach "$revision"; then
    DEGRADED+=("$label: command failed: git -C $directory checkout --detach $revision")
    note "DEGRADED: $label (component stopped before exposure)" >&2
    return 1
  fi
  if "$DRY_RUN"; then
    return 0
  fi
  actual=$(git -C "$directory" rev-parse HEAD 2>/dev/null) || {
    DEGRADED+=("$label: could not read checked-out revision")
    return 1
  }
  if [[ "$actual" != "$revision" ]]; then
    DEGRADED+=("$label: revision mismatch (expected $revision, got $actual)")
    note "DEGRADED: $label (component stopped before exposure)" >&2
    return 1
  fi
}

disable_managed_exposure() {
  local label=$1 path=$2 revision=$3 marker
  marker="$MARKER_DIR/$label.marker"
  if [[ "$path" != "$MANAGED_BIN/$label" ]]; then
    DEGRADED+=("$label: refused non-managed exposure path: $path")
    return 0
  fi
  if "$DRY_RUN"; then
    note "DRY RUN: would disable only marker-owned $label exposure: $path" >&2
    return 0
  fi
  if [[ -e "$path" || -L "$path" ]]; then
    if marker_matches "$label" "$path" "$revision"; then
      if rm -f "$path" && rm -f "$marker"; then
        note "DEGRADED: removed marker-owned $label exposure: $path" >&2
      else
        DEGRADED+=("$label: could not disable marker-owned exposure: $path")
      fi
    else
      DEGRADED+=("$label: unmarked or mismatching local exposure preserved: $path")
      note "DEGRADED: refusing to remove unmarked or mismatching $label exposure: $path" >&2
    fi
  fi
}

marker_matches() {
  local label=$1 path=$2 revision=$3 marker
  local recorded_path recorded_revision recorded_digest actual_digest
  marker="$MARKER_DIR/$label.marker"
  [[ -f "$marker" && -f "$path" ]] || return 1
  recorded_path=$(awk -F= '$1 == "path" {print substr($0, 6)}' "$marker")
  recorded_revision=$(awk -F= '$1 == "revision" {print substr($0, 10)}' "$marker")
  recorded_digest=$(awk -F= '$1 == "sha256" {print substr($0, 8)}' "$marker")
  actual_digest=$(sha256sum "$path" 2>/dev/null | awk '{print $1}')
  [[ "$recorded_path" == "$path" && "$recorded_revision" == "$revision" && -n "$recorded_digest" && "$recorded_digest" == "$actual_digest" ]]
}

write_marker() {
  local label=$1 path=$2 revision=$3 digest
  "$DRY_RUN" && return 0
  digest=$(sha256sum "$path" | awk '{print $1}') || return 1
  mkdir -p "$MARKER_DIR" || return 1
  printf 'tool=%s\npath=%s\nrevision=%s\nsha256=%s\n' "$label" "$path" "$revision" "$digest" > "$MARKER_DIR/$label.marker"
}

write_managed_env() {
  local quoted_bin quoted_lib
  "$DRY_RUN" && return 0
  if [[ "$MANAGED_BIN" == *$'\n'* || "$MANAGED_BIN" == *$'\r'* ]]; then
    note "DEGRADED: managed tool environment path contains a newline and was rejected" >&2
    return 1
  fi
  mkdir -p "$MANAGED_ROOT" || return 1
  printf -v quoted_bin '%q' "$MANAGED_BIN"
  printf -v quoted_lib '%q' "$MANAGED_ROOT/lib"
  printf '%s\n' '#!/usr/bin/env bash' "export PATH=${quoted_bin}:\"\${PATH}\"" "export LD_LIBRARY_PATH=${quoted_lib}:\"\${LD_LIBRARY_PATH:-}\"" > "$ENV_FILE"
  chmod +x "$ENV_FILE"
}

sqlmap_wrapper_matches() {
  local path=$1
  [[ -f "$path" ]] || return 1
  diff -q "$path" <(printf '%s\n' '#!/usr/bin/env bash' "exec \"$VENV/bin/python\" \"$MANAGED_SRC/sqlmap/sqlmap.py\" \"\$@\"") >/dev/null 2>&1
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
  try_run "managed Go tool directory" mkdir -p "$MANAGED_BIN"
  try_run "ffuf" env GOBIN="$MANAGED_BIN" go install github.com/ffuf/ffuf/v2@v2.1.0
  try_run "ProjectDiscovery httpx" env GOBIN="$MANAGED_BIN" go install github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0
  try_run "gobuster" env GOBIN="$MANAGED_BIN" go install github.com/OJ/gobuster/v3@v3.8.2
}

install_nuclei() {
  local temp_dir asset expected actual
  if [[ -x "$MANAGED_BIN/nuclei" ]] && "$MANAGED_BIN/nuclei" -version 2>&1 | grep -q "Nuclei Engine Version: v${NUCLEI_VERSION}"; then
    return 0
  fi
  if "$DRY_RUN"; then
    note "DRY RUN: download the official ProjectDiscovery nuclei Linux archive and checksums, verify SHA-256, then install nuclei to $MANAGED_BIN"
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
  if unzip -q "$temp_dir/nuclei.zip" -d "$temp_dir/unpacked" && install -d "$MANAGED_BIN" && install -m 0755 "$temp_dir/unpacked/nuclei" "$MANAGED_BIN/nuclei" && "$MANAGED_BIN/nuclei" -version 2>&1 | grep -q "Nuclei Engine Version: v${NUCLEI_VERSION}"; then
    note "Installed checksum-verified official nuclei release in $MANAGED_BIN"
  else
    DEGRADED+=("nuclei: verified archive could not be installed and probed in $MANAGED_BIN")
  fi
  rm -rf "$temp_dir"
}

install_sqlmap() {
  local sqlmap_dir="$MANAGED_SRC/sqlmap"
  try_run "managed sqlmap directory" mkdir -p "$MANAGED_SRC" "$MANAGED_BIN" "$MARKER_DIR"
  if [[ ! -e "$sqlmap_dir" ]]; then
    try_run "official sqlmap checkout" git clone https://github.com/sqlmapproject/sqlmap.git "$sqlmap_dir"
  fi
  if [[ ! -d "$sqlmap_dir/.git" ]]; then
    DEGRADED+=("sqlmap: official checkout did not create a Git repository")
    disable_managed_exposure "sqlmap" "$MANAGED_BIN/sqlmap" "$SQLMAP_REVISION"
    return 0
  fi
  if ! pin_revision "pinned sqlmap revision" "$sqlmap_dir" "$SQLMAP_REVISION"; then
    disable_managed_exposure "sqlmap" "$MANAGED_BIN/sqlmap" "$SQLMAP_REVISION"
    return 0
  fi
  if "$DRY_RUN"; then
    note "DRY RUN: create $MANAGED_BIN/sqlmap wrapper for $sqlmap_dir/sqlmap.py"
  elif [[ -f "$sqlmap_dir/sqlmap.py" ]]; then
    if [[ -e "$MANAGED_BIN/sqlmap" ]] && ! marker_matches "sqlmap" "$MANAGED_BIN/sqlmap" "$SQLMAP_REVISION" && ! sqlmap_wrapper_matches "$MANAGED_BIN/sqlmap"; then
      DEGRADED+=("sqlmap: unmarked managed collision preserved: $MANAGED_BIN/sqlmap")
      return 0
    fi
    printf '%s\n' '#!/usr/bin/env bash' "exec \"$VENV/bin/python\" \"$sqlmap_dir/sqlmap.py\" \"\$@\"" > "$MANAGED_BIN/sqlmap"
    chmod +x "$MANAGED_BIN/sqlmap"
    if ! write_marker "sqlmap" "$MANAGED_BIN/sqlmap" "$SQLMAP_REVISION"; then
      DEGRADED+=("sqlmap: wrapper created but ownership marker could not be written")
    fi
  else
    DEGRADED+=("sqlmap: official checkout did not provide $sqlmap_dir/sqlmap.py")
  fi
}

install_radare2() {
  local r2_dir="$MANAGED_SRC/radare2"
  try_run "managed radare2 directory" mkdir -p "$MANAGED_SRC" "$MANAGED_BIN" "$MARKER_DIR"
  if [[ ! -d "$r2_dir/.git" ]]; then
    try_run "official radare2 source" git clone https://github.com/radareorg/radare2.git "$r2_dir"
  fi
  if [[ ! -d "$r2_dir/.git" ]]; then
    DEGRADED+=("radare2: official checkout did not create a Git repository")
    disable_managed_exposure "radare2" "$MANAGED_BIN/radare2" "$R2_REVISION"
    return 0
  fi
  if ! pin_revision "pinned radare2 revision" "$r2_dir" "$R2_REVISION"; then
    disable_managed_exposure "radare2" "$MANAGED_BIN/radare2" "$R2_REVISION"
    return 0
  fi
  if [[ -e "$MANAGED_BIN/radare2" ]] && ! marker_matches "radare2" "$MANAGED_BIN/radare2" "$R2_REVISION"; then
    DEGRADED+=("radare2: unmarked managed collision preserved: $MANAGED_BIN/radare2")
    return 0
  fi
  if [[ -f "$r2_dir/configure" ]]; then
    try_run "managed radare2 build" bash -c 'cd "$1" && ./configure --prefix="$2" && make -j"$(nproc)" && make install' _ "$r2_dir" "$MANAGED_ROOT"
    if [[ -x "$MANAGED_BIN/radare2" ]] && ! write_marker "radare2" "$MANAGED_BIN/radare2" "$R2_REVISION"; then
      DEGRADED+=("radare2: binary created but ownership marker could not be written")
    fi
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

if ! write_managed_env; then
  DEGRADED+=("managed tool environment: could not write $ENV_FILE")
fi

if [[ "$COMPONENT" == all ]]; then
  try_run "CTF root directory" mkdir -p "$CTF_ROOT"
  install_native_tools
  ensure_uv_python
  install_go_tools
  install_nuclei
  install_sqlmap
  install_radare2
elif [[ "$COMPONENT" == sqlmap ]]; then
  install_sqlmap
else
  install_radare2
fi

if ((${#DEGRADED[@]})); then
  note "Installation completed with degraded capabilities:"
  printf ' - %s\n' "${DEGRADED[@]}"
  note "Run tools/check-ctf-tools.sh for per-capability fallback guidance."
else
  note "Installation completed. Run tools/check-ctf-tools.sh for the capability report."
fi
