#!/usr/bin/env bash
# =============================================================================
#  CTF 에이전트 → Codex(OpenAI) 하네스 설치 (새 PC, Codex 메인)
#  repo clone + checkout feature/multi-category-agents 후, repo 루트에서 실행.
# =============================================================================
set -euo pipefail

# ----- 수정할 변수 ------------------------------------------------------------
IDA_DIR="/opt/idapro-9.3"                 # ← 새 PC의 IDA Pro 설치 경로로 수정!
CODEX_HOME="${CODEX_HOME:-$HOME/.codex}"
# -----------------------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "repo: $REPO_ROOT"
echo "codex home: $CODEX_HOME"

echo "==> 0. 필수 도구 확인"
command -v uv >/dev/null || { echo "uv 필요: curl -LsSf https://astral.sh/uv/install.sh | sh"; exit 1; }
command -v gdb >/dev/null || echo "WARN: gdb 없음 (sudo apt install gdb 권장)"
command -v codex >/dev/null || echo "WARN: codex CLI 가 PATH에 없음 (설치/로그인 먼저)"

echo "==> 1. CTF 에이전트를 Codex 스킬로 연결 (심링크 → git pull 시 자동 동기화)"
mkdir -p "$CODEX_HOME/skills"
for a in pwn-agent rev-agent web-agent; do
  ln -sfn "$REPO_ROOT/$a" "$CODEX_HOME/skills/$a"
  echo "   linked $CODEX_HOME/skills/$a"
done
# (대안: repo를 안 두고 GitHub에서 직접 복사하려면)
#   "$CODEX_HOME/skills/.system/skill-installer/scripts/install-skill-from-github.py" \
#     --repo goldsimchoi/ctf_agent --ref feature/multi-category-agents \
#     --path pwn-agent rev-agent web-agent

echo "==> 2. gdb MCP 설치 (Claude Code와 공용)"
uv tool install gdb-mcp 2>/dev/null || uv tool upgrade gdb-mcp || true
GDB_MCP="$(command -v gdb-mcp || echo "$HOME/.local/bin/gdb-mcp")"
echo "   gdb-mcp -> $GDB_MCP"

echo "==> 3. idalib 전역 활성화 (IDA Pro 라이선스 필요, 1회)"
ACT="$IDA_DIR/idalib/python/py-activate-idalib.py"
if [ -f "$ACT" ]; then
  uv run "$ACT" || echo "   활성화 실패 - 수동 확인: uv run \"$ACT\""
else
  echo "   IDA 경로 확인 필요: $ACT 없음 (IDA_DIR 수정)"
fi

echo "==> 4. config.toml 병합용 조각 생성 (기존 config 는 건드리지 않음)"
OUT="$CODEX_HOME/ctf-config-snippet.toml"
sed "s|REPLACE_WITH_ABS_PATH/gdb-mcp|$GDB_MCP|" \
    "$REPO_ROOT/deploy/codex-config.snippet.toml" > "$OUT"
echo "   생성됨: $OUT"
echo
echo "   ↓ 아래 내용을 ~/.codex/config.toml 에 '추가 병합' 하세요 (통째 교체 금지):"
echo "   ------------------------------------------------------------------"
cat "$OUT"
echo "   ------------------------------------------------------------------"

echo
echo "==> 5. idalib 플러그인 설치 (Codex CLI)"
echo "   아래를 실행하거나 config 의 [marketplaces.mrexodia]+[plugins] 블록으로 처리:"
echo "     codex plugin marketplace add https://github.com/mrexodia/codex-marketplace.git"
echo "     codex plugin install ida-pro-mcp@mrexodia"
echo "   (정확한 플래그는 'codex plugin --help' 확인)"

echo
echo "==> 완료. Codex 재시작 후 세션에서 pwn-agent/rev-agent/web-agent 와"
echo "    idalib/gdb MCP 툴이 보이는지 확인하세요."
