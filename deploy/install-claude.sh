#!/usr/bin/env bash
# =============================================================================
#  CTF 에이전트 → Claude Code 하네스 설치 (새 PC)
#  repo clone + checkout feature/multi-category-agents 후, repo 루트에서 실행.
# =============================================================================
set -euo pipefail

# ----- 수정할 변수 ------------------------------------------------------------
IDA_DIR="/opt/idapro-9.3"                 # ← 새 PC의 IDA Pro 설치 경로로 수정!
IDA_MCP_DIR="$HOME/tools/ida-pro-mcp"     # ida-pro-mcp 받을 위치
# -----------------------------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "repo: $REPO_ROOT"

echo "==> 0. 필수 도구 확인"
command -v uv     >/dev/null || { echo "uv 필요: curl -LsSf https://astral.sh/uv/install.sh | sh"; exit 1; }
command -v claude >/dev/null || { echo "Claude Code CLI 필요"; exit 1; }
command -v gdb    >/dev/null || echo "WARN: gdb 없음 (sudo apt install gdb 권장)"

echo "==> 1. 스킬 심링크 (복사 아님 — ctf-common 상대참조 유지)"
mkdir -p "$HOME/.claude/skills"
for a in pwn-agent rev-agent web-agent; do
  ln -sfn "$REPO_ROOT/$a" "$HOME/.claude/skills/$a"
  echo "   linked ~/.claude/skills/$a"
done

echo "==> 2. gdb MCP 설치"
uv tool install gdb-mcp 2>/dev/null || uv tool upgrade gdb-mcp || true
GDB_MCP="$(command -v gdb-mcp || echo "$HOME/.local/bin/gdb-mcp")"

echo "==> 3. idalib MCP (ida-pro-mcp) 받기 + 활성화"
[ -d "$IDA_MCP_DIR/.git" ] || git clone https://github.com/mrexodia/ida-pro-mcp "$IDA_MCP_DIR"
ACT="$IDA_DIR/idalib/python/py-activate-idalib.py"
if [ -f "$ACT" ]; then uv run "$ACT" || echo "   활성화 실패 - 수동: uv run \"$ACT\"";
else echo "   IDA 경로 확인 필요: $ACT 없음"; fi

echo "==> 4. MCP 서버 등록 (user 스코프)"
claude mcp add -s user gdb -- "$GDB_MCP"
claude mcp add -s user idalib -- uv run --directory "$IDA_MCP_DIR" idalib-mcp --stdio

echo "==> 5. 플러그인 설치 (superpowers 필수)"
claude plugin marketplace add anthropics/claude-plugins-official 2>/dev/null || true
claude plugin install superpowers@claude-plugins-official
claude plugin install clangd-lsp@claude-plugins-official
claude plugin install code-review@claude-plugins-official

echo
echo "==> 완료. 검증: claude mcp list  /  claude 실행 후 /skills"
