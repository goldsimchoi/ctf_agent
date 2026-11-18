# CTF 에이전트 이식 가이드 (deploy/)

pwn / rev / web 에이전트를 **새 PC**로 옮기기 위한 설치 패키지.
Claude Code와 Codex(OpenAI) 두 하네스를 모두 지원한다. Codex가 메인이면 `install-codex.sh`를 먼저 돌리면 된다.

## 0. 새 PC 선행 설치 (공통)

| 도구 | 설치 | 용도 |
|---|---|---|
| git | OS 패키지 | repo clone |
| uv | `curl -LsSf https://astral.sh/uv/install.sh \| sh` | gdb-mcp / idalib 실행 |
| gdb | `sudo apt install gdb` | gdb MCP |
| IDA Pro 9.x (+ idalib) | 상용 라이선스, 직접 설치 | idalib MCP (리버싱 정적분석) |

> IDA는 상용 라이선스라 복사로 안 옮겨진다. 새 PC에 설치 후 idalib 전역 활성화가 필요하다(아래 스크립트가 안내).

## 1. repo 받기

```bash
git clone https://github.com/goldsimchoi/ctf_agent.git ~/ctf_agent
cd ~/ctf_agent
git checkout feature/multi-category-agents
```

## 2. 하네스별 설치

```bash
# Codex (메인)
./deploy/install-codex.sh

# Claude Code (같이 쓸 경우)
./deploy/install-claude.sh
```

두 스크립트 맨 위의 `IDA_DIR` 변수를 새 PC의 IDA 설치 경로로 수정할 것.

## 3. 검증

- **Codex**: `codex` 실행 → 세션에서 `pwn-agent`, `rev-agent`, `web-agent`가 보이고, idalib/gdb MCP 툴이 뜨는지 확인.
- **Claude Code**: `claude mcp list` (gdb, idalib connected) → `/skills`에 세 에이전트 확인.

## 이식되지 않는 것 (의도적)

- `~/.codex/config.toml`의 **개인 프로젝트 신뢰 목록 / 커넥터(Notion·GDrive) / auth.json** → 개인정보·자격증명. 새 PC에서 직접 로그인/신뢰.
- `~/.codex/rules/default.rules` → 승인 이력 누적 파일. 새 PC에서 자동 재생성.
- `__pycache__/`, `.superpowers/`(SDD 기획 문서) → 실행에 불필요.

## 의존성 주의

- 에이전트 워크플로우는 **superpowers** 스킬(브레인스토밍·systematic-debugging·TDD 등)을 전제로 한다. 두 하네스 모두 superpowers가 설치돼 있어야 제대로 동작한다.
