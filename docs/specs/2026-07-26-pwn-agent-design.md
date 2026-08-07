# Codex Pwn Agent 설계

## 1. 목표

사용자가 Codex에서 다음과 같이 요청하면 pwnable 문제를 분석하고 exploit을 작성해 검증된 플래그를 반환하는 재사용 스킬을 만든다.

```text
이 문제 풀고 플래그 가져와.
```

에이전트는 IDA MCP, GDB/pwndbg, Shell, pwntools를 직접 사용한다. 별도의 단계별 담당 에이전트는 두지 않는다. 문제의 공격면이 불명확할 때만 짧은 병렬 탐색을 수행하고, 전략을 선택한 뒤에는 하나의 Lead Solver가 문제 전체를 소유한다.

## 2. 설계 원칙

1. **문제 단위 소유권:** Lead Solver 하나가 분석 기록, `exploit.py`, 도구 세션과 검증 결과를 끝까지 소유한다.
2. **조건부 병렬 탐색:** 명확한 풀이 경로가 없을 때만 최대 3개의 Explorer를 사용한다.
3. **빠른 수렴:** Explorer는 exploit 완성이 아니라 가설의 최소 검증만 수행한다.
4. **단일 작성자:** Explorer는 공용 산출물을 수정하지 않는다. 전략 선택 후 Lead Solver만 수정할 수 있다.
5. **점진적 정보 로딩:** 세부 공격 기법은 필요한 유형만 읽는다.
6. **증거 기반 성공:** 프로세스 종료 코드가 아니라 실제 플래그와 재현 결과로 성공을 판정한다.
7. **증거 기반 상태:** 도구 출력 없는 모델 추측을 Fact로 저장하지 않는다.
8. **진행 능력 추적:** 최종 flag뿐 아니라 leak, controlled read/write, RIP control 등 확인된 capability를 추적한다.
9. **교체 가능한 도구 경로:** MCP를 우선하되 IDA/idapro와 GDB/PTY·batch fallback을 유지한다.

## 3. 실행 구조

```text
사용자 요청
    |
    v
공통 저비용 정찰
    |
    +-- 풀이 경로가 명확함 --------> Lead Solver
    |
    +-- 공격면이 불명확함
            |
            +-- Explorer A: 후보 가설 1
            +-- Explorer B: 후보 가설 2
            +-- Explorer C: 후보 가설 3
            |
            v
        증거 비교 및 전략 선택
            |
            v
        나머지 Explorer 중단
            |
            v
        Lead Solver
            |
            +-- IDA/GDB/Shell/pwntools 반복 사용
            +-- exploit.py 작성 및 수정
            +-- 로컬 재현
            +-- 허가된 원격 대상 재현
            |
            v
        Flag Verifier
            |
            v
        결과 반환
```

## 4. 스킬 디렉터리

```text
pwn-agent/
├── SKILL.md
├── agents/
│   └── openai.yaml
├── references/
│   ├── exploration.md
│   ├── solver-loop.md
│   ├── state-model.md
│   ├── capabilities.md
│   ├── tool-runtime.md
│   ├── verification.md
│   ├── sandbox-security.md
│   └── strategies/
│       ├── stack.md
│       ├── format-string.md
│       ├── heap.md
│       ├── cpp.md
│       └── seccomp-orw.md
├── scripts/
│   ├── init_run.py
│   ├── inspect_binary.py
│   ├── run_exploit.py
│   ├── record_transcript.py
│   └── verify_flag.py
└── assets/
    ├── exploit.py
    └── challenge.yaml
```

### `SKILL.md`

항상 읽히는 핵심 행동 계약만 둔다. 다음 내용만 포함한다.

- 입력과 원격 접속 정보 확인
- 저비용 정찰 실행
- 단일 Solver와 조건부 Explorer 선택 기준
- Lead Solver의 반복 루프
- 파일 소유권
- 플래그 검증 기준
- 필요한 reference를 읽는 조건

세부 취약점 설명이나 긴 예시는 넣지 않는다.

### `references/`

필요할 때만 읽는 지침이다.

- `exploration.md`: Explorer 생성 조건, 예산, 결과 형식과 전략 선택법
- `solver-loop.md`: 관찰, 가설, 최소 실험, exploit 수정 루프
- `state-model.md`: Fact, Evidence, Hypothesis, Experiment, Strategy의 최소 schema
- `capabilities.md`: exploit 진행 능력과 결정론적 확인 조건
- `tool-runtime.md`: IDA와 pwndbg MCP 도구 계약, 세션 소유권과 fallback
- `verification.md`: 로컬·원격 플래그 검증과 transcript 보존
- `sandbox-security.md`: 불신 바이너리 실행, 네트워크와 파일시스템 경계
- `strategies/*`: 실제로 식별된 취약점 유형에 해당하는 파일만 로드

### `scripts/`

추론이 필요 없는 반복 작업을 처리한다.

- `init_run.py`: 원본과 실행 산출물을 분리한 작업공간 생성
- `inspect_binary.py`: `file`, 보호 기법, 의존성, 문자열 등 초기 정보 수집
- `run_exploit.py`: timeout과 transcript를 적용해 exploit 실행
- `verify_flag.py`: 출력에서 플래그 후보를 추출하고 결과 JSON 생성

### `assets/`

실행 작업공간에 복사할 최소 템플릿을 보관한다.

## 5. 문제별 작업공간

스킬 설치 디렉터리에는 문제별 실행 상태를 저장하지 않는다. 원본 문제와 실행 산출물을 분리하고 실행마다 새 run ID를 만든다.

```text
CTF/
├── challenges/
│   └── babyheap/
│       ├── challenge.yaml
│       └── input/
│           ├── chall
│           ├── libc.so.6
│           └── ld-linux-x86-64.so.2
└── runs/
    └── 2026-07-26T120000Z/
        └── babyheap/
            ├── challenge.resolved.yaml
            ├── state.json
            ├── exploit.py
            ├── notes.md
            ├── result.json
            ├── ida/
            ├── gdb/
            ├── explorers/
            ├── crashes/
            ├── transcripts/
            └── logs/
```

`challenges/*/input/`은 읽기 전용 원본으로 취급한다. 생성·수정되는 모든 파일은 `runs/<run-id>/<challenge-id>/` 아래에 둔다. 중단된 run은 같은 `state.json`과 artifact를 사용해 재개하며, 새 실행이 이전 결과를 덮어쓰지 않는다.

## 6. Challenge manifest

명시적 manifest를 우선하고, 없으면 로컬 파일 정보만으로 `challenge.resolved.yaml`을 생성한다. 불확실한 값은 `unknown`으로 남기며 원격 주소는 자동 추론하지 않는다.

```yaml
id: babyheap
category: pwn
binary: input/chall
libc: input/libc.so.6
loader: input/ld-linux-x86-64.so.2
architecture: amd64

execution:
  argv: []
  env: {}
  working_directory: .

remote:
  enabled: true
  host: challenge.example.ctf
  port: 31337
  tls: false

flag:
  patterns:
    - 'FLAG\{[^}\r\n]+\}'
    - 'CTF\{[^}\r\n]+\}'

limits:
  wall_time_seconds: 1800
  max_tool_calls: 200
  max_strategy_resets: 3
  max_explorer_calls: 2
  process_timeout_seconds: 20
```

## 7. 공통 정찰

병렬 탐색을 시작하기 전에 Lead Solver가 저비용 정찰을 한 번 수행한다.

- 파일 형식, 아키텍처와 인터프리터
- 보호 기법
- 동적 라이브러리와 제공된 loader
- imports, 주요 문자열과 심볼
- 기본 입출력 방식
- 짧은 정상 실행과 비정상 입력

다음과 같이 공격 경로가 명확하면 Explorer 없이 바로 진행한다.

- 직접 호출 가능한 win 함수와 명확한 반환 주소 덮어쓰기
- 사용자 입력이 format 문자열로 직접 사용됨
- 간단한 메뉴 동작에서 재현 가능한 UAF 또는 double free

두 개 이상의 현실적인 공격 경로가 남거나 현재 증거로 우선순위를 정할 수 없을 때만 Explorer를 사용한다.

## 8. Explorer 계약

Explorer는 역할별 전문 에이전트가 아니라 서로 다른 가설을 검증하는 임시 탐색자다.

### 제한

- 최대 3개
- 각자 하나의 가설만 조사
- 기본 도구 호출 예산 8회
- exploit 완성 금지
- 공용 `exploit.py`, `state.json`, IDA DB 수정 금지
- 각자의 `runs/<run-id>/<challenge-id>/explorers/<id>/`만 사용

### 반환 형식

```json
{
  "hypothesis": "freed chunk remains editable",
  "status": "supported",
  "facts": [
    "delete(0) 후 edit(0, data)가 성공한다"
  ],
  "evidence": [
    "gdb transcript: explorers/heap-uaf/gdb.txt"
  ],
  "blockers": [
    "libc leak primitive not yet identified"
  ],
  "next_experiment": "free a large chunk and inspect unsorted-bin metadata",
  "confidence": 0.82
}
```

`confidence`만으로 전략을 선택하지 않는다. 재현 가능한 증거, 필요한 primitive와 blocker의 크기를 함께 비교한다.

## 9. 전략 선택과 가지치기

Coordinator 역할은 Lead Solver가 겸한다. 별도 상시 Orchestrator는 만들지 않는다.

선택 우선순위는 다음과 같다.

1. 재현 가능한 취약 동작이 있는가
2. 필요한 exploit primitive까지의 거리가 짧은가
3. 바이너리 보호 기법과 제공된 libc 환경에서 실현 가능한가
4. 다음 실험으로 빠르게 반증하거나 강화할 수 있는가

선택되지 않은 탐색 작업은 중단하지만 요약은 `state.json`에 보존한다. 선택 전략이 반증되면 폐기 후보를 무작정 다시 조사하지 않고, 보존된 증거를 바탕으로 다음 후보를 선택한다.

## 10. Lead Solver 반복 루프

Lead Solver는 고정된 분석 단계를 따르지 않는다.

```python
while not solved and within_budget:
    state = load_compact_state()
    goal = choose_highest_value_missing_capability(state)
    hypothesis = select_or_create_hypothesis(goal)
    experiment = design_minimal_discriminating_experiment(hypothesis)
    evidence = run_with_best_tool(experiment)
    update_facts_hypotheses_and_capabilities(evidence)

    if evidence_justifies_exploit_change:
        patch_exploit()
        execution = run_relevant_exploit_stage()

    if flag_candidate_found(execution):
        verify_flag()
    elif hypothesis_refuted:
        select_next_strategy()
```

IDA, GDB, Shell과 pwntools 사이를 자유롭게 왕복한다. “정적 분석 완료 후 동적 분석”과 같은 단계 게이트는 두지 않는다.

## 11. 최소 상태

`state.json`에는 실행 재개, 근거 추적과 중복 방지에 필요한 정보만 기록한다. 전체 대화나 raw 도구 출력은 상태에 넣지 않는다.

```json
{
  "status": "solving",
  "facts": [],
  "evidence": [],
  "hypotheses": [],
  "experiments": [],
  "capabilities": {},
  "current_strategy": {},
  "discarded_strategies": [],
  "current_blockers": [],
  "next_experiment_id": null,
  "attempts": 0,
  "remaining_budget": {},
  "local_verified": false,
  "remote_verified": false
}
```

상세 schema는 `references/state-model.md`에서 필요할 때만 읽는다.

- **Fact:** 도구로 확인된 주장. 최소 하나의 Evidence ID가 필요하다.
- **Evidence:** 도구, 세션, 인자 hash, artifact 경로, raw output hash와 짧은 요약.
- **Hypothesis:** suspected, static-confirmed, runtime-confirmed, primitive-confirmed, exploit-confirmed, rejected 상태를 가진다.
- **Experiment:** 하나의 가설을 확인하거나 반박하는 최소 실험.
- **Strategy:** 필요한 capability, 전제, blocker와 시도 횟수.

Capability는 `missing`, `candidate`, `confirmed`, `invalidated` 중 하나다. `confirmed` 전에는 주소 mapping, page alignment, cyclic offset, 메모리/RIP 제어 또는 clean reproduction 같은 결정론적 검증을 통과해야 한다.

초기 capability 목록은 다음으로 제한한다.

```text
vulnerable_path_reached
crash
controlled_input
controlled_overflow
controlled_read
controlled_write
heap_leak
stack_leak
pie_leak
libc_leak
arbitrary_read
arbitrary_write
instruction_pointer_control
stack_pivot
code_execution
interactive_shell
flag_read
flag_verified
```

장황한 사고 과정은 저장하지 않는다. `notes.md`에는 확인된 사실, 현재 가설, 현재 blocker와 다음 실험만 기록한다. raw IDA/GDB 출력은 artifact 파일로 저장하고 compact state에는 Evidence ID와 경로만 넣는다.

## 12. 정체와 전략 전환

다음 중 하나가 발생하면 현재 전략을 재평가한다.

- 같은 실패 원인이 세 번 반복됨
- 도구 호출 12회 동안 새로운 사실이나 primitive가 추가되지 않음
- 새로운 Evidence 없이 exploit 실행이 세 번 반복됨
- 필수 primitive가 현재 제약에서 불가능하다고 증명됨
- 로컬 exploit은 성공하지만 깨끗한 재실행에서 재현되지 않음

실패 문구가 달라도 같은 근본 원인이면 동일한 normalized failure signature로 집계한다. 재평가 시 현재 전략의 전제를 `confirmed`, `unknown`, `contradicted`로 분류하고 반박된 전제가 있으면 전략을 폐기한다.

별도의 상시 Reviewer는 만들지 않는다. 먼저 Lead Solver가 보존된 Explorer 결과에서 다음 후보를 선택한다. 후보가 모두 약하거나 독립 전략이 두 개 이상이면 새로운 가설에 한해 읽기 전용 Explorer를 최대 2개 다시 실행한다.

## 13. 도구 런타임과 세션 계약

### IDA

1. 현재 Codex에 등록된 `idapro` MCP가 응답하면 우선 사용한다.
2. MCP가 응답하지 않으면 Windows 전용 Python `C:\Users\RYZEN1\.ctf-ida-agent\venv\Scripts\python.exe`에서 `idapro`/idalib를 사용한다.
3. IDA를 사용할 수 없으면 `objdump`, `readelf`, `nm`, `strings`로 저비용 fallback을 수행하고 blocker를 기록한다.

IDA 9.2.250902와 idalib 로딩은 현재 환경에서 검증되었다. 문제와 Explorer마다 별도 IDA DB를 사용한다.

### GDB/pwndbg

Codex MCP `pwndbg`는 다음 명령으로 WSL `Ubuntu-24.04`의 STDIO 서버를 실행한다.

```text
wsl.exe -d Ubuntu-24.04 --exec
/home/boblab04/mcp/pwndbg-mcp/.venv/bin/pwndbg-mcp
--transport stdio
--pwndbg gdb
```

검증된 MCP 도구는 다음과 같다.

```text
load_executable(executable_path, args?)
debug_control(action)
send_to_process(data)
eval_to_send_to_process(statement)
read_from_process(size?, timeout?)
interrupt_process(ctrl?)
pwndbg_status()
pwndbg_hard_reset()
list_pwndbg_commands()
telescope(statement, count?)
context(subsection?)
heap()
bins()
backtrace()
procinfo()
vmmap(pattern?)
xinfo(statement)
execute_command(command)
```

MCP는 stateful debugging의 기본 경로다. 비대화형 batch 명령이 훨씬 저렴하거나 MCP가 불가할 때만 WSL의 직접 GDB/PTY 또는 batch GDB를 fallback으로 사용한다.

각 Explorer는 별도 MCP 프로세스와 GDB 세션을 사용한다. 전략 선택 후 Explorer 세션을 종료한다. Lead Solver만 살아남은 GDB 세션과 canonical `exploit.py`를 소유한다.

`eval_to_send_to_process`와 `execute_command`는 임의 코드 실행 능력으로 취급한다. MCP는 STDIO로만 실행하고 HTTP/SSE listener를 열지 않는다.

### Process와 transcript

메뉴형 문제의 송수신은 bytes를 보존한다. transcript에는 timestamp, direction, raw bytes SHA-256과 printable representation을 기록한다. 디코딩 실패로 원본 bytes를 버리지 않는다.

## 14. 플래그 검증

성공은 다음 조건을 모두 만족해야 한다.

1. stdout, stderr 또는 명시된 플래그 파일에서 설정된 정규식과 일치하는 후보가 발견된다.
2. exploit을 깨끗한 프로세스에서 다시 실행해 같은 공격 흐름이 재현된다.
3. 원격 정보가 제공된 경우 사용자가 제공하거나 허가한 대상에 동일 exploit을 실행한다.
4. 실행 명령, stdout, stderr와 종료 상태를 transcript로 저장한다.
5. 단순 입력 echo와 플래그 후보를 구분한다.
6. 셸 획득은 무해한 challenge-response 문자열을 실행해 확인한다.

기본 패턴은 다음을 지원하되 `challenge.yaml`의 명시적 패턴을 우선한다.

```text
FLAG{...}
CTF{...}
<대회명>{...}
```

`result.json`은 다음 형식을 사용한다.

```json
{
  "status": "solved",
  "flag": "FLAG{example}",
  "exploit": "runs/2026-07-26T120000Z/babyheap/exploit.py",
  "local_verified": true,
  "remote_verified": true,
  "strategy": "tcache poisoning",
  "attempts": 17,
  "transcript": "runs/2026-07-26T120000Z/babyheap/transcripts/final.txt"
}
```

## 15. 오류 처리와 안전 경계

- 대상은 사용자가 제공한 CTF 바이너리와 접속 정보로 제한한다.
- 원격 연결은 `challenge.yaml`에 명시된 host와 port만 허용한다.
- 원격 정보가 없으면 임의의 호스트를 탐색하거나 주소를 추론하지 않는다.
- 명령과 exploit에 timeout을 적용한다.
- 원본 바이너리, libc와 loader를 수정하지 않는다.
- 대상 바이너리를 신뢰하지 않으며 가능한 경우 non-root 컨테이너에서 실행한다.
- 컨테이너에는 Docker socket, SSH key, 사용자 credential 또는 불필요한 host 경로를 전달하지 않는다.
- 문제 원본은 read-only, run workspace만 writable로 마운트한다.
- 네트워크는 기본 차단하고 manifest에 명시된 CTF 목적지만 예외로 허용한다.
- Explorer 또는 실패한 전략이 남긴 프로세스와 디버거 세션을 정리한다.
- 도구가 없으면 확인된 분석 결과와 정확한 blocker를 남기고 가능한 로컬 분석을 계속한다.
- 플래그 후보가 검증되지 않으면 `solved`로 기록하지 않는다.

## 16. 검증 계획

스킬 구조와 스크립트는 다음 순서로 검증한다.

1. `quick_validate.py`로 스킬 메타데이터와 디렉터리를 검사한다.
2. `inspect_binary.py`, `run_exploit.py`, `verify_flag.py`의 단위 테스트를 실행한다.
3. 간단한 ret2win 문제에서 Explorer 없이 해결되는지 확인한다.
4. 두 개 이상의 공격면을 가진 테스트 문제에서 조건부 Explorer와 전략 수렴을 확인한다.
5. 가짜 플래그 문자열만 출력하는 문제에서 검증기가 오탐하지 않는지 확인한다.
6. 중단 후 같은 작업공간에서 재개할 때 이미 반증된 가설을 반복하지 않는지 확인한다.
7. Evidence 없는 Fact 저장이 거부되는지 확인한다.
8. capability가 verifier 없이 `confirmed`로 전이되지 않는지 확인한다.
9. MCP 부재 시 idalib와 batch GDB fallback이 선택되는지 확인한다.
10. 두 Explorer의 IDA/GDB 세션과 artifact가 섞이지 않는지 확인한다.

## 17. MVP 범위

첫 버전에 포함한다.

- 단일 문제 풀이
- 조건부 Explorer 최대 3개
- Lead Solver 단일 작성자
- IDA MCP, GDB/pwndbg, Shell, pwntools 사용 계약
- 실행별 작업공간, 구조화된 Evidence 상태와 capability 추적
- idalib 및 직접 GDB fallback
- binary-safe transcript
- 로컬·허가된 원격 플래그 검증

첫 버전에서 제외한다.

- 여러 문제의 동시 처리
- 상시 Orchestrator와 상시 Reviewer
- 대규모 작업 큐
- 완전 자동 Docker 이미지 빌드와 목적지별 방화벽 생성
- 모든 heap 기법을 포괄하는 지식베이스
- CTF 플랫폼 자동 로그인 또는 문제 다운로드

이 제외 항목은 실제 사용에서 병목이 확인될 때 추가한다.
