# Pwndbg MCP Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install a WSL-hosted pwndbg MCP server and register it as a local STDIO MCP server for Codex.

**Architecture:** Run `RocketMaDev/pwndbg-mcp` inside `Ubuntu-24.04`, where GDB 15 and pwndbg are already working. Codex launches the server through `wsl.exe` using STDIO; no TCP port is opened. Keep one GDB session per MCP process and use the existing WSL `~/.gdbinit` to load pwndbg.

**Tech Stack:** WSL2 Ubuntu 24.04, Python 3.12 venv, GDB 15, pwndbg, Model Context Protocol, Codex `config.toml`

## Global Constraints

- Use only the `Ubuntu-24.04` WSL distribution.
- Use STDIO transport; do not expose HTTP or SSE listeners.
- Install under `/home/boblab04/mcp/pwndbg-mcp`.
- Do not modify the existing `/home/boblab04/pwndbg` installation.
- Register the server as `pwndbg`.
- Treat `load_executable`, arbitrary GDB commands, and process-input evaluation as local code execution capabilities.

---

### Task 1: Install and validate pwndbg-mcp in WSL

**Files:**
- Create: `/home/boblab04/mcp/pwndbg-mcp/`
- Create: `/home/boblab04/mcp/pwndbg-mcp/.venv/`

**Interfaces:**
- Consumes: `/usr/bin/gdb` and `/home/boblab04/.gdbinit`
- Produces: `/home/boblab04/mcp/pwndbg-mcp/.venv/bin/pwndbg-mcp`

- [x] **Step 1: Verify the target does not conflict with an existing installation**

Run:

```powershell
wsl -d Ubuntu-24.04 -- bash -lc 'test ! -e /home/boblab04/mcp/pwndbg-mcp'
```

Expected: exit code `0`. If the directory exists, inspect its Git remote and working tree before changing it.

- [x] **Step 2: Clone the selected MCP implementation**

Run:

```powershell
wsl -d Ubuntu-24.04 -- git clone https://github.com/RocketMaDev/pwndbg-mcp.git /home/boblab04/mcp/pwndbg-mcp
```

Expected: repository cloned from `RocketMaDev/pwndbg-mcp`.

- [x] **Step 3: Create an isolated Python environment**

Run:

```powershell
wsl -d Ubuntu-24.04 -- python3 -m venv /home/boblab04/mcp/pwndbg-mcp/.venv
```

Expected: `.venv/bin/python` exists and reports Python 3.12.

- [x] **Step 4: Install the checked-out server**

Run:

```powershell
wsl -d Ubuntu-24.04 -- /home/boblab04/mcp/pwndbg-mcp/.venv/bin/pip install /home/boblab04/mcp/pwndbg-mcp
```

Expected: `.venv/bin/pwndbg-mcp` exists.

- [x] **Step 5: Verify the server command and pwndbg dependency**

Run:

```powershell
wsl -d Ubuntu-24.04 -- /home/boblab04/mcp/pwndbg-mcp/.venv/bin/pwndbg-mcp --help
wsl -d Ubuntu-24.04 -- bash -lc 'timeout 20s gdb -q -batch /bin/true -ex starti -ex context'
```

Expected: help lists `--transport {stdio,http,sse}`, and GDB prints pwndbg register/disassembly context.

### Task 2: Register and verify the Codex MCP server

**Files:**
- Modify: `C:\Users\RYZEN1\.codex\config.toml`

**Interfaces:**
- Consumes: `/home/boblab04/mcp/pwndbg-mcp/.venv/bin/pwndbg-mcp`
- Produces: Codex MCP server named `pwndbg`

- [x] **Step 1: Inspect the generated registration command**

Run:

```powershell
codex mcp add --help
```

Expected: the CLI supports registering a local command after `--`.

- [x] **Step 2: Register the WSL STDIO server**

Run:

```powershell
codex mcp add pwndbg -- wsl.exe -d Ubuntu-24.04 --exec /home/boblab04/mcp/pwndbg-mcp/.venv/bin/pwndbg-mcp --transport stdio --pwndbg gdb
```

Expected: `config.toml` gains `[mcp_servers.pwndbg]` with `wsl.exe` as the command and no URL.

- [x] **Step 3: Confirm Codex recognizes the registration**

Run:

```powershell
codex mcp get pwndbg
codex mcp list
```

Expected: `pwndbg` is enabled and uses STDIO.

- [ ] **Step 4: Restart Codex and inspect exposed tools**

After restarting Codex, search for these tools:

```text
load_executable
execute_command
debug_control
context
vmmap
bins
```

Expected: the `pwndbg` MCP namespace exposes the server tools.

- [x] **Step 5: Perform an end-to-end smoke test**

Use MCP tools to load `/bin/true`, start execution, request `context`, request `vmmap`, and terminate/reset the session.

Expected:

- the inferior stops at an executable address;
- `context` returns registers and disassembly;
- `vmmap` returns mapped regions;
- no HTTP/SSE port is listening for the MCP server;
- the MCP process exits when the Codex session closes.

### Task 3: Record the verified tool contract in the pwn-agent design

**Files:**
- Modify: `C:\Users\RYZEN1\Desktop\CTF\docs\superpowers\specs\2026-07-26-pwn-agent-design.md`

**Interfaces:**
- Consumes: verified MCP tool names from Task 2
- Produces: an exact pwndbg MCP contract for the future `pwn-agent` skill

- [x] **Step 1: Add the runtime selection rule**

Add:

```text
Use the pwndbg MCP tools for stateful debugging. Use direct WSL shell commands only when the MCP server is unavailable or a noninteractive batch command is substantially cheaper.
```

- [x] **Step 2: Add session ownership rules**

Add:

```text
Each active Explorer uses its own MCP server process and GDB session. After strategy selection, terminate Explorer sessions. The Lead Solver is the sole owner of the surviving GDB session.
```

- [x] **Step 3: Add the verified tool inventory**

Document only tool names and argument shapes confirmed after the Codex restart. Do not copy assumed schemas from the upstream README.

- [x] **Step 4: Review the design for transport and safety consistency**

Run:

```powershell
rg -n "pwndbg|HTTP|SSE|STDIO|GDB session|Explorer" C:\Users\RYZEN1\Desktop\CTF\docs\superpowers\specs\2026-07-26-pwn-agent-design.md
```

Expected: STDIO is the only configured transport, and session ownership does not permit concurrent mutation.
