# Local runtime and tool routing

Prefer available MCP tools because they preserve state and structured evidence.

## IDA

- MCP server name: `idapro`
- IDA installation: `C:\Users\RYZEN1\Desktop\ida`
- idalib Python:
  `C:\Users\RYZEN1\.ctf-ida-agent\venv\Scripts\python.exe`
- The IDA RPC bridge normally listens at `http://127.0.0.1:13337`.

Use IDA for decompilation, xrefs, types, and semantic static analysis. Treat
decompiler output as a hypothesis until dynamic evidence or exact assembly
supports it. If the MCP is absent, use idalib scripts; fall back to local
`objdump`, `readelf`, `nm`, and `strings`.

## GDB and pwndbg

- MCP server name: `pwndbg`
- WSL distro: `Ubuntu-24.04`
- pwndbg: `/home/boblab04/pwndbg`
- pwndbg MCP executable:
  `/home/boblab04/mcp/pwndbg-mcp/.venv/bin/pwndbg-mcp`

Useful MCP operations include `load_executable`, `debug_control`, `context`,
`backtrace`, `vmmap`, `xinfo`, `telescope`, `heap`, `bins`, and
`execute_command`. Use `pwndbg_hard_reset` between independent reproductions.

If the MCP is absent, invoke WSL GDB with pwndbg directly. Convert Windows paths
with `wslpath`; do not guess `/mnt/<drive>` paths when quoting or spaces matter.

## Tool choice

Use pwntools for protocol automation and exploit delivery, pwndbg for runtime
truth, and IDA/idalib for semantic static analysis. Do not wait for every tool:
start with what is available and record exact fallback failures in `notes.md`.
