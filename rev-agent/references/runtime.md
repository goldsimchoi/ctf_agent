# Runtime and analysis routing

Use `python3`, never an assumed `python` executable. Prefer the `idalib` MCP for
function discovery, call graphs, xrefs, types, decompilation, and local data-flow
queries. Prefer the `gdb` MCP for a controlled execution, breakpoints, register
and memory observations, and traces. Store resulting IDA work in `rev/ida/` and
GDB logs, scripts, and dumps in `rev/gdb/` for the owning session only.

If MCP is unavailable, use native `file`, `readelf`, `objdump`, `nm`, `strings`,
`gdb`, `strace`, and Python 3. Optional radare2, capstone, angr, unicorn, z3,
LIEF, binwalk, ltrace, and QEMU are accelerators, not prerequisites. Record a
missing tool as a degraded capability and take the documented native fallback.

Decompiler output is a hypothesis, not proof. Check a proposed flow against
assembly, xrefs, or controlled runtime behavior before treating it as a fact.
When packing, runtime decoding, anti-debugging, or self-modifying behavior makes
static evidence diverge, stop expanding static summaries and switch to a GDB
trace or a session-local memory artifact.
