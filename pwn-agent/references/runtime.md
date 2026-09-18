# Local runtime and tool routing

Use Ubuntu-local capabilities and store analysis artifacts in the owning session.

## Managed Python

Run pwntools through the managed environment:

```text
uv run --with pwntools python3 exploit.py
```

If an optional tool is unavailable, record the degradation and use the native
fallback. Do not assume a `python` executable exists.

## Debugging and analysis

- Preferred GDB MCP: `gdb`; native fallback: `gdb`, `readelf`, `objdump`, `nm`,
  `strings`, and `strace`.
- Preferred IDA MCP: `idalib`; native fallback: `readelf`, `objdump`, `nm`, and
  `strings`.

Use GDB for controlled runtime evidence and idalib for decompilation, xrefs, and
types. Treat decompiler output as a hypothesis until assembly or runtime evidence
supports it. Restart the debugger between independent reproductions.
