# Feature Request: Security Research Workflow Improvements

**Source:** Real-world embedded security research session — ASUS RT-AX53U router (MIPS32r2, stripped binaries, remote gdbserver over TCP, Ghidra decompilation as sole "source")

**Context:** These requests come from a full bug-bounty session: live filesystem dump, Ghidra decompilation of 13 binaries (3647 functions), static analysis producing 26 leads, remote gdbserver attached to httpd. The gap is between "I have static leads" and "I can efficiently verify them dynamically."

**Status:** Implemented for 0.4.

| Request | Delivery |
|---|---|
| Logging breakpoints | `gdb_log_breakpoint`, `gdb_log_read`, `gdb_log_list`, `gdb_log_delete` with bounded JSON/JSONL retention |
| Crash catcher | `gdb_catch_crash` backed by retained execution jobs and stop-pinned evidence |
| Connection profiles | `gdb_connect_profile` with inline architecture/sysroot/endian/setup |
| Symbols from JSON | `gdb_load_symbols_json` via a temporary `objcopy` companion ELF |
| Compact notifications | `compact` on remote connect/disconnect, plus counts, summaries, and event cursor spans |
| Bulk breakpoints | `locations` on `gdb_breakpoint`, with independent partial-success results |

Crash catching returns a retained job by default so an agent can trigger the
external request after arming it; set `wait_timeout` for the original one-call
blocking behavior. Poll/cancel through `gdb_execution_status` and
`gdb_execution_cancel`. JSON symbol loading uses a local ELF mirror and keeps
Ghidra/JVM analysis outside the live debugger process.

---

## 1. Logging Breakpoints (aligns with ROADMAP P3.2)

**Problem:** Tracing data flow through a live binary requires setting breakpoints at sinks (system(), strcpy(), popen()), logging argument values, and auto-continuing. Currently requires manual loop: set breakpoint → wait for stop → read registers/args → continue → repeat. Each iteration is 3-4 MCP round-trips.

**Proposed tool:** `gdb_log_breakpoint`
```
gdb_log_breakpoint(
    session_id,
    location="*0x0043ead4",          # address or symbol
    expressions=["$a0", "$a1", "(char*)$a0"],  # what to log
    condition="",                      # optional conditional
    limit=100,                         # max hits before auto-disable
    backtrace_depth=4                  # 0 = no backtrace per hit
)
```
Returns a `log_id`. Each hit auto-evaluates expressions, optionally captures a short backtrace, stores the result, and continues without stopping.

**Poll tool:** `gdb_log_read(session_id, log_id, after_cursor=0, limit=50)`
Returns captured hits as structured data:
```json
[{"hit": 1, "address": "0x0043ead4", "expressions": {"$a0": "0x7fffe430", "(char*)$a0": "ping 192.168.50.2"}, "backtrace": [...], "timestamp": ...}]
```

**Why this matters for security research:**
- Set logging breakpoints on all 8 `system()` call sites in httpd
- Send HTTP requests and see which ones get hit and with what arguments
- Find which user inputs reach dangerous sinks without manual stepping
- The ROADMAP P3.2 "bounded breakpoint command/action traces" is exactly this

---

## 2. Crash Catcher

**Problem:** Investigating crashes (DOS-001: httpd crash on apply.cgi) requires: continue target → trigger crash externally → capture crash state. Currently: `gdb_continue` → external HTTP request → `gdb_wait_for_stop` with timeout guessing → separate calls for backtrace/registers/memory. If timeout too short, miss the crash. If too long, waste time.

**Proposed tool:** `gdb_catch_crash`
```
gdb_catch_crash(
    session_id,
    signals=["SIGSEGV", "SIGABRT", "SIGBUS"],  # default: all fatal signals
    collect=["backtrace", "registers", "memory:$sp,256"],
    timeout_sec=60
)
```
Continues execution, waits for a signal/crash (not a regular breakpoint), auto-collects requested evidence when it triggers, returns everything in one response.

**Why this matters:**
- One call replaces 5+ calls and timing coordination
- Critical for crash analysis — the primary path to finding exploitable bugs in stripped binaries
- Could also catch SIGPIPE, SIGFPE etc. for edge-case bug hunting

---

## 3. Connection Profiles

**Problem:** Every debug session starts with 3 commands: `set architecture mips`, `set sysroot /long/path/...`, `target remote host:port`. For embedded targets this never changes. `gdb_batch` helps but still requires passing the same 3 strings every time.

**Proposed tool:** `gdb_connect_profile`
```
gdb_connect_profile(
    session_id,
    profile={
        "architecture": "mips",
        "sysroot": "/home/witchtape/bug-bounty/asus-router/firmware/live-filesystem/filesystem",
        "target": "192.168.50.1:9999",
        "commands": ["set endian little"]  # optional extra setup
    }
)
```
Executes all setup + connect in one atomic call, returns connected session state.

Could also support named profiles stored in a JSON file the server reads — but inline is the minimum viable version.

---

## 4. Symbol Loading from JSON

**Problem:** We have Ghidra's `functions.json` and `exports.json` with every function name and address. GDB shows raw hex in backtraces because the binary is stripped. Loading symbols manually means generating a GDB script with hundreds of `add-symbol-file` calls or building custom ELFs.

**Proposed tool:** `gdb_load_symbols_json`
```
gdb_load_symbols_json(
    session_id,
    file="/path/to/functions.json",
    format="ghidra-decomp",     # knows the schema
    base_address="0x00400000"   # for PIE adjustment, optional
)
```
Parses the JSON, defines function symbols in GDB (via `add-symbol-file` with a generated minimal ELF, or GDB's Python API if available). Backtraces now show `apply_cgi_handler` instead of `0x0043ead4`.

**Supported formats:**
- `ghidra-decomp`: the `functions.json` schema from ghidra-decomp tool (address, name, body_ranges)
- `exports`: simpler `[{address, name}]` array
- `plain`: `address name\n` text file

**Why this matters:**
- Stripped binary debugging is nearly universal in embedded/IoT security research
- Ghidra is the standard decompiler — its output format is predictable
- This bridges static analysis (Ghidra) and dynamic analysis (GDB) — the exact gap ROADMAP P3.5 identifies

---

## 5. Compact Notification Mode

**Problem:** `gdb_remote_connect` returns ~4KB of library-loaded notifications (18 libs × ~200 bytes each). `gdb_remote_disconnect` returns similar unload spam. These consume agent context for zero analytical value.

**Proposed:** Add an optional `compact` or `summary_notifications` parameter:
```
gdb_remote_connect(session_id, target, compact=true)
```
Response includes `"libraries_loaded": 18` instead of 18 full notification objects. The individual notifications still exist in the event stream for anyone who needs them via `gdb_events`.

**Not a new tool** — just a parameter on existing connect/disconnect tools. Low effort, high context savings for agent workflows.

---

## 6. Bulk Breakpoints

**Problem:** Setting breakpoints at all dangerous sinks identified in static analysis (8 system() sites, 5 popen() sites, 9 strcpy() sites = 22 breakpoints) requires 22 sequential `gdb_breakpoint` calls.

**Proposed:** Allow `gdb_breakpoint` to accept a list:
```
gdb_breakpoint(
    session_id,
    locations=["*0x0043ead4", "*0x00429e14", "*0x0044f054", ...],
    condition="",
    temporary=false
)
```
Returns list of breakpoint numbers. Failing one doesn't abort the rest.

---

## Priority for This Research

1. **Logging breakpoints** — unlocks efficient data-flow tracing (P3.2)
2. **Crash catcher** — unlocks crash root-cause analysis (DOS-001)
3. **Symbol loading from JSON** — makes all debugging output readable (P3.5 bridge)
4. **Connection profiles** — quality of life, saves 3 calls per session
5. **Compact notifications** — context efficiency
6. **Bulk breakpoints** — convenience

Items 1 and 2 are the difference between "I can debug" and "I can efficiently hunt vulnerabilities at scale."
