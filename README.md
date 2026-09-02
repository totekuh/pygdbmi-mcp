# pygdbmi-mcp

MCP server for GDB. Uses pygdbmi under the hood.

## Install

```bash
git clone https://github.com/totekuh/pygdbmi-mcp.git
cd pygdbmi-mcp
pipx install .
```

This puts `pygdbmi-mcp` on your `PATH`. If you don't have `pipx`, install it with `sudo apt install pipx && pipx ensurepath` (or `python3 -m pip install --user pipx`).

## Add to Claude Code

```bash
claude mcp add pygdbmi-mcp -- pygdbmi-mcp
```

## Result contract

Every tool returns the same versioned object. GDB `^error` records are failures,
not successful strings wearing an `ERROR:` fake moustache.

```json
{
  "schema": "pygdbmi.mcp/1",
  "ok": true,
  "result": {},
  "error": null,
  "session": {"session_id": "gdb-1", "run_state": "stopped", "stop_id": 3}
}
```

Errors carry a stable code, operation, retryability, bounded details, and
recovery hints. Session tools expose target kind, PID/thread group, selected
thread/frame, exit code, architecture, endianness, pointer width, and last
error. All commands are correlated by numeric GDB/MI tokens through one reader
thread per session.

Direct execution tools return as soon as GDB reports `^running`. Use the
previous `stop_id` with `gdb_wait_for_stop`, or use `gdb_execution_start` plus
`gdb_execution_status` for a retained start/poll/cancel operation. Jobs survive
MCP client calls for the lifetime of the server process; they do not pretend to
survive a server restart. At a stop, use `gdb_context` for a compact atomic
snapshot so evidence cannot be mixed across stop epochs.

For sink tracing, create `gdb_log_breakpoint`, run or continue normally, then
page `gdb_log_read`; matching stops are captured and resumed inside the server.
For crash work, `gdb_catch_crash` returns a retained execution job immediately
unless `wait_timeout` is requested. Poll it with `gdb_execution_status` and
cancel a timed-out/running watch with `gdb_execution_cancel`. Crash-job timeout
does not secretly interrupt the target, matching ordinary execution-job
semantics.

`gdb_load_symbols_json` accepts `ghidra-decomp`, `exports`, and plain address/name
inputs. It needs a local ELF mirror and GNU `objcopy`; for a stopped PIE it can
infer the runtime image base from `gdb_modules`, while `base_address` remains
available for remote layouts that cannot expose mappings. If Ghidra rebased the
analysis image independently of the ELF link image, pass that value separately
as `analysis_base_address`.

## Tools (89)

### Session
| Tool | Description |
|---|---|
| `gdb_start` | Start a session; accepts GDB args, exact inferior argv, and working directory |
| `gdb_stop` | Clean up by target-aware `auto`/`kill`/`detach`/`disconnect` policy |
| `gdb_list_sessions` | List active sessions |

### Control plane
| Tool | Description |
|---|---|
| `gdb_session_status` | Structured run state, current stop epoch, and session metadata |
| `gdb_events` | Bounded cursor-based polling for asynchronous MI events and inferior output |
| `gdb_wait_for_stop` | Wait for a newer stop epoch or inferior exit without issuing another resume |
| `gdb_context` | Compact stop-pinned frame/register/stack/disassembly bundle with optional expansion |
| `gdb_output_page` | Retrieve retained console output by command ID and offset |
| `gdb_batch` | Run 1–32 commands atomically, optionally pinned to a `stop_id` |
| `gdb_inferior_io` | Cursor-page bounded stdout/stderr from a session-owned PTY |
| `gdb_inferior_stdin` | Write bounded UTF-8, hex, or base64 input to the inferior PTY |
| `gdb_execution_status` | Read or long-poll a retained execution job by revision |
| `gdb_execution_list` | List the bounded per-session execution job history |
| `gdb_execution_cancel` | Idempotently cancel an active/timed-out job by interrupting its target |
| `gdb_catch_crash` | Continue under a retained fatal-signal filter and collect stop-pinned evidence |
| `gdb_capabilities` | Discover and cache a normalized GDB/MI and target capability manifest |
| `gdb_inferiors` | Refresh normalized inferior/thread-group topology and history |
| `gdb_select_inferior` | Select an inferior by stable numeric ID |
| `gdb_fork_policy` | Apply follow-fork, detach-on-fork, and scheduling policy with rollback |

### Load target
| Tool | Description |
|---|---|
| `gdb_load_binary` | Load executable + optional args |
| `gdb_attach` | Attach to PID |
| `gdb_remote_connect` | Connect to gdbserver/QEMU/OpenOCD, with optional compact notifications |
| `gdb_remote_disconnect` | Disconnect from remote, with optional compact notifications |
| `gdb_connect_profile` | Apply architecture/sysroot/endian setup and connect in one serialized call |
| `gdb_rr_replay` | Launch an optional local rr replay server and connect to it |
| `gdb_load_core` | Load core dump |
| `gdb_add_symbol_file` | Load debug symbols |

### Execute
| Tool | Description |
|---|---|
| `gdb_execution_start` | Start a retained run/continue/step/next/finish/until job |
| `gdb_run` | Start/restart program |
| `gdb_continue` | Continue after stop |
| `gdb_step` | Step into (source or instruction) |
| `gdb_next` | Step over (source or instruction) |
| `gdb_finish` | Run until function returns |
| `gdb_until` | Run until location |
| `gdb_interrupt` | Interrupt a running target and wait for a real stop epoch |
| `gdb_signal` | Send signal to inferior |
| `gdb_record_start` | Start `record btrace`/`record full`, with explicit automatic fallback |
| `gdb_record_status` | Inspect the active GDB recording backend |
| `gdb_record_stop` | Stop and discard the active recording |
| `gdb_reverse` | Reverse continue/step/next/finish |

### Breakpoints
| Tool | Description |
|---|---|
| `gdb_breakpoint` | Set one or up to 128 independently reported breakpoints |
| `gdb_log_breakpoint` | Log expressions/backtraces at a breakpoint and auto-continue |
| `gdb_log_read` | Cursor-page retained trace hits as JSON or JSONL |
| `gdb_log_list` | List managed logging breakpoints and hit counts |
| `gdb_log_delete` | Delete a logging breakpoint and retained evidence |
| `gdb_delete_breakpoint` | Delete by number |
| `gdb_enable_breakpoint` | Enable/disable |
| `gdb_list_breakpoints` | List all |
| `gdb_watchpoint` | Watch expression (write/read/access) |
| `gdb_catchpoint` | Catch syscall/signal/fork/exec/throw |

### Inspect
| Tool | Description |
|---|---|
| `gdb_backtrace` | Call stack, optionally with locals |
| `gdb_print` | Evaluate expression |
| `gdb_locals` | Local variables |
| `gdb_args` | Function arguments |
| `gdb_registers` | Register values (all or by name) |
| `gdb_info_threads` | List threads |
| `gdb_select_thread` | Switch thread |
| `gdb_select_frame` | Switch stack frame |

### Memory
| Tool | Description |
|---|---|
| `gdb_memory` | Read memory |
| `gdb_memory_write` | Write raw bytes |
| `gdb_memory_find` | Search memory for pattern |
| `gdb_disassemble` | Disassemble (function, address, N bytes) |
| `gdb_source_list` | View source code |

### Types & structs
| Tool | Description |
|---|---|
| `gdb_ptype` | Show type definition |
| `gdb_print_struct` | Pretty-print struct value |
| `gdb_sizeof` | Size of type/expression |
| `gdb_offsetof` | Field offset in struct |
| `gdb_cast_print` | Cast address to type and print |
| `gdb_info_types` | Search types by regex |
| `gdb_whatis` | Quick type check |

### Variable objects
| Tool | Description |
|---|---|
| `gdb_var_create` | Create a structured GDB/MI watch object |
| `gdb_var_update` | Fetch incremental changes |
| `gdb_var_children` | Page children of arrays/structs/classes |
| `gdb_var_assign` | Assign through a variable object |
| `gdb_var_delete` | Delete an object or its children |

### Symbols
| Tool | Description |
|---|---|
| `gdb_info_functions` | Search functions by regex |
| `gdb_info_variables` | Search global/static variables |
| `gdb_info_sharedlibs` | Loaded shared libraries |
| `gdb_info_files` | Sections and address ranges |
| `gdb_info_proc_mappings` | Process memory map |
| `gdb_modules` | Normalize mappings, ELF sections, build IDs, symbol files, and load slides |
| `gdb_address_info` | Resolve runtime address/expression to module identity, linked VA, RVA, and section |
| `gdb_load_symbols_json` | Convert Ghidra/plain address-name data to a temporary ELF symbol companion |

### Mutation
| Tool | Description |
|---|---|
| `gdb_set_variable` | Set variable/memory value |

### Settings
| Tool | Description |
|---|---|
| `gdb_set` | Set GDB option (ASLR, fork-mode, asm flavor, etc.) |
| `gdb_show` | Show GDB option |
| `gdb_debug_config` | Configure source substitutions, debug directories, and explicit debuginfod policy |
| `gdb_debug_status` | Show source/split-debug/sysroot/debuginfod settings |

### Raw
| Tool | Description |
|---|---|
| `gdb_command` | Send any GDB/MI or CLI command |

## Stability and bounds

- State-gated operations reject invalid `idle`/`running`/`stopped`/`exited`
  combinations before they hit GDB.
- MI strings, paths, expressions, breakpoint conditions, and exact argument
  vectors use centralized encoding. Embedded raw-command newlines and caller
  supplied MI tokens are rejected.
- Events, payloads, memory operations, context depth, disassembly, batch size,
  var-object children, timeouts, retained execution jobs, and retained command
  output are bounded.
- Execution jobs have monotonic revisions for efficient long polling, explicit
  terminal states, timeout-without-hidden-interrupt semantics, idempotent
  cancellation, and bounded oldest-terminal eviction. If a remote stub accepts
  an interrupt but never reports a stop, cancellation returns a typed
  `interrupt_timeout` and terminalizes the job as failed instead of leaving it
  wedged in `cancelling`.
- Managed logging breakpoints own only their matching breakpoint stops. They
  capture bounded expression/backtrace evidence, auto-continue, and do not
  advance the public stop epoch or terminate an execution job. Signal and
  unrelated breakpoint stops remain visible. Collocated ordinary/managed or
  managed/managed breakpoints are rejected because GDB/MI reports only one
  breakpoint owner at a shared address.
- Crash watches are retained execution jobs. Selected signal handling is made
  explicit, evidence is collected under one stop-pinned command lock, and the
  prior signal policy is restored before the job becomes terminal.
- Command replies expose notification counts, summaries, and event-cursor
  spans. Compact remote connect/disconnect replies omit the duplicate objects;
  the bounded event stream remains available for detailed inspection.
- Module evidence uses local ELF parsing for build IDs, debuglinks, sections,
  and load-slide calculation. JSON symbol import invokes `objcopy` as a bounded
  optional adapter and removes generated companions when the session closes.
- Inferiors are tracked independently across fork, exec, partial exit, and
  selection. Local cleanup kills every active inferior instead of trusting one
  stale selected PID. Fork policy rolls back if a multi-setting update fails.
- Capability discovery is cached per session, degrades individual failed probes
  into a manifest `errors` map, and is invalidated when target traits change.
- A recording backend accepting `record full` does not prove every later target
  instruction or syscall is recordable. Such target-specific failures surface
  as ordinary stops with the original GDB diagnostics retained in the event
  stream.
- MCP tool annotations identify read-only, destructive, idempotent, and
  open-world calls. Server instructions advertise the low-call-count workflow.
- Target cleanup defaults to kill for local inferiors, detach for attached
  processes, disconnect for remote targets, and quit for core/no-target sessions.

Linux `gdbserver --attach` has a sharp edge in all-stop mode: some builds send
Ctrl-C to process group `-PID`, which fails when the attached PID is not its
group leader. Set `non-stop on` before `gdb_remote_connect` (or put that command
in `gdb_connect_profile.commands`) to make GDB use the remote `vCtrlC` path.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q
```

The suite includes fake-controller race/failure tests plus real-GDB local,
attach, `gdbserver`, core-dump, quoting, paging, retained-job A/B and edge cases,
managed tracepoints, crash evidence, stripped-PIE symbol import, module/RVA
identity, record/reverse execution, source/debug configuration, multi-inferior
fork/exec, capability-cache A/B, burst output, and interactive inferior input.
