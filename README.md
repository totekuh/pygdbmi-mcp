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

## Tools (52)

### Session
| Tool | Description |
|---|---|
| `gdb_start` | Start new GDB session (supports `gdb_path="gdb-multiarch"`) |
| `gdb_stop` | Destroy a session |
| `gdb_list_sessions` | List active sessions |

### Load target
| Tool | Description |
|---|---|
| `gdb_load_binary` | Load executable + optional args |
| `gdb_attach` | Attach to PID |
| `gdb_remote_connect` | Connect to gdbserver/QEMU/OpenOCD |
| `gdb_remote_disconnect` | Disconnect from remote |
| `gdb_load_core` | Load core dump |
| `gdb_add_symbol_file` | Load debug symbols |

### Execute
| Tool | Description |
|---|---|
| `gdb_run` | Start/restart program |
| `gdb_continue` | Continue after stop |
| `gdb_step` | Step into (source or instruction) |
| `gdb_next` | Step over (source or instruction) |
| `gdb_finish` | Run until function returns |
| `gdb_until` | Run until location |
| `gdb_interrupt` | SIGINT the GDB process to regain control |
| `gdb_signal` | Send signal to inferior |

### Breakpoints
| Tool | Description |
|---|---|
| `gdb_breakpoint` | Set breakpoint (conditional, temporary, hardware) |
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

### Symbols
| Tool | Description |
|---|---|
| `gdb_info_functions` | Search functions by regex |
| `gdb_info_variables` | Search global/static variables |
| `gdb_info_sharedlibs` | Loaded shared libraries |
| `gdb_info_files` | Sections and address ranges |
| `gdb_info_proc_mappings` | Process memory map |

### Mutation
| Tool | Description |
|---|---|
| `gdb_set_variable` | Set variable/memory value |

### Settings
| Tool | Description |
|---|---|
| `gdb_set` | Set GDB option (ASLR, fork-mode, asm flavor, etc.) |
| `gdb_show` | Show GDB option |

### Raw
| Tool | Description |
|---|---|
| `gdb_command` | Send any GDB/MI or CLI command |
