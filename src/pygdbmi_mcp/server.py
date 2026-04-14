from __future__ import annotations

import os
import signal
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from mcp.server.fastmcp import FastMCP
from pygdbmi.gdbcontroller import GdbController


@dataclass
class GdbSession:
    controller: GdbController
    binary: str | None = None
    pid: int | None = None


@dataclass
class GdbManager:
    sessions: dict[str, GdbSession] = field(default_factory=dict)
    _counter: int = 0

    def create(self, gdb_path: str = "gdb", gdb_args: list[str] | None = None) -> str:
        self._counter += 1
        sid = f"gdb-{self._counter}"
        args = gdb_args or []
        ctrl = GdbController(
            command=[gdb_path, "--nx", "--quiet", "--interpreter=mi3"]
        )
        if args:
            ctrl.write(f"set args {' '.join(args)}", timeout_sec=5)
        self.sessions[sid] = GdbSession(controller=ctrl)
        return sid

    def get(self, session_id: str) -> GdbSession:
        if session_id not in self.sessions:
            raise ValueError(
                f"No GDB session with id '{session_id}'. Active: {list(self.sessions.keys())}"
            )
        return self.sessions[session_id]

    def destroy(self, session_id: str) -> None:
        session = self.get(session_id)
        try:
            session.controller.exit()
        except Exception:
            pass
        del self.sessions[session_id]

    def destroy_all(self) -> None:
        for sid in list(self.sessions):
            self.destroy(sid)


manager = GdbManager()


@asynccontextmanager
async def lifespan(server: FastMCP):
    yield
    manager.destroy_all()


mcp = FastMCP("pygdbmi-mcp", lifespan=lifespan)


def _fmt_response(responses: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for r in responses:
        msg = r.get("message")
        payload = r.get("payload")
        stream = r.get("stream")
        token = r.get("token")

        if msg == "done" and payload is None:
            continue

        # GDB/MI error responses
        if msg == "error":
            error_msg = payload.get("msg", payload) if isinstance(payload, dict) else payload
            lines.append(f"ERROR: {error_msg}")
        # Console/target/log stream output (strings only)
        elif stream == "stdout" and payload and isinstance(payload, str):
            lines.append(payload)
        # Result records with payload
        elif msg and payload:
            lines.append(f"[{msg}] {payload}")
        # Stream output with non-string payload
        elif stream and payload:
            lines.append(str(payload))
        elif msg:
            lines.append(f"[{msg}]")
    return "\n".join(lines) if lines else "(no output)"


def _send_sigint(session: GdbSession) -> None:
    """Send SIGINT directly to the GDB subprocess.

    This works even when GDB is blocked waiting for the inferior,
    unlike MI commands which go through the same blocked pipe.
    """
    pid = session.controller.gdb_process.pid
    os.kill(pid, signal.SIGINT)


# ===========================================================================
# Session management
# ===========================================================================

@mcp.tool()
def gdb_start(gdb_path: str = "gdb") -> str:
    """Start a new GDB session. Returns a session ID used for all other commands."""
    sid = manager.create(gdb_path=gdb_path)
    return f"Session started: {sid}"


@mcp.tool()
def gdb_stop(session_id: str) -> str:
    """Stop and destroy a GDB session."""
    manager.destroy(session_id)
    return f"Session {session_id} destroyed."


@mcp.tool()
def gdb_list_sessions() -> str:
    """List active GDB sessions."""
    if not manager.sessions:
        return "No active sessions."
    lines = []
    for sid, s in manager.sessions.items():
        info = f"{sid}: binary={s.binary or '(none)'} pid={s.pid or '(none)'}"
        lines.append(info)
    return "\n".join(lines)


# ===========================================================================
# Raw GDB/MI command
# ===========================================================================

@mcp.tool()
def gdb_command(session_id: str, command: str, timeout_sec: int = 30) -> str:
    """Send a raw GDB/MI or CLI command to a session and return the response.

    Examples:
        gdb_command("gdb-1", "-file-exec-and-symbols /path/to/binary")
        gdb_command("gdb-1", "break main")
        gdb_command("gdb-1", "-exec-run")
    """
    session = manager.get(session_id)
    responses = session.controller.write(command, timeout_sec=timeout_sec)
    return _fmt_response(responses)


# ===========================================================================
# Loading targets
# ===========================================================================

@mcp.tool()
def gdb_load_binary(session_id: str, binary_path: str, args: str = "") -> str:
    """Load a binary into a GDB session. Optionally set program arguments."""
    session = manager.get(session_id)
    binary_path = os.path.expanduser(binary_path)
    responses = session.controller.write(
        f"-file-exec-and-symbols {binary_path}", timeout_sec=10
    )
    session.binary = binary_path
    out = _fmt_response(responses)
    if args:
        session.controller.write(f"-exec-arguments {args}", timeout_sec=5)
        out += f"\nArguments set: {args}"
    return out


@mcp.tool()
def gdb_attach(session_id: str, pid: int) -> str:
    """Attach GDB to a running process by PID."""
    session = manager.get(session_id)
    responses = session.controller.write(f"-target-attach {pid}", timeout_sec=10)
    session.pid = pid
    return _fmt_response(responses)


@mcp.tool()
def gdb_remote_connect(
    session_id: str, target: str, extended: bool = False
) -> str:
    """Connect to a remote GDB server (gdbserver, QEMU, OpenOCD, etc.).

    Args:
        target: host:port or device path (e.g. "localhost:1234", "/dev/ttyUSB0")
        extended: use extended-remote mode (allows run/restart on remote)
    """
    session = manager.get(session_id)
    mode = "extended-remote" if extended else "remote"
    responses = session.controller.write(
        f"-target-select {mode} {target}", timeout_sec=30
    )
    return _fmt_response(responses)


@mcp.tool()
def gdb_remote_disconnect(session_id: str) -> str:
    """Disconnect from a remote target without killing it."""
    session = manager.get(session_id)
    responses = session.controller.write("-target-disconnect", timeout_sec=10)
    return _fmt_response(responses)


@mcp.tool()
def gdb_load_core(session_id: str, core_path: str, binary_path: str = "") -> str:
    """Load a core dump for post-mortem analysis.

    Args:
        core_path: path to the core dump file
        binary_path: optional path to the binary that generated the core
    """
    session = manager.get(session_id)
    core_path = os.path.expanduser(core_path)
    out_parts = []
    if binary_path:
        binary_path = os.path.expanduser(binary_path)
        resp = session.controller.write(
            f"-file-exec-and-symbols {binary_path}", timeout_sec=10
        )
        session.binary = binary_path
        out_parts.append(_fmt_response(resp))
    responses = session.controller.write(f"core-file {core_path}", timeout_sec=30)
    out_parts.append(_fmt_response(responses))
    return "\n".join(out_parts)


@mcp.tool()
def gdb_add_symbol_file(
    session_id: str, symbol_file: str, address: str = ""
) -> str:
    """Load additional symbol/debug info from a file.

    Essential for stripped binaries, split debug info, or remote targets.

    Args:
        symbol_file: path to the symbol file (.debug, .elf, etc.)
        address: optional base address for position-dependent symbols
    """
    session = manager.get(session_id)
    symbol_file = os.path.expanduser(symbol_file)
    cmd = f"add-symbol-file {symbol_file}"
    if address:
        cmd += f" {address}"
    responses = session.controller.write(cmd, timeout_sec=10)
    return _fmt_response(responses)


# ===========================================================================
# Execution control
# ===========================================================================

@mcp.tool()
def gdb_run(session_id: str) -> str:
    """Start (or restart) the loaded program."""
    session = manager.get(session_id)
    responses = session.controller.write("-exec-run", timeout_sec=30)
    return _fmt_response(responses)


@mcp.tool()
def gdb_continue(session_id: str) -> str:
    """Continue execution after a breakpoint/stop."""
    session = manager.get(session_id)
    responses = session.controller.write("-exec-continue", timeout_sec=30)
    return _fmt_response(responses)


@mcp.tool()
def gdb_step(session_id: str, instruction: bool = False) -> str:
    """Step one source line (or one instruction if instruction=True)."""
    session = manager.get(session_id)
    cmd = "-exec-step-instruction" if instruction else "-exec-step"
    responses = session.controller.write(cmd, timeout_sec=10)
    return _fmt_response(responses)


@mcp.tool()
def gdb_next(session_id: str, instruction: bool = False) -> str:
    """Step over one source line (or one instruction if instruction=True)."""
    session = manager.get(session_id)
    cmd = "-exec-next-instruction" if instruction else "-exec-next"
    responses = session.controller.write(cmd, timeout_sec=10)
    return _fmt_response(responses)


@mcp.tool()
def gdb_finish(session_id: str) -> str:
    """Execute until the current function returns."""
    session = manager.get(session_id)
    responses = session.controller.write("-exec-finish", timeout_sec=30)
    return _fmt_response(responses)


@mcp.tool()
def gdb_until(session_id: str, location: str) -> str:
    """Continue execution until a location is reached (like a temporary breakpoint + continue).

    Args:
        location: e.g. "file.c:50", "main+20", "*0x400120"
    """
    session = manager.get(session_id)
    responses = session.controller.write(f"-exec-until {location}", timeout_sec=30)
    return _fmt_response(responses)


@mcp.tool()
def gdb_interrupt(session_id: str) -> str:
    """Interrupt (pause) the running inferior by sending SIGINT to GDB.

    This sends SIGINT directly to the GDB subprocess, which works even when
    GDB is blocked waiting for the inferior (e.g. after continue with no
    breakpoint hit). This is the reliable way to regain control.
    """
    session = manager.get(session_id)
    _send_sigint(session)
    try:
        responses = session.controller.get_gdb_response(timeout_sec=5)
        return _fmt_response(responses)
    except Exception:
        return "SIGINT sent to GDB. Session should be responsive again."


@mcp.tool()
def gdb_signal(session_id: str, sig: str) -> str:
    """Send a signal to the inferior process.

    Args:
        sig: signal name or number (e.g. "SIGINT", "SIGCONT", "9")
    """
    session = manager.get(session_id)
    responses = session.controller.write(f"signal {sig}", timeout_sec=10)
    return _fmt_response(responses)


# ===========================================================================
# Breakpoints & watchpoints & catchpoints
# ===========================================================================

@mcp.tool()
def gdb_breakpoint(
    session_id: str,
    location: str,
    condition: str = "",
    temporary: bool = False,
    hardware: bool = False,
) -> str:
    """Set a breakpoint.

    Args:
        location: e.g. "main", "file.c:42", "*0x400080"
        condition: optional breakpoint condition expression
        temporary: if True, breakpoint is auto-deleted after first hit
        hardware: if True, use a hardware breakpoint
    """
    session = manager.get(session_id)
    cmd = "-break-insert"
    if temporary:
        cmd += " -t"
    if hardware:
        cmd += " -h"
    if condition:
        cmd += f' -c "{condition}"'
    cmd += f" {location}"
    responses = session.controller.write(cmd, timeout_sec=10)
    return _fmt_response(responses)


@mcp.tool()
def gdb_delete_breakpoint(session_id: str, breakpoint_number: int) -> str:
    """Delete a breakpoint by its number."""
    session = manager.get(session_id)
    responses = session.controller.write(
        f"-break-delete {breakpoint_number}", timeout_sec=5
    )
    return _fmt_response(responses)


@mcp.tool()
def gdb_enable_breakpoint(
    session_id: str, breakpoint_number: int, enable: bool = True
) -> str:
    """Enable or disable a breakpoint."""
    session = manager.get(session_id)
    cmd = "-break-enable" if enable else "-break-disable"
    responses = session.controller.write(
        f"{cmd} {breakpoint_number}", timeout_sec=5
    )
    return _fmt_response(responses)


@mcp.tool()
def gdb_list_breakpoints(session_id: str) -> str:
    """List all breakpoints in the session."""
    session = manager.get(session_id)
    responses = session.controller.write("-break-list", timeout_sec=5)
    return _fmt_response(responses)


@mcp.tool()
def gdb_watchpoint(
    session_id: str,
    expression: str,
    access: bool = False,
    read: bool = False,
) -> str:
    """Set a watchpoint on an expression.

    Args:
        expression: variable or memory expression to watch
        access: watch for both reads and writes
        read: watch for reads only (default is write-only)
    """
    session = manager.get(session_id)
    if access:
        cmd = f"-break-watch -a {expression}"
    elif read:
        cmd = f"-break-watch -r {expression}"
    else:
        cmd = f"-break-watch {expression}"
    responses = session.controller.write(cmd, timeout_sec=5)
    return _fmt_response(responses)


@mcp.tool()
def gdb_catchpoint(session_id: str, event: str) -> str:
    """Set a catchpoint to stop on specific events.

    Args:
        event: the event to catch. Examples:
            "syscall open" — catch the open() syscall
            "syscall read write" — catch read and write syscalls
            "signal SIGSEGV" — catch segfaults
            "throw" — catch C++ exceptions being thrown
            "catch" — catch C++ exceptions being caught
            "fork" — catch fork() calls
            "exec" — catch exec() calls
            "load libfoo" — catch loading of shared library
    """
    session = manager.get(session_id)
    responses = session.controller.write(f"catch {event}", timeout_sec=10)
    return _fmt_response(responses)


# ===========================================================================
# Inspection — stack, variables, expressions
# ===========================================================================

@mcp.tool()
def gdb_backtrace(session_id: str, full: bool = False) -> str:
    """Get the current backtrace/call stack."""
    session = manager.get(session_id)
    responses = session.controller.write("-stack-list-frames", timeout_sec=10)
    out = _fmt_response(responses)
    if full:
        locals_resp = session.controller.write(
            "-stack-list-locals 1", timeout_sec=10
        )
        out += "\n\nLocals:\n" + _fmt_response(locals_resp)
    return out


@mcp.tool()
def gdb_print(session_id: str, expression: str) -> str:
    """Evaluate an expression and return its value (like GDB 'print')."""
    session = manager.get(session_id)
    responses = session.controller.write(
        f'-data-evaluate-expression "{expression}"', timeout_sec=10
    )
    return _fmt_response(responses)


@mcp.tool()
def gdb_locals(session_id: str) -> str:
    """List local variables and their values in the current frame."""
    session = manager.get(session_id)
    responses = session.controller.write("-stack-list-locals 1", timeout_sec=10)
    return _fmt_response(responses)


@mcp.tool()
def gdb_args(session_id: str) -> str:
    """List function arguments and their values in the current frame."""
    session = manager.get(session_id)
    responses = session.controller.write("-stack-list-arguments 1", timeout_sec=10)
    return _fmt_response(responses)


@mcp.tool()
def gdb_registers(session_id: str, names: str = "") -> str:
    """Read register values.

    Args:
        names: space-separated register names to read (e.g. "rax rbx rip").
               If empty, reads all registers.
    """
    session = manager.get(session_id)
    if names:
        # Use the CLI info registers for named access
        responses = session.controller.write(
            f"info registers {names}", timeout_sec=10
        )
    else:
        responses = session.controller.write(
            "-data-list-register-values x", timeout_sec=10
        )
    return _fmt_response(responses)


# ===========================================================================
# Memory
# ===========================================================================

@mcp.tool()
def gdb_memory(
    session_id: str, address: str, count: int = 64, word_size: int = 1
) -> str:
    """Read memory at an address.

    Args:
        address: memory address (e.g. "0x7fffffffe000" or "&variable")
        count: number of units to read
        word_size: bytes per unit (1, 2, 4, 8)
    """
    session = manager.get(session_id)
    responses = session.controller.write(
        f"-data-read-memory-bytes {address} {count * word_size}",
        timeout_sec=10,
    )
    return _fmt_response(responses)


@mcp.tool()
def gdb_memory_write(
    session_id: str, address: str, bytes_hex: str
) -> str:
    """Write raw bytes to memory.

    Args:
        address: target address (e.g. "0x7fff0000")
        bytes_hex: hex string of bytes to write (e.g. "deadbeef", "90909090")
    """
    session = manager.get(session_id)
    # Validate hex string
    clean = bytes_hex.replace(" ", "")
    if len(clean) % 2 != 0:
        return "ERROR: bytes_hex must have even number of hex digits"
    responses = session.controller.write(
        f"-data-write-memory-bytes {address} {clean}", timeout_sec=10
    )
    return _fmt_response(responses)


@mcp.tool()
def gdb_memory_find(
    session_id: str,
    start: str,
    end: str,
    pattern: str,
) -> str:
    """Search memory for a byte pattern.

    Args:
        start: start address (e.g. "0x400000", "$sp")
        end: end address (e.g. "0x401000", "$sp+0x1000")
        pattern: what to search for. Supports:
            - string: "/s" prefix, e.g. 'find start, end, "HELLO"'
            - bytes: hex bytes, e.g. "0x41, 0x42, 0x43"
            - integers: e.g. "0xdeadbeef"
    """
    session = manager.get(session_id)
    responses = session.controller.write(
        f"find {start}, {end}, {pattern}", timeout_sec=30
    )
    return _fmt_response(responses)


# ===========================================================================
# Disassembly & source
# ===========================================================================

@mcp.tool()
def gdb_disassemble(
    session_id: str,
    start: str = "",
    end: str = "",
    function: str = "",
    num_bytes: int = 0,
) -> str:
    """Disassemble code.

    Args:
        start: start address (e.g. "0x400080", "$pc")
        end: end address — mutually exclusive with num_bytes
        function: function name to disassemble (e.g. "main")
        num_bytes: number of bytes to disassemble from start (e.g. 200)

    If nothing is specified, disassembles around the current PC.
    """
    session = manager.get(session_id)
    if function:
        responses = session.controller.write(
            f"disassemble {function}", timeout_sec=10
        )
    elif start and num_bytes:
        responses = session.controller.write(
            f"-data-disassemble -s {start} -e {start}+{num_bytes} -- 0",
            timeout_sec=10,
        )
    elif start and end:
        responses = session.controller.write(
            f"-data-disassemble -s {start} -e {end} -- 0", timeout_sec=10
        )
    elif start:
        responses = session.controller.write(
            f"-data-disassemble -s {start} -e {start}+100 -- 0",
            timeout_sec=10,
        )
    else:
        responses = session.controller.write(
            "-data-disassemble -s $pc -e $pc+100 -- 0", timeout_sec=10
        )
    return _fmt_response(responses)


@mcp.tool()
def gdb_source_list(
    session_id: str, location: str = "", count: int = 40
) -> str:
    """List source code around a location.

    Args:
        location: file:line, function name, or address. Defaults to current position.
        count: number of lines to show
    """
    session = manager.get(session_id)
    session.controller.write(f"set listsize {count}", timeout_sec=5)
    cmd = f"list {location}" if location else "list"
    responses = session.controller.write(cmd, timeout_sec=10)
    return _fmt_response(responses)


# ===========================================================================
# Threads & frames
# ===========================================================================

@mcp.tool()
def gdb_info_threads(session_id: str) -> str:
    """List all threads."""
    session = manager.get(session_id)
    responses = session.controller.write("-thread-info", timeout_sec=10)
    return _fmt_response(responses)


@mcp.tool()
def gdb_select_thread(session_id: str, thread_id: int) -> str:
    """Switch to a specific thread."""
    session = manager.get(session_id)
    responses = session.controller.write(
        f"-thread-select {thread_id}", timeout_sec=5
    )
    return _fmt_response(responses)


@mcp.tool()
def gdb_select_frame(session_id: str, frame_number: int) -> str:
    """Switch to a specific stack frame."""
    session = manager.get(session_id)
    responses = session.controller.write(
        f"-stack-select-frame {frame_number}", timeout_sec=5
    )
    return _fmt_response(responses)


# ===========================================================================
# Symbol / function / variable lookup
# ===========================================================================

@mcp.tool()
def gdb_info_functions(session_id: str, regexp: str = "") -> str:
    """List function symbols, optionally filtered by regex.

    Args:
        regexp: optional regex to filter (e.g. "main", "handle_.*")
    """
    session = manager.get(session_id)
    cmd = f"info functions {regexp}" if regexp else "info functions"
    responses = session.controller.write(cmd, timeout_sec=30)
    return _fmt_response(responses)


@mcp.tool()
def gdb_info_variables(session_id: str, regexp: str = "") -> str:
    """List global/static variable symbols, optionally filtered by regex."""
    session = manager.get(session_id)
    cmd = f"info variables {regexp}" if regexp else "info variables"
    responses = session.controller.write(cmd, timeout_sec=30)
    return _fmt_response(responses)


@mcp.tool()
def gdb_info_sharedlibs(session_id: str) -> str:
    """List loaded shared libraries and their address ranges."""
    session = manager.get(session_id)
    responses = session.controller.write("info sharedlibrary", timeout_sec=10)
    return _fmt_response(responses)


@mcp.tool()
def gdb_info_files(session_id: str) -> str:
    """Show loaded files, sections, and their memory address ranges."""
    session = manager.get(session_id)
    responses = session.controller.write("info files", timeout_sec=10)
    return _fmt_response(responses)


@mcp.tool()
def gdb_info_proc_mappings(session_id: str) -> str:
    """Show the process memory map (like /proc/pid/maps)."""
    session = manager.get(session_id)
    responses = session.controller.write("info proc mappings", timeout_sec=10)
    return _fmt_response(responses)


# ===========================================================================
# Type / struct inspection
# ===========================================================================

@mcp.tool()
def gdb_ptype(session_id: str, name: str) -> str:
    """Show the definition of a type or variable's type.

    Works for structs, unions, enums, typedefs, and variables.

    Examples:
        gdb_ptype("gdb-1", "struct sockaddr_in")
        gdb_ptype("gdb-1", "my_variable")
        gdb_ptype("gdb-1", "enum state")
    """
    session = manager.get(session_id)
    responses = session.controller.write(f"ptype {name}", timeout_sec=10)
    return _fmt_response(responses)


@mcp.tool()
def gdb_print_struct(
    session_id: str, expression: str, pretty: bool = True
) -> str:
    """Print a struct/union value with all its fields.

    Args:
        expression: variable, pointer deref, or cast expression
            e.g. "my_struct", "*ptr", "*(struct foo *)0x7fff0000"
        pretty: pretty-print with indentation (default True)
    """
    session = manager.get(session_id)
    if pretty:
        session.controller.write("set print pretty on", timeout_sec=5)
    responses = session.controller.write(f"print {expression}", timeout_sec=10)
    if pretty:
        session.controller.write("set print pretty off", timeout_sec=5)
    return _fmt_response(responses)


@mcp.tool()
def gdb_sizeof(session_id: str, type_or_expr: str) -> str:
    """Get the size of a type or expression in bytes.

    Examples:
        gdb_sizeof("gdb-1", "struct sockaddr_in")
        gdb_sizeof("gdb-1", "int")
        gdb_sizeof("gdb-1", "my_variable")
    """
    session = manager.get(session_id)
    responses = session.controller.write(
        f'-data-evaluate-expression "sizeof({type_or_expr})"', timeout_sec=10
    )
    return _fmt_response(responses)


@mcp.tool()
def gdb_offsetof(session_id: str, struct_type: str, field: str) -> str:
    """Get the byte offset of a field within a struct.

    Args:
        struct_type: e.g. "struct sockaddr_in" or a typedef name
        field: field name within the struct
    """
    session = manager.get(session_id)
    responses = session.controller.write(
        f'-data-evaluate-expression "(int)&(({struct_type} *)0)->{field}"',
        timeout_sec=10,
    )
    return _fmt_response(responses)


@mcp.tool()
def gdb_cast_print(session_id: str, address: str, cast_type: str) -> str:
    """Cast an address to a type and print the dereferenced value.

    Examples:
        gdb_cast_print("gdb-1", "0x7fff0000", "struct foo *")
        gdb_cast_print("gdb-1", "$rdi", "char *")
    """
    session = manager.get(session_id)
    session.controller.write("set print pretty on", timeout_sec=5)
    responses = session.controller.write(
        f"print *({cast_type})({address})", timeout_sec=10
    )
    session.controller.write("set print pretty off", timeout_sec=5)
    return _fmt_response(responses)


@mcp.tool()
def gdb_info_types(session_id: str, regexp: str = "") -> str:
    """List type names matching a regexp, or all types if no regexp given.

    Args:
        regexp: optional regex filter (e.g. "sock" to find socket-related types)
    """
    session = manager.get(session_id)
    cmd = f"info types {regexp}" if regexp else "info types"
    responses = session.controller.write(cmd, timeout_sec=30)
    return _fmt_response(responses)


@mcp.tool()
def gdb_whatis(session_id: str, expression: str) -> str:
    """Show the type of an expression without expanding typedefs.

    Useful to quickly check what type a variable or expression is.
    """
    session = manager.get(session_id)
    responses = session.controller.write(
        f"whatis {expression}", timeout_sec=10
    )
    return _fmt_response(responses)


# ===========================================================================
# Memory / variable writing
# ===========================================================================

@mcp.tool()
def gdb_set_variable(session_id: str, variable: str, value: str) -> str:
    """Set a variable or memory location to a value.

    Examples:
        gdb_set_variable("gdb-1", "x", "42")
        gdb_set_variable("gdb-1", "*0x7fff0000", "0xdeadbeef")
    """
    session = manager.get(session_id)
    responses = session.controller.write(
        f"-gdb-set var {variable}={value}", timeout_sec=5
    )
    return _fmt_response(responses)


# ===========================================================================
# GDB settings
# ===========================================================================

@mcp.tool()
def gdb_set(session_id: str, setting: str, value: str) -> str:
    """Set a GDB configuration option.

    Common settings:
        "follow-fork-mode", "child" — follow child after fork
        "detach-on-fork", "off" — debug both parent and child
        "disable-randomization", "off" — enable ASLR
        "disassembly-flavor", "intel" — use Intel syntax
        "pagination", "off" — disable the GDB pager
        "print elements", "0" — don't truncate array printing
        "architecture", "i386:x86-64" — force architecture
    """
    session = manager.get(session_id)
    responses = session.controller.write(
        f"-gdb-set {setting} {value}", timeout_sec=5
    )
    return _fmt_response(responses)


@mcp.tool()
def gdb_show(session_id: str, setting: str) -> str:
    """Show current value of a GDB setting."""
    session = manager.get(session_id)
    responses = session.controller.write(f"show {setting}", timeout_sec=5)
    return _fmt_response(responses)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
