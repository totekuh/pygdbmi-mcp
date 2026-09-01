"""MCP tools for a persistent, token-correlated GDB/MI runtime."""

from __future__ import annotations

import functools
import inspect
import re
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar, get_type_hints

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .contracts import (
    CATALOG_REVISION,
    GdbMcpError,
    ToolEnvelope,
    error_envelope,
    ok_envelope,
)
from .runtime import (
    DEFAULT_OUTPUT_PAGE,
    MAX_OUTPUT_PAGE,
    GdbManager,
    GdbSession,
    cli_quote,
    mi_quote,
)

CleanupPolicy = Literal["auto", "kill", "detach", "disconnect", "quit"]
CommandMode = Literal["auto", "mi", "console"]
RegisterSet = Literal["general", "all"]
WordSize = Literal[1, 2, 4, 8]
ExecutionAction = Literal["run", "continue", "step", "next", "finish", "until"]
FollowFork = Literal["parent", "child"]
NonNegative = Annotated[int, Field(ge=0)]
Positive = Annotated[int, Field(ge=1)]
EventLimit = Annotated[int, Field(ge=1, le=500)]
WaitTimeout = Annotated[float, Field(ge=0, le=300)]
CommandTimeout = Annotated[float, Field(ge=0.05, le=300)]
OutputLimit = Annotated[int, Field(ge=256, le=MAX_OUTPUT_PAGE)]
InferiorOutputLimit = Annotated[int, Field(ge=1, le=MAX_OUTPUT_PAGE)]
ExecutionTimeout = Annotated[float, Field(ge=0, le=86400)]
MemoryCount = Annotated[int, Field(ge=1, le=65536)]
SmallCount = Annotated[int, Field(ge=1, le=1000)]

ANY_STATE = frozenset({"idle", "running", "stopped", "exited", "indeterminate"})
NOT_RUNNING = frozenset({"idle", "stopped", "exited"})
STOPPED = frozenset({"stopped"})
RUNNABLE = frozenset({"idle", "stopped", "exited"})

manager = GdbManager()


@asynccontextmanager
async def lifespan(server: FastMCP):
    yield
    manager.destroy_all()


mcp = FastMCP(
    "pygdbmi-mcp",
    instructions=(
        "Start with gdb_start and retain session_id. Load, attach, or connect, then use "
        "execution tools. Prefer gdb_execution_start plus gdb_execution_status for "
        "retained start/poll/cancel workflows; direct execution returns on ^running and "
        "uses gdb_wait_for_stop with the previous stop_id. Cache gdb_capabilities, prefer "
        "gdb_context over many inspection calls, and inspect gdb_inferiors after fork/exec. "
        "Every tool returns pygdbmi.mcp/1; check ok before result. Page large output "
        "through gdb_output_page and stop sessions explicitly."
    ),
    lifespan=lifespan,
)

F = TypeVar("F", bound=Callable[..., Any])


def _safe_status(session: GdbSession | None) -> dict[str, Any] | None:
    return session.status() if session is not None else None


def gdb_tool(
    *,
    states: frozenset[str] | None = ANY_STATE,
    read_only: bool = False,
    destructive: bool = False,
    idempotent: bool = False,
    open_world: bool = False,
) -> Callable[[F], F]:
    """Register a tool with a common envelope, state gate, and annotations."""

    def decorate(function: F) -> F:
        raw_signature = inspect.signature(function)
        hints = get_type_hints(function, include_extras=True)
        signature = raw_signature.replace(
            parameters=[
                parameter.replace(annotation=hints.get(name, parameter.annotation))
                for name, parameter in raw_signature.parameters.items()
            ]
        )

        @functools.wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> ToolEnvelope:
            session: GdbSession | None = None
            try:
                bound = signature.bind(*args, **kwargs)
                bound.apply_defaults()
                session_id = bound.arguments.get("session_id")
                if isinstance(session_id, str):
                    session = manager.get(session_id)
                    if states is not None and session.run_state not in states:
                        raise GdbMcpError(
                            f"{function.__name__} is not valid while the session is {session.run_state}",
                            code="invalid_state",
                            details={
                                "run_state": session.run_state,
                                "allowed_states": sorted(states),
                            },
                            recovery=["Wait for a stop or interrupt the inferior."],
                        )
                # State-gated GDB operations pin the check to the same command
                # lock used by execute(). Two concurrent MCP calls therefore
                # cannot both observe "stopped" and then resume/inspect in the
                # opposite order.
                if session is not None and states not in {None, ANY_STATE}:
                    with session.command_lock:
                        if session.run_state not in states:
                            raise GdbMcpError(
                                f"{function.__name__} is not valid while the session is {session.run_state}",
                                code="invalid_state",
                                details={
                                    "run_state": session.run_state,
                                    "allowed_states": sorted(states),
                                },
                                recovery=["Wait for a stop or interrupt the inferior."],
                            )
                        result = function(*args, **kwargs)
                else:
                    result = function(*args, **kwargs)
                if session is None and function.__name__ == "gdb_start":
                    sid = result.get("session_id") if isinstance(result, dict) else None
                    session = manager.get(sid) if isinstance(sid, str) else None
                return ok_envelope(result, _safe_status(session))
            except Exception as exc:  # noqa: BLE001 - normalize every tool failure
                return error_envelope(
                    exc, operation=function.__name__, session=_safe_status(session)
                )

        # Keep the wire result structured without repeating the full envelope
        # schema for every tool in each tools/list response. The versioned fields are
        # enforced by this wrapper and tested once as a shared contract.
        wrapped.__signature__ = signature.replace(return_annotation=dict[str, Any])  # type: ignore[attr-defined]
        registered = mcp.tool(
            annotations=ToolAnnotations(
                readOnlyHint=read_only,
                destructiveHint=destructive,
                idempotentHint=idempotent,
                openWorldHint=open_world,
            )
        )(wrapped)
        return registered  # type: ignore[return-value]

    return decorate


def _reply(session: GdbSession, command: str, timeout: float = 10) -> dict[str, Any]:
    return session.execute(command, timeout_sec=timeout)


def _payload(reply: dict[str, Any]) -> Any:
    return reply.get("payload")


def _catalog() -> dict[str, Any]:
    return {
        "revision": CATALOG_REVISION,
        "tool_count": len(mcp._tool_manager._tools),
        "result_schema": "pygdbmi.mcp/1",
    }


def _require_single_line(value: str, name: str) -> str:
    if not value.strip():
        raise GdbMcpError(f"{name} must not be empty", code="invalid_argument")
    if "\n" in value or "\r" in value:
        raise GdbMcpError(f"{name} must be one line", code="invalid_argument")
    return value


def _temporary_boolean_setting(
    session: GdbSession, setting: str, enabled: bool
) -> Callable[[], None]:
    shown = _reply(session, f"show {setting}", 5)
    previous = bool(re.search(r"\bis on\.?\s*$", shown["output"], re.IGNORECASE))
    if previous != enabled:
        _reply(session, f"set {setting} {'on' if enabled else 'off'}", 5)

    def restore() -> None:
        if previous != enabled:
            _reply(session, f"set {setting} {'on' if previous else 'off'}", 5)

    return restore


# Session and control plane --------------------------------------------------


@gdb_tool(states=None, destructive=True, open_world=True)
def gdb_start(
    gdb_path: str = "gdb",
    gdb_args: list[str] | None = None,
    inferior_args: list[str] | None = None,
    inferior_tty: bool = True,
    working_directory: str = "",
) -> dict[str, Any]:
    """Start an isolated GDB/MI session and persistent reader."""
    sid = manager.create(
        gdb_path=gdb_path,
        gdb_args=gdb_args,
        inferior_args=inferior_args,
        inferior_tty=inferior_tty,
        working_directory=working_directory,
    )
    return {"session_id": sid, "catalog": _catalog()}


@gdb_tool(destructive=True)
def gdb_stop(session_id: str, policy: CleanupPolicy = "auto") -> dict[str, Any]:
    """Clean up the target according to its kind, then destroy the session."""
    return manager.destroy(session_id, policy=policy)


@gdb_tool(states=None, read_only=True, idempotent=True)
def gdb_list_sessions() -> dict[str, Any]:
    """List active sessions and catalog identity."""
    sessions = manager.list()
    return {"sessions": sessions, "count": len(sessions), "catalog": _catalog()}


@gdb_tool(read_only=True, idempotent=True)
def gdb_session_status(session_id: str) -> dict[str, Any]:
    """Return target state, stop epoch, identity, and catalog revision."""
    return {**manager.get(session_id).status(), "catalog": _catalog()}


@gdb_tool(read_only=True, idempotent=True)
def gdb_events(
    session_id: str,
    after_cursor: NonNegative = 0,
    limit: EventLimit = 100,
    wait_timeout: WaitTimeout = 0,
) -> dict[str, Any]:
    """Read bounded asynchronous MI events using a monotonic cursor."""
    if isinstance(after_cursor, bool) or isinstance(limit, bool):
        raise GdbMcpError("cursor and limit must be integers", code="invalid_argument")
    return manager.get(session_id).events(
        after_cursor=int(after_cursor),
        limit=int(limit),
        wait_timeout=float(wait_timeout),
    )


@gdb_tool(read_only=True, idempotent=True)
def gdb_wait_for_stop(
    session_id: str,
    after_stop_id: NonNegative = 0,
    timeout_sec: WaitTimeout = 30,
) -> dict[str, Any]:
    """Wait for a newer stop epoch or exit without resuming the target."""
    if isinstance(after_stop_id, bool):
        raise GdbMcpError("after_stop_id must be an integer", code="invalid_argument")
    return manager.get(session_id).wait_for_stop(
        after_stop_id=int(after_stop_id), timeout_sec=float(timeout_sec)
    )


@gdb_tool(read_only=True, idempotent=True)
def gdb_output_page(
    session_id: str,
    command_id: Positive,
    offset: NonNegative = 0,
    limit: OutputLimit = DEFAULT_OUTPUT_PAGE,
) -> dict[str, Any]:
    """Read another bounded page of retained console output."""
    return manager.get(session_id).output_page(int(command_id), int(offset), int(limit))


@gdb_tool(read_only=True, idempotent=True)
def gdb_inferior_io(
    session_id: str,
    after_cursor: NonNegative = 0,
    limit: InferiorOutputLimit = DEFAULT_OUTPUT_PAGE,
    wait_timeout: WaitTimeout = 0,
    encoding: Literal["utf-8", "hex", "base64"] = "utf-8",
) -> dict[str, Any]:
    """Read bounded stdout/stderr from the session-owned inferior PTY."""
    return manager.get(session_id).inferior_io(
        after_cursor=int(after_cursor),
        limit=int(limit),
        wait_timeout=float(wait_timeout),
        encoding=encoding,
    )


@gdb_tool(destructive=True)
def gdb_inferior_stdin(
    session_id: str,
    data: str,
    encoding: Literal["utf-8", "hex", "base64"] = "utf-8",
) -> dict[str, Any]:
    """Write at most 64 KiB to the session-owned inferior PTY."""
    return manager.get(session_id).write_inferior(data, encoding=encoding)


@gdb_tool(destructive=True)
def gdb_execution_start(
    session_id: str,
    action: ExecutionAction,
    instruction: bool = False,
    location: str = "",
    timeout_sec: ExecutionTimeout = 0,
) -> dict[str, Any]:
    """Start a retained execution operation that completes at a later stop or exit."""
    return manager.get(session_id).start_execution(
        action,
        instruction=instruction,
        location=location,
        timeout_sec=float(timeout_sec),
    )


@gdb_tool(read_only=True, idempotent=True)
def gdb_execution_status(
    session_id: str,
    job_id: str,
    after_revision: NonNegative = 0,
    wait_timeout: WaitTimeout = 0,
) -> dict[str, Any]:
    """Read or long-poll a retained execution operation by revision."""
    return manager.get(session_id).execution_status(
        job_id,
        after_revision=int(after_revision),
        wait_timeout=float(wait_timeout),
    )


@gdb_tool(read_only=True, idempotent=True)
def gdb_execution_list(session_id: str) -> dict[str, Any]:
    """List bounded retained execution operations for a session."""
    return manager.get(session_id).list_executions()


@gdb_tool(destructive=True, idempotent=True)
def gdb_execution_cancel(
    session_id: str,
    job_id: str,
    timeout_sec: CommandTimeout = 5,
) -> dict[str, Any]:
    """Cancel an active execution operation by interrupting the target."""
    return manager.get(session_id).cancel_execution(
        job_id, timeout_sec=float(timeout_sec)
    )


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_inferiors(session_id: str, refresh: bool = True) -> dict[str, Any]:
    """Return normalized GDB inferior/thread-group topology."""
    return manager.get(session_id).inferiors(refresh=refresh)


@gdb_tool(states=NOT_RUNNING, destructive=True, idempotent=True)
def gdb_select_inferior(session_id: str, inferior_id: Positive) -> dict[str, Any]:
    """Select a GDB inferior by its numeric ID."""
    return manager.get(session_id).select_inferior(int(inferior_id))


@gdb_tool(states=NOT_RUNNING, destructive=True, idempotent=True)
def gdb_fork_policy(
    session_id: str,
    follow: FollowFork = "parent",
    detach_on_fork: bool = True,
    schedule_multiple: bool = False,
) -> dict[str, Any]:
    """Set explicit follow-fork, detach-on-fork, and scheduling policy."""
    return manager.get(session_id).set_fork_policy(
        follow=follow,
        detach_on_fork=detach_on_fork,
        schedule_multiple=schedule_multiple,
    )


@gdb_tool(read_only=True, idempotent=True)
def gdb_capabilities(session_id: str, refresh: bool = False) -> dict[str, Any]:
    """Discover or return cached MI, target, architecture, and execution capabilities."""
    return manager.get(session_id).capabilities(refresh=refresh)


_GENERAL_REGISTERS = (
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "rip",
    "eflags",
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "ebp",
    "esp",
    "eip",
    "cpsr",
    "x0",
    "x1",
    "x2",
    "x3",
    "x4",
    "x5",
    "x6",
    "x7",
    "x8",
    "x9",
    "x10",
    "x11",
    "x12",
    "x13",
    "x14",
    "x15",
    "x16",
    "x17",
    "x18",
    "x19",
    "x20",
    "x21",
    "x22",
    "x23",
    "x24",
    "x25",
    "x26",
    "x27",
    "x28",
    "x29",
    "x30",
    "sp",
    "pc",
    "lr",
    "fp",
    "ra",
    "gp",
    "tp",
)


def _register_name_table(session: GdbSession) -> list[str]:
    if session.register_names is None:
        payload = _payload(_reply(session, "-data-list-register-names", 10)) or {}
        names = payload.get("register-names", []) if isinstance(payload, dict) else []
        session.register_names = [str(name) for name in names]
    return session.register_names


def _read_register_map(
    session: GdbSession,
    register_set: RegisterSet,
    requested: list[str] | None,
) -> dict[str, str]:
    names = _register_name_table(session)
    wanted = set(requested or ())
    if requested:
        unknown = sorted(wanted.difference(names))
        if unknown:
            raise GdbMcpError(
                "unknown register name(s)",
                code="invalid_argument",
                details={"unknown": unknown[:32]},
            )
        indexes = [index for index, name in enumerate(names) if name in wanted]
    elif register_set == "general":
        indexes = [
            index for index, name in enumerate(names) if name in set(_GENERAL_REGISTERS)
        ]
    else:
        indexes = [index for index, name in enumerate(names) if name]
    command = "-data-list-register-values x"
    if indexes:
        command += " " + " ".join(str(index) for index in indexes)
    payload = _payload(_reply(session, command, 15)) or {}
    values = payload.get("register-values", []) if isinstance(payload, dict) else []
    result: dict[str, str] = {}
    for item in values:
        if not isinstance(item, dict):
            continue
        try:
            index = int(item["number"])
            name = names[index]
        except (KeyError, TypeError, ValueError, IndexError):
            continue
        result[name] = str(item.get("value", ""))
    return result


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_context(
    session_id: str,
    backtrace_depth: Annotated[int, Field(ge=1, le=64)] = 12,
    instruction_count: Annotated[int, Field(ge=1, le=64)] = 16,
    register_set: RegisterSet = "general",
    registers: list[str] | None = None,
    include_locals: bool = True,
    include_threads: bool = False,
    include_breakpoints: bool = False,
    stack_bytes: Annotated[int, Field(ge=0, le=4096)] = 0,
) -> dict[str, Any]:
    """Collect compact stop-pinned evidence in one atomic bundle."""
    session = manager.get(session_id)
    errors: dict[str, dict[str, Any]] = {}
    with session.command_lock:
        pinned_stop = session.stop_id

        def section(name: str, command: str, timeout: float = 10) -> Any:
            try:
                value = _payload(_reply(session, command, timeout))
                if session.stop_id != pinned_stop or session.run_state != "stopped":
                    raise GdbMcpError(
                        "stop epoch changed while collecting context",
                        code="stale_stop",
                        retryable=True,
                    )
                return value
            except GdbMcpError as exc:
                errors[name] = {"code": exc.code, "message": exc.message}
                return None

        frame_payload = section("frame", "-stack-info-frame") or {}
        frame = frame_payload.get("frame") if isinstance(frame_payload, dict) else None
        try:
            register_values = _read_register_map(session, register_set, registers)
        except GdbMcpError as exc:
            errors["registers"] = {"code": exc.code, "message": exc.message}
            register_values = {}
        trace_payload = (
            section("backtrace", f"-stack-list-frames 0 {int(backtrace_depth) - 1}")
            or {}
        )
        backtrace = (
            trace_payload.get("stack", []) if isinstance(trace_payload, dict) else []
        )
        locals_value = (
            section("locals", "-stack-list-variables --simple-values")
            if include_locals
            else None
        )
        disasm_payload = (
            section(
                "disassembly",
                f"-data-disassemble -s $pc -e $pc+{int(instruction_count) * 15} -- 0",
            )
            or {}
        )
        disassembly = (
            disasm_payload.get("asm_insns", [])[: int(instruction_count)]
            if isinstance(disasm_payload, dict)
            else []
        )
        threads = section("threads", "-thread-info") if include_threads else None
        breakpoints = (
            section("breakpoints", "-break-list") if include_breakpoints else None
        )
        stack = (
            section("stack", f"-data-read-memory-bytes $sp {int(stack_bytes)}")
            if stack_bytes
            else None
        )
        return {
            "stop_id": pinned_stop,
            "frame": frame,
            "registers": register_values,
            "backtrace": backtrace,
            "locals": locals_value,
            "disassembly": disassembly,
            "threads": threads,
            "breakpoints": breakpoints,
            "stack": stack,
            "partial": bool(errors),
            "errors": errors,
        }


@gdb_tool(destructive=True, open_world=True)
def gdb_command(
    session_id: str,
    command: str,
    timeout_sec: CommandTimeout = 30,
    mode: CommandMode = "auto",
    output_page_chars: OutputLimit = DEFAULT_OUTPUT_PAGE,
) -> dict[str, Any]:
    """Execute one raw MI or CLI command; newlines and caller tokens are rejected."""
    return manager.get(session_id).execute(
        command,
        timeout_sec=float(timeout_sec),
        mode=mode,
        output_page_chars=int(output_page_chars),
    )


@gdb_tool(states=NOT_RUNNING, destructive=True, open_world=True)
def gdb_batch(
    session_id: str,
    commands: list[str],
    stop_id: int | None = None,
    continue_on_error: bool = False,
    timeout_sec: CommandTimeout = 30,
) -> dict[str, Any]:
    """Execute 1-32 commands atomically, optionally pinned to a stop epoch."""
    if not isinstance(commands, list) or not all(
        isinstance(command, str) for command in commands
    ):
        raise GdbMcpError("commands must be a list of strings", code="invalid_argument")
    if not 1 <= len(commands) <= 32:
        raise GdbMcpError(
            "commands must contain 1 to 32 items", code="invalid_argument"
        )
    session = manager.get(session_id)
    with session.command_lock:
        if stop_id is not None and session.stop_id != stop_id:
            raise GdbMcpError(
                "requested stop epoch is stale",
                code="stale_stop",
                details={"requested": stop_id, "current": session.stop_id},
            )
        items: list[dict[str, Any]] = []
        for index, command in enumerate(commands):
            try:
                reply = session.execute(command, timeout_sec=float(timeout_sec))
                items.append({"index": index, "ok": True, "reply": reply})
            except GdbMcpError as exc:
                items.append(
                    {
                        "index": index,
                        "ok": False,
                        "error": {"code": exc.code, "message": exc.message},
                    }
                )
                if not continue_on_error:
                    break
        return {"items": items, "completed": len(items), "requested": len(commands)}


# Targets and execution -----------------------------------------------------


@gdb_tool(states=NOT_RUNNING, destructive=True, open_world=True)
def gdb_load_binary(
    session_id: str, binary_path: str, args: list[str] | None = None
) -> dict[str, Any]:
    """Load an executable and set an exact argument vector."""
    session = manager.get(session_id)
    path = str(Path(binary_path).expanduser().resolve())
    reply = _reply(session, f"-file-exec-and-symbols {mi_quote(path)}", 15)
    if args is not None:
        session.set_inferior_args(args)
    session.binary = path
    session.target_kind = "local"
    session.pid = None
    session.thread_group = None
    session.exit_code = None
    session.selected_thread = None
    session.selected_frame = 0
    session.set_state("idle", clear_stop=True)
    session.refresh_target_traits()
    return {"load": reply, "inferior_args": session.inferior_args}


@gdb_tool(states=NOT_RUNNING, destructive=True, open_world=True)
def gdb_attach(session_id: str, pid: Positive) -> dict[str, Any]:
    """Attach to a local process."""
    if isinstance(pid, bool):
        raise GdbMcpError("pid must be an integer", code="invalid_argument")
    session = manager.get(session_id)
    reply = _reply(session, f"-target-attach {int(pid)}", 30)
    session.pid = int(pid)
    session.target_kind = "attached"
    session.set_state("stopped")
    session.refresh_target_traits()
    return reply


@gdb_tool(states=NOT_RUNNING, destructive=True, open_world=True)
def gdb_remote_connect(
    session_id: str, target: str, extended_remote: bool = False
) -> dict[str, Any]:
    """Connect to a GDB remote target such as host:port or a serial device."""
    session = manager.get(session_id)
    kind = "extended-remote" if extended_remote else "remote"
    reply = _reply(
        session,
        f"-target-select {kind} {_require_single_line(target, 'target')}",
        30,
    )
    session.target_kind = "remote"
    session.set_state("stopped")
    session.refresh_target_traits()
    return reply


@gdb_tool(states=NOT_RUNNING, destructive=True, idempotent=True, open_world=True)
def gdb_remote_disconnect(session_id: str) -> dict[str, Any]:
    """Disconnect a remote target without killing it."""
    session = manager.get(session_id)
    reply = _reply(session, "-target-disconnect", 10)
    session.target_kind = "none"
    session.pid = None
    session.thread_group = None
    session.selected_thread = None
    session.selected_frame = 0
    session.set_state("idle", clear_stop=True)
    session.invalidate_capabilities()
    return reply


@gdb_tool(states=NOT_RUNNING, destructive=True, open_world=True)
def gdb_load_core(
    session_id: str, core_path: str, binary_path: str = ""
) -> dict[str, Any]:
    """Load a core file, optionally loading its executable first."""
    session = manager.get(session_id)
    load = None
    if binary_path:
        binary = str(Path(binary_path).expanduser().resolve())
        load = _reply(session, f"-file-exec-and-symbols {mi_quote(binary)}", 15)
        session.binary = binary
    core = str(Path(core_path).expanduser().resolve())
    # GDB 15's MI target-select parser leaks quotes into core filenames while
    # newer GDBs silently accept them. Route this one through the CLI parser,
    # which handles quoted paths consistently across both generations.
    reply = _reply(session, f"core-file {cli_quote(core)}", 30)
    session.target_kind = "core"
    session.set_state("stopped")
    session.refresh_target_traits()
    return {"binary": load, "core": reply}


@gdb_tool(states=NOT_RUNNING, destructive=True, open_world=True)
def gdb_add_symbol_file(
    session_id: str, symbol_path: str, address: str = ""
) -> dict[str, Any]:
    """Add a symbol file at its natural or specified load address."""
    path = str(Path(symbol_path).expanduser().resolve())
    command = f"add-symbol-file {cli_quote(path)}"
    if address:
        command += f" {_require_single_line(address, 'address')}"
    return _reply(manager.get(session_id), command, 30)


@gdb_tool(states=RUNNABLE, destructive=True)
def gdb_run(session_id: str) -> dict[str, Any]:
    """Start or restart the loaded program; return once GDB reports running."""
    return _reply(manager.get(session_id), "-exec-run", 30)


@gdb_tool(states=STOPPED, destructive=True)
def gdb_continue(session_id: str) -> dict[str, Any]:
    """Continue a stopped target."""
    return _reply(manager.get(session_id), "-exec-continue", 30)


@gdb_tool(states=STOPPED, destructive=True)
def gdb_step(session_id: str, instruction: bool = False) -> dict[str, Any]:
    """Step into by source line or instruction."""
    command = "-exec-step-instruction" if instruction else "-exec-step"
    return _reply(manager.get(session_id), command, 30)


@gdb_tool(states=STOPPED, destructive=True)
def gdb_next(session_id: str, instruction: bool = False) -> dict[str, Any]:
    """Step over by source line or instruction."""
    command = "-exec-next-instruction" if instruction else "-exec-next"
    return _reply(manager.get(session_id), command, 30)


@gdb_tool(states=STOPPED, destructive=True)
def gdb_finish(session_id: str) -> dict[str, Any]:
    """Run until the current function returns."""
    return _reply(manager.get(session_id), "-exec-finish", 30)


@gdb_tool(states=STOPPED, destructive=True)
def gdb_until(session_id: str, location: str) -> dict[str, Any]:
    """Run until a source location or address."""
    return _reply(manager.get(session_id), f"-exec-until {mi_quote(location)}", 30)


@gdb_tool(destructive=True, idempotent=True)
def gdb_interrupt(session_id: str, timeout_sec: WaitTimeout = 5) -> dict[str, Any]:
    """Interrupt a running target and wait for its next stop epoch."""
    return manager.get(session_id).interrupt(timeout_sec=float(timeout_sec))


@gdb_tool(states=STOPPED, destructive=True)
def gdb_signal(session_id: str, sig: str) -> dict[str, Any]:
    """Deliver a validated signal name or number to the inferior."""
    if not re.fullmatch(r"(?:SIG[A-Z0-9]+|[0-9]{1,3})", sig):
        raise GdbMcpError("invalid signal name or number", code="invalid_argument")
    return _reply(manager.get(session_id), f"signal {sig}", 10)


# Breakpoints ---------------------------------------------------------------


@gdb_tool(states=NOT_RUNNING, destructive=True)
def gdb_breakpoint(
    session_id: str,
    location: str,
    condition: str = "",
    temporary: bool = False,
    hardware: bool = False,
) -> dict[str, Any]:
    """Set a normal, conditional, temporary, or hardware breakpoint."""
    command = "-break-insert"
    if temporary:
        command += " -t"
    if hardware:
        command += " -h"
    if condition:
        command += f" -c {mi_quote(condition)}"
    command += f" {mi_quote(location)}"
    return _reply(manager.get(session_id), command, 10)


@gdb_tool(states=NOT_RUNNING, destructive=True, idempotent=True)
def gdb_delete_breakpoint(
    session_id: str, breakpoint_number: Positive
) -> dict[str, Any]:
    """Delete a breakpoint by number."""
    return _reply(manager.get(session_id), f"-break-delete {int(breakpoint_number)}", 5)


@gdb_tool(states=NOT_RUNNING, destructive=True, idempotent=True)
def gdb_enable_breakpoint(
    session_id: str, breakpoint_number: Positive, enable: bool = True
) -> dict[str, Any]:
    """Enable or disable a breakpoint."""
    command = "-break-enable" if enable else "-break-disable"
    return _reply(manager.get(session_id), f"{command} {int(breakpoint_number)}", 5)


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_list_breakpoints(session_id: str) -> dict[str, Any]:
    """List all breakpoints."""
    return _reply(manager.get(session_id), "-break-list", 5)


@gdb_tool(states=NOT_RUNNING, destructive=True)
def gdb_watchpoint(
    session_id: str, expression: str, access: bool = False, read: bool = False
) -> dict[str, Any]:
    """Set a write, read, or access watchpoint."""
    if access and read:
        raise GdbMcpError(
            "access and read are mutually exclusive", code="invalid_argument"
        )
    flag = " -a" if access else " -r" if read else ""
    return _reply(
        manager.get(session_id), f"-break-watch{flag} {mi_quote(expression)}", 10
    )


@gdb_tool(states=NOT_RUNNING, destructive=True)
def gdb_catchpoint(session_id: str, event: str) -> dict[str, Any]:
    """Set a catchpoint using a single-line GDB event specification."""
    return _reply(
        manager.get(session_id), f"catch {_require_single_line(event, 'event')}", 10
    )


# Inspection, memory, source, and threads ----------------------------------


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_backtrace(
    session_id: str,
    full: bool = False,
    max_frames: Annotated[int, Field(ge=1, le=256)] = 64,
) -> dict[str, Any]:
    """Return a bounded backtrace and optional current-frame variables."""
    session = manager.get(session_id)
    frames = _reply(session, f"-stack-list-frames 0 {int(max_frames) - 1}", 15)
    variables = (
        _reply(session, "-stack-list-variables --all-values", 15) if full else None
    )
    return {"frames": frames, "variables": variables}


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_print(session_id: str, expression: str) -> dict[str, Any]:
    """Evaluate an expression through GDB/MI."""
    return _reply(
        manager.get(session_id), f"-data-evaluate-expression {mi_quote(expression)}", 10
    )


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_locals(session_id: str) -> dict[str, Any]:
    """List current-frame local variables and values."""
    return _reply(manager.get(session_id), "-stack-list-locals --all-values", 10)


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_args(session_id: str) -> dict[str, Any]:
    """List current-frame function arguments and values."""
    return _reply(manager.get(session_id), "-stack-list-arguments --all-values", 10)


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_registers(
    session_id: str,
    names: list[str] | str | None = None,
    register_set: RegisterSet = "general",
) -> dict[str, Any]:
    """Read named, general, or all registers as a name/value map."""
    requested = names.split() if isinstance(names, str) else names
    return {
        "registers": _read_register_map(
            manager.get(session_id), register_set, requested
        )
    }


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_memory(
    session_id: str,
    address: str,
    count: MemoryCount = 64,
    word_size: WordSize = 1,
) -> dict[str, Any]:
    """Read at most 64 KiB of target memory."""
    total = int(count) * int(word_size)
    if total > 65536:
        raise GdbMcpError(
            "count * word_size exceeds 65536 bytes", code="invalid_argument"
        )
    return _reply(
        manager.get(session_id),
        f"-data-read-memory-bytes {mi_quote(address)} {total}",
        15,
    )


@gdb_tool(states=STOPPED, destructive=True)
def gdb_memory_write(session_id: str, address: str, bytes_hex: str) -> dict[str, Any]:
    """Write at most 64 KiB of validated hexadecimal bytes."""
    clean = re.sub(r"\s+", "", bytes_hex)
    try:
        raw = bytes.fromhex(clean)
    except ValueError as exc:
        raise GdbMcpError(
            "bytes_hex is not valid hexadecimal", code="invalid_argument"
        ) from exc
    if not raw or len(raw) > 65536:
        raise GdbMcpError(
            "bytes_hex must encode 1 to 65536 bytes", code="invalid_argument"
        )
    return _reply(
        manager.get(session_id),
        f"-data-write-memory-bytes {mi_quote(address)} {clean}",
        15,
    )


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_memory_find(
    session_id: str, start: str, end: str, pattern: str
) -> dict[str, Any]:
    """Search an address range using GDB's find command."""
    for name, value in (("start", start), ("end", end), ("pattern", pattern)):
        _require_single_line(value, name)
    return _reply(manager.get(session_id), f"find {start}, {end}, {pattern}", 30)


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_disassemble(
    session_id: str,
    start: str = "",
    end: str = "",
    function: str = "",
    num_bytes: Annotated[int, Field(ge=0, le=4096)] = 0,
) -> dict[str, Any]:
    """Disassemble one function or one bounded address range."""
    if function and (start or end or num_bytes):
        raise GdbMcpError(
            "function is mutually exclusive with address selectors",
            code="invalid_argument",
        )
    if end and not start:
        raise GdbMcpError("end requires start", code="invalid_argument")
    if end and num_bytes:
        raise GdbMcpError(
            "end and num_bytes are mutually exclusive", code="invalid_argument"
        )
    session = manager.get(session_id)
    if function:
        return _reply(
            session,
            f"disassemble {_require_single_line(function, 'function')}",
            15,
        )
    start_value = start or "$pc"
    end_value = end or f"{start_value}+{int(num_bytes) if num_bytes else 256}"
    return _reply(
        session,
        f"-data-disassemble -s {mi_quote(start_value)} -e {mi_quote(end_value)} -- 0",
        15,
    )


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_source_list(
    session_id: str, location: str = "", count: SmallCount = 40
) -> dict[str, Any]:
    """List source without leaking a changed global listsize setting."""
    session = manager.get(session_id)
    shown = _reply(session, "show listsize", 5)
    match = re.search(r"(?:is|set to)\s+(\d+)", shown["output"], re.IGNORECASE)
    previous = int(match.group(1)) if match else 10
    _reply(session, f"set listsize {int(count)}", 5)
    try:
        command = (
            f"list {_require_single_line(location, 'location')}" if location else "list"
        )
        return _reply(session, command, 15)
    finally:
        _reply(session, f"set listsize {previous}", 5)


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_info_threads(session_id: str) -> dict[str, Any]:
    """List threads."""
    return _reply(manager.get(session_id), "-thread-info", 10)


@gdb_tool(states=STOPPED, destructive=True, idempotent=True)
def gdb_select_thread(session_id: str, thread_id: Positive) -> dict[str, Any]:
    """Select a thread."""
    session = manager.get(session_id)
    reply = _reply(session, f"-thread-select {int(thread_id)}", 5)
    session.selected_thread = int(thread_id)
    session.selected_frame = 0
    return reply


@gdb_tool(states=STOPPED, destructive=True, idempotent=True)
def gdb_select_frame(session_id: str, frame_number: NonNegative) -> dict[str, Any]:
    """Select a stack frame."""
    session = manager.get(session_id)
    reply = _reply(session, f"-stack-select-frame {int(frame_number)}", 5)
    session.selected_frame = int(frame_number)
    return reply


# Symbols, types, mutation, and settings -----------------------------------


def _info_command(session_id: str, category: str, regexp: str = "") -> dict[str, Any]:
    command = f"info {category}"
    if regexp:
        command += f" {_require_single_line(regexp, 'regexp')}"
    return _reply(manager.get(session_id), command, 30)


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_info_functions(session_id: str, regexp: str = "") -> dict[str, Any]:
    """List function symbols with paged console output."""
    return _info_command(session_id, "functions", regexp)


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_info_variables(session_id: str, regexp: str = "") -> dict[str, Any]:
    """List global/static variables with paged console output."""
    return _info_command(session_id, "variables", regexp)


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_info_sharedlibs(session_id: str) -> dict[str, Any]:
    """List loaded shared libraries."""
    return _info_command(session_id, "sharedlibrary")


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_info_files(session_id: str) -> dict[str, Any]:
    """List loaded files and sections."""
    return _info_command(session_id, "files")


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_info_proc_mappings(session_id: str) -> dict[str, Any]:
    """List process memory mappings."""
    return _info_command(session_id, "proc mappings")


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_ptype(session_id: str, name: str) -> dict[str, Any]:
    """Show a type definition."""
    return _reply(
        manager.get(session_id), f"ptype {_require_single_line(name, 'name')}", 15
    )


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_print_struct(
    session_id: str, expression: str, pretty: bool = True
) -> dict[str, Any]:
    """Print a struct while preserving the pretty-print setting."""
    session = manager.get(session_id)
    restore = _temporary_boolean_setting(session, "print pretty", pretty)
    try:
        return _reply(
            session, f"print {_require_single_line(expression, 'expression')}", 15
        )
    finally:
        restore()


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_sizeof(session_id: str, type_or_expr: str) -> dict[str, Any]:
    """Evaluate sizeof(type-or-expression)."""
    expression = f"sizeof({type_or_expr})"
    return _reply(
        manager.get(session_id), f"-data-evaluate-expression {mi_quote(expression)}", 10
    )


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_offsetof(session_id: str, struct_type: str, field: str) -> dict[str, Any]:
    """Evaluate a field byte offset."""
    expression = f"(unsigned long)&(({struct_type} *)0)->{field}"
    return _reply(
        manager.get(session_id), f"-data-evaluate-expression {mi_quote(expression)}", 10
    )


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_cast_print(session_id: str, address: str, cast_type: str) -> dict[str, Any]:
    """Cast and print a dereferenced address while preserving settings."""
    session = manager.get(session_id)
    restore = _temporary_boolean_setting(session, "print pretty", True)
    try:
        expression = f"*({cast_type})({address})"
        return _reply(
            session, f"print {_require_single_line(expression, 'expression')}", 15
        )
    finally:
        restore()


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_info_types(session_id: str, regexp: str = "") -> dict[str, Any]:
    """List type names with paged console output."""
    return _info_command(session_id, "types", regexp)


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_whatis(session_id: str, expression: str) -> dict[str, Any]:
    """Show an expression's type."""
    return _reply(
        manager.get(session_id),
        f"whatis {_require_single_line(expression, 'expression')}",
        10,
    )


@gdb_tool(states=STOPPED, destructive=True)
def gdb_set_variable(session_id: str, variable: str, value: str) -> dict[str, Any]:
    """Set a program variable or memory lvalue."""
    expression = f"{variable}={value}"
    return _reply(
        manager.get(session_id),
        f"-data-evaluate-expression {mi_quote(expression)}",
        10,
    )


@gdb_tool(states=NOT_RUNNING, destructive=True)
def gdb_set(session_id: str, setting: str, value: str) -> dict[str, Any]:
    """Set one single-line GDB option."""
    _require_single_line(setting, "setting")
    _require_single_line(value, "value")
    return _reply(manager.get(session_id), f"-gdb-set {setting} {value}", 10)


@gdb_tool(read_only=True, idempotent=True)
def gdb_show(session_id: str, setting: str) -> dict[str, Any]:
    """Show one single-line GDB option."""
    return _reply(
        manager.get(session_id), f"show {_require_single_line(setting, 'setting')}", 10
    )


# GDB/MI variable objects ---------------------------------------------------


@gdb_tool(states=STOPPED, destructive=True)
def gdb_var_create(
    session_id: str, expression: str, name: str = "-", frame: str = "*"
) -> dict[str, Any]:
    """Create a GDB/MI variable object for an expression."""
    return _reply(
        manager.get(session_id),
        f"-var-create {mi_quote(name)} {mi_quote(frame)} {mi_quote(expression)}",
        10,
    )


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_var_update(session_id: str, name: str = "*") -> dict[str, Any]:
    """Return incremental changes for one or all variable objects."""
    return _reply(
        manager.get(session_id), f"-var-update --all-values {mi_quote(name)}", 10
    )


@gdb_tool(states=STOPPED, read_only=True, idempotent=True)
def gdb_var_children(
    session_id: str,
    name: str,
    from_index: NonNegative = 0,
    to_index: Annotated[int, Field(ge=0, le=4096)] = 128,
) -> dict[str, Any]:
    """Read a bounded page of variable-object children."""
    if int(to_index) < int(from_index) or int(to_index) - int(from_index) > 512:
        raise GdbMcpError(
            "child range must be ordered and no larger than 512",
            code="invalid_argument",
        )
    return _reply(
        manager.get(session_id),
        f"-var-list-children --all-values {mi_quote(name)} {int(from_index)} {int(to_index)}",
        10,
    )


@gdb_tool(states=STOPPED, destructive=True)
def gdb_var_assign(session_id: str, name: str, expression: str) -> dict[str, Any]:
    """Assign a new value through a variable object."""
    return _reply(
        manager.get(session_id),
        f"-var-assign {mi_quote(name)} {mi_quote(expression)}",
        10,
    )


@gdb_tool(states=NOT_RUNNING, destructive=True, idempotent=True)
def gdb_var_delete(
    session_id: str, name: str, children_only: bool = False
) -> dict[str, Any]:
    """Delete a variable object or only its children."""
    flag = " -c" if children_only else ""
    return _reply(manager.get(session_id), f"-var-delete{flag} {mi_quote(name)}", 10)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
