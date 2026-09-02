"""MCP tools for a persistent, token-correlated GDB/MI runtime."""

from __future__ import annotations

import functools
import inspect
import json
import os
import re
import select
import shutil
import subprocess
import time
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
from .research import collect_modules, load_symbols_json, resolve_address

CleanupPolicy = Literal["auto", "kill", "detach", "disconnect", "quit"]
CommandMode = Literal["auto", "mi", "console"]
RegisterSet = Literal["general", "all"]
WordSize = Literal[1, 2, 4, 8]
ExecutionAction = Literal["run", "continue", "step", "next", "finish", "until"]
FollowFork = Literal["parent", "child"]
RecordMethod = Literal["auto", "full", "btrace"]
ReverseAction = Literal["continue", "step", "next", "finish"]
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
BreakpointHitLimit = Annotated[int, Field(ge=1, le=100000)]
TraceDepth = Annotated[int, Field(ge=0, le=64)]

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
        "Use gdb_log_breakpoint for auto-continuing sink traces, gdb_catch_crash for retained "
        "fatal-signal evidence, and gdb_modules before translating runtime addresses. "
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


def _notification_result(reply: dict[str, Any], compact: bool) -> dict[str, Any]:
    if not isinstance(compact, bool):
        raise GdbMcpError("compact must be boolean", code="invalid_argument")
    if not compact:
        return reply
    result = dict(reply)
    result["notifications"] = []
    result["notifications_omitted"] = int(reply.get("notification_count", 0))
    return result


def _complete_remote_connection(
    session: GdbSession,
    reply: dict[str, Any],
    *,
    baseline_stop_id: int,
    extended_remote: bool,
) -> dict[str, Any]:
    """Wait until target-select's asynchronous state is real and observable."""
    session.target_kind = "remote"
    if extended_remote:
        topology = session.inferiors(refresh=True)
        if topology["active_count"] == 0:
            session.set_state("idle", clear_stop=True)
            session.refresh_target_traits()
            return reply
    ready = session.wait_for_stop(after_stop_id=baseline_stop_id, timeout_sec=10.0)
    if ready["reason"] != "stopped":
        session.set_state("indeterminate")
        raise GdbMcpError(
            "remote target connected but did not publish its initial stop",
            code="target_state_timeout",
            retryable=True,
            details={
                "reason": ready["reason"],
                "baseline_stop_id": baseline_stop_id,
                "command_id": reply.get("command_id"),
            },
            recovery=[
                "Inspect gdb_events, interrupt the target, or reconnect the session."
            ],
        )
    session.refresh_target_traits()
    return reply


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


@gdb_tool(destructive=True)
def gdb_catch_crash(
    session_id: str,
    signals: list[str] | None = None,
    collect: list[str] | None = None,
    timeout_sec: ExecutionTimeout = 60,
    wait_timeout: WaitTimeout = 0,
) -> dict[str, Any]:
    """Continue under a retained fatal-signal filter and capture bounded evidence."""
    session = manager.get(session_id)
    job = session.start_crash_watch(
        signals=(
            ["SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL", "SIGFPE"]
            if signals is None
            else signals
        ),
        collect=(
            ["backtrace", "registers", "memory:$sp,256"]
            if collect is None
            else collect
        ),
        timeout_sec=float(timeout_sec),
    )
    if wait_timeout:
        deadline = time.monotonic() + float(wait_timeout)
        current = job
        terminal = {
            "stopped",
            "exited",
            "cancelled",
            "timed_out",
            "failed",
            "crashed",
            "unexpected_stop",
        }
        while current["state"] not in terminal:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            current = session.execution_status(
                job["job_id"],
                after_revision=current["revision"],
                wait_timeout=remaining,
            )
        return current
    return job


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
    session_id: str,
    target: str,
    extended_remote: bool = False,
    compact: bool = False,
) -> dict[str, Any]:
    """Connect to a GDB remote target such as host:port or a serial device."""
    session = manager.get(session_id)
    kind = "extended-remote" if extended_remote else "remote"
    baseline_stop_id = session.stop_id
    reply = _reply(
        session,
        f"-target-select {kind} {_require_single_line(target, 'target')}",
        30,
    )
    reply = _complete_remote_connection(
        session,
        reply,
        baseline_stop_id=baseline_stop_id,
        extended_remote=extended_remote,
    )
    return _notification_result(reply, compact)


@gdb_tool(states=NOT_RUNNING, destructive=True, idempotent=True, open_world=True)
def gdb_remote_disconnect(session_id: str, compact: bool = False) -> dict[str, Any]:
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
    return _notification_result(reply, compact)


@gdb_tool(states=NOT_RUNNING, destructive=True, open_world=True)
def gdb_connect_profile(
    session_id: str,
    profile: dict[str, Any],
    compact: bool = True,
) -> dict[str, Any]:
    """Apply bounded inline target setup and connect to a remote target in one call."""
    if not isinstance(profile, dict):
        raise GdbMcpError("profile must be an object", code="invalid_argument")
    allowed = {
        "architecture",
        "sysroot",
        "target",
        "endian",
        "commands",
        "extended_remote",
    }
    unknown = sorted(set(profile).difference(allowed))
    if unknown:
        raise GdbMcpError(
            "profile contains unknown fields",
            code="invalid_argument",
            details={"unknown": unknown},
        )
    target = profile.get("target")
    if not isinstance(target, str):
        raise GdbMcpError("profile.target must be a string", code="invalid_argument")
    target = _require_single_line(target, "target")
    commands = profile.get("commands", [])
    if not isinstance(commands, list) or not 0 <= len(commands) <= 16 or not all(
        isinstance(command, str) for command in commands
    ):
        raise GdbMcpError(
            "profile.commands must contain at most 16 strings",
            code="invalid_argument",
        )
    architecture = profile.get("architecture", "")
    sysroot = profile.get("sysroot", "")
    endian = profile.get("endian", "")
    extended_remote = profile.get("extended_remote", False)
    for name, value in (("architecture", architecture), ("sysroot", sysroot)):
        if not isinstance(value, str) or len(value) > 4096 or any(
            char in value for char in "\r\n\x00"
        ):
            raise GdbMcpError(
                f"profile.{name} must be one string of at most 4096 characters",
                code="invalid_argument",
            )
    if endian not in {"", "auto", "little", "big"}:
        raise GdbMcpError(
            "profile.endian must be auto, little, or big", code="invalid_argument"
        )
    if not isinstance(extended_remote, bool):
        raise GdbMcpError(
            "profile.extended_remote must be boolean", code="invalid_argument"
        )
    commands = [
        _require_single_line(command, "profile command") for command in commands
    ]
    session = manager.get(session_id)
    setup: list[dict[str, Any]] = []
    with session.command_lock:
        try:
            if architecture:
                setup.append(
                    _reply(
                        session,
                        f"set architecture {_require_single_line(architecture, 'architecture')}",
                        10,
                    )
                )
            if sysroot:
                local_root = str(Path(sysroot).expanduser().resolve())
                setup.append(_reply(session, f"set sysroot {cli_quote(local_root)}", 10))
                session.sysroot = local_root
            if endian:
                setup.append(_reply(session, f"set endian {endian}", 10))
            for command in commands:
                setup.append(_reply(session, command, 30))
            kind = "extended-remote" if extended_remote else "remote"
            baseline_stop_id = session.stop_id
            connected = _reply(
                session,
                f"-target-select {kind} {target}",
                30,
            )
        except GdbMcpError as exc:
            raise GdbMcpError(
                exc.message,
                code=exc.code,
                retryable=exc.retryable,
                details={**exc.details, "setup_steps_completed": len(setup)},
                recovery=exc.recovery,
            ) from exc
        connected = _complete_remote_connection(
            session,
            connected,
            baseline_stop_id=baseline_stop_id,
            extended_remote=extended_remote,
        )
        return {
            "setup": setup,
            "connected": _notification_result(connected, compact),
            "profile": {
                "architecture": architecture or None,
                "sysroot": session.sysroot,
                "target": target,
                "endian": endian or None,
                "command_count": len(commands),
                "extended_remote": extended_remote,
            },
        }


@gdb_tool(states=NOT_RUNNING, destructive=True, open_world=True)
def gdb_rr_replay(
    session_id: str,
    trace_dir: str,
    rr_path: str = "rr",
    startup_timeout_sec: CommandTimeout = 15,
    compact: bool = True,
) -> dict[str, Any]:
    """Launch an rr replay server on a random local port and connect this session."""
    session = manager.get(session_id)
    executable = shutil.which(rr_path)
    if executable is None:
        raise GdbMcpError(
            f"rr executable {rr_path!r} was not found", code="adapter_unavailable"
        )
    trace = Path(trace_dir).expanduser().resolve()
    if not trace.is_dir():
        raise GdbMcpError("trace_dir must be an rr trace directory", code="invalid_argument")
    try:
        process = subprocess.Popen(
            [executable, "replay", "-s", "0", str(trace)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        raise GdbMcpError(
            f"could not launch rr: {exc}", code="adapter_unavailable"
        ) from exc
    output: list[str] = []
    port = None
    deadline = time.monotonic() + float(startup_timeout_sec)
    try:
        while time.monotonic() < deadline and process.poll() is None:
            if process.stdout is None:
                break
            readable, _, _ = select.select(
                [process.stdout], [], [], min(0.25, deadline - time.monotonic())
            )
            if not readable:
                continue
            line = process.stdout.readline()
            if not line:
                continue
            output.append(line[:4096])
            joined = "".join(output)[-16_384:]
            match = re.search(
                r"(?:Listening on (?:port |[^:\s]+:)|localhost:)(\d{1,5})",
                joined,
                re.IGNORECASE,
            )
            if match:
                port = int(match.group(1))
                break
        if port is None:
            raise GdbMcpError(
                "rr replay did not publish a listening port",
                code="adapter_start_timeout" if process.poll() is None else "adapter_failed",
                details={"output": "".join(output)[-16_384:], "returncode": process.poll()},
            )
        with session.command_lock:
            baseline_stop_id = session.stop_id
            connected = _reply(
                session, f"-target-select extended-remote localhost:{port}", 30
            )
            connected = _complete_remote_connection(
                session,
                connected,
                baseline_stop_id=baseline_stop_id,
                extended_remote=True,
            )
            session._adapter_processes.append(process)
        return {
            "adapter": "rr",
            "trace_dir": str(trace),
            "pid": process.pid,
            "port": port,
            "startup_output": "".join(output)[-16_384:],
            "connected": _notification_result(connected, compact),
        }
    except Exception:
        if process not in session._adapter_processes:
            try:
                process.terminate()
                process.wait(timeout=2.0)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass
        raise


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
    # GDB 17 requires a quoted filename with spaces. GDB 15's core-file parser
    # instead treats those quote bytes as part of the filename and expects the
    # complete remainder literally. Probe the modern form, then retry only the
    # older parser's exact quote-leak failure. _wire_command rejects newlines.
    try:
        reply = _reply(session, f"core-file {cli_quote(core)}", 30)
    except GdbMcpError as exc:
        if f'"{core}"' not in exc.message:
            raise
        reply = _reply(session, f"core-file {core}", 30)
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


@gdb_tool(destructive=True, open_world=True)
def gdb_load_symbols_json(
    session_id: str,
    file: str,
    format: Literal["ghidra-decomp", "exports", "plain"] = "ghidra-decomp",
    base_address: str = "",
    analysis_base_address: str = "",
    binary_path: str = "",
) -> dict[str, Any]:
    """Convert bounded address/name data into a temporary ELF symbol companion and load it."""
    return load_symbols_json(
        manager.get(session_id),
        file=file,
        format_name=format,
        base_address=base_address,
        analysis_base_address=analysis_base_address,
        binary_path=binary_path,
    )


@gdb_tool(read_only=True, idempotent=True, open_world=True)
def gdb_modules(
    session_id: str,
    include_sections: bool = False,
    include_hashes: bool = False,
    max_sections: Annotated[int, Field(ge=1, le=4096)] = 256,
    sysroot: str = "",
) -> dict[str, Any]:
    """Normalize mappings, modules, ELF identity, load slides, sections, and debug evidence."""
    return collect_modules(
        manager.get(session_id),
        include_sections=include_sections,
        include_hashes=include_hashes,
        max_sections=int(max_sections),
        sysroot=sysroot,
    )


@gdb_tool(read_only=True, idempotent=True, open_world=True)
def gdb_address_info(
    session_id: str,
    address: str,
    sysroot: str = "",
) -> dict[str, Any]:
    """Resolve a runtime address to exact module identity, linked VA, RVA, and section."""
    raw_address = _require_single_line(address, "address")
    session = manager.get(session_id)
    expression_stop_id = None
    try:
        value = int(raw_address, 0)
    except ValueError:
        with session.command_lock:
            if session.run_state != "stopped":
                raise GdbMcpError(
                    "non-literal addresses require a stopped target",
                    code="invalid_argument",
                )
            expression_stop_id = session.stop_id
            payload = _payload(
                _reply(
                    session,
                    f"-data-evaluate-expression {mi_quote(raw_address)}",
                    10,
                )
            )
        rendered = payload.get("value", "") if isinstance(payload, dict) else ""
        match = re.match(r"0x[0-9a-fA-F]+", str(rendered))
        if not match:
            raise GdbMcpError(
                "address expression did not evaluate to an address",
                code="invalid_argument",
            )
        value = int(match.group(0), 16)
    modules = collect_modules(
        session,
        include_sections=True,
        include_hashes=False,
        max_sections=4096,
        sysroot=sysroot,
    )
    if expression_stop_id is not None and modules["stop_id"] != expression_stop_id:
        raise GdbMcpError(
            "stop epoch changed while resolving the address expression",
            code="stale_stop",
            details={
                "expression_stop_id": expression_stop_id,
                "module_stop_id": modules["stop_id"],
            },
            retryable=True,
        )
    return {**resolve_address(modules, value), "stop_id": modules["stop_id"]}


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


@gdb_tool(states=STOPPED, destructive=True)
def gdb_record_start(
    session_id: str,
    method: RecordMethod = "auto",
) -> dict[str, Any]:
    """Start GDB process recording with explicit btrace/full fallback evidence."""
    if method not in {"auto", "full", "btrace"}:
        raise GdbMcpError(
            "method must be auto, full, or btrace", code="invalid_argument"
        )
    session = manager.get(session_id)
    methods = ["btrace", "full"] if method == "auto" else [method]
    errors: dict[str, Any] = {}
    with session.command_lock:
        for candidate in methods:
            try:
                reply = _reply(session, f"record {candidate}", 30)
                return {
                    "method": candidate,
                    "requested": method,
                    "reply": reply,
                    "fallback_errors": errors,
                }
            except GdbMcpError as exc:
                errors[candidate] = {"code": exc.code, "message": exc.message}
    raise GdbMcpError(
        "no requested GDB recording backend could start",
        code="record_unavailable",
        details={"requested": method, "errors": errors},
    )


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_record_status(session_id: str) -> dict[str, Any]:
    """Return bounded GDB recording status and active instruction bounds."""
    return _reply(manager.get(session_id), "info record", 15)


@gdb_tool(states=STOPPED, destructive=True, idempotent=True)
def gdb_record_stop(session_id: str) -> dict[str, Any]:
    """Stop and discard the active GDB recording target."""
    return _reply(manager.get(session_id), "record stop", 15)


@gdb_tool(states=STOPPED, destructive=True)
def gdb_reverse(
    session_id: str,
    action: ReverseAction = "continue",
    instruction: bool = False,
) -> dict[str, Any]:
    """Start a reverse continue/step/next/finish operation and return on ^running."""
    commands = {
        "continue": "reverse-continue",
        "step": "reverse-stepi" if instruction else "reverse-step",
        "next": "reverse-nexti" if instruction else "reverse-next",
        "finish": "reverse-finish",
    }
    if action not in commands:
        raise GdbMcpError(
            "action must be continue, step, next, or finish", code="invalid_argument"
        )
    if action == "finish" and instruction:
        raise GdbMcpError(
            "instruction is not valid for reverse finish", code="invalid_argument"
        )
    return _reply(manager.get(session_id), commands[action], 30)


# Breakpoints ---------------------------------------------------------------


def _breakpoint_command(
    location: str, condition: str, temporary: bool, hardware: bool
) -> str:
    if not isinstance(location, str) or not isinstance(condition, str):
        raise GdbMcpError(
            "location and condition must be strings", code="invalid_argument"
        )
    if not isinstance(temporary, bool) or not isinstance(hardware, bool):
        raise GdbMcpError(
            "temporary and hardware must be boolean", code="invalid_argument"
        )
    _require_single_line(location, "location")
    if len(location) > 4096:
        raise GdbMcpError("location is too long", code="invalid_argument")
    if len(condition) > 4096 or "\n" in condition or "\r" in condition:
        raise GdbMcpError(
            "condition must be one line of at most 4096 characters",
            code="invalid_argument",
        )
    command = "-break-insert"
    if temporary:
        command += " -t"
    if hardware:
        command += " -h"
    if condition:
        command += f" -c {mi_quote(condition)}"
    return command + f" {mi_quote(location)}"


@gdb_tool(states=NOT_RUNNING, destructive=True)
def gdb_breakpoint(
    session_id: str,
    location: str = "",
    condition: str = "",
    temporary: bool = False,
    hardware: bool = False,
    locations: list[str] | None = None,
) -> dict[str, Any]:
    """Set one breakpoint, or up to 128 independently reported bulk breakpoints."""
    if locations is not None and location:
        raise GdbMcpError(
            "use either location or locations, not both", code="invalid_argument"
        )
    if locations is None:
        session = manager.get(session_id)
        reply = _reply(
            session,
            _breakpoint_command(location, condition, temporary, hardware),
            10,
        )
        session.reject_managed_breakpoint_conflict(reply, location)
        return reply
    if not isinstance(locations, list) or not 1 <= len(locations) <= 128 or not all(
        isinstance(item, str) for item in locations
    ):
        raise GdbMcpError(
            "locations must contain 1 to 128 strings", code="invalid_argument"
        )
    session = manager.get(session_id)
    items: list[dict[str, Any]] = []
    with session.command_lock:
        for index, item in enumerate(locations):
            try:
                reply = _reply(
                    session,
                    _breakpoint_command(item, condition, temporary, hardware),
                    10,
                )
                session.reject_managed_breakpoint_conflict(reply, item)
                items.append(
                    {"index": index, "location": item, "ok": True, "reply": reply}
                )
            except GdbMcpError as exc:
                items.append(
                    {
                        "index": index,
                        "location": item,
                        "ok": False,
                        "error": {"code": exc.code, "message": exc.message},
                    }
                )
    return {
        "items": items,
        "requested": len(locations),
        "created": sum(item["ok"] for item in items),
        "failed": sum(not item["ok"] for item in items),
    }


@gdb_tool(states=NOT_RUNNING, destructive=True)
def gdb_log_breakpoint(
    session_id: str,
    location: str,
    expressions: list[str],
    condition: str = "",
    limit: BreakpointHitLimit = 100,
    backtrace_depth: TraceDepth = 0,
) -> dict[str, Any]:
    """Create a bounded expression/backtrace logger that auto-continues its stops."""
    return manager.get(session_id).create_log_breakpoint(
        location,
        expressions=expressions,
        condition=condition,
        limit=int(limit),
        backtrace_depth=int(backtrace_depth),
    )


@gdb_tool(read_only=True, idempotent=True)
def gdb_log_read(
    session_id: str,
    log_id: str,
    after_cursor: NonNegative = 0,
    limit: EventLimit = 50,
    encoding: Literal["json", "jsonl"] = "json",
) -> dict[str, Any]:
    """Read retained logging-breakpoint hits using a monotonic per-log cursor."""
    if encoding not in {"json", "jsonl"}:
        raise GdbMcpError("encoding must be json or jsonl", code="invalid_argument")
    result = manager.get(session_id).read_log_breakpoint(
        log_id, after_cursor=int(after_cursor), limit=int(limit)
    )
    if encoding == "jsonl":
        result["jsonl"] = "\n".join(
            json.dumps(item, separators=(",", ":"), sort_keys=True)
            for item in result["hits"]
        )
        result["hits"] = []
    result["encoding"] = encoding
    return result


@gdb_tool(read_only=True, idempotent=True)
def gdb_log_list(session_id: str) -> dict[str, Any]:
    """List retained logging breakpoints and their hit counts."""
    return manager.get(session_id).list_log_breakpoints()


@gdb_tool(states=NOT_RUNNING, destructive=True, idempotent=True)
def gdb_log_delete(session_id: str, log_id: str) -> dict[str, Any]:
    """Delete a managed logging breakpoint and its retained evidence."""
    return manager.get(session_id).delete_log_breakpoint(log_id)


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


@gdb_tool(states=NOT_RUNNING, destructive=True, open_world=True)
def gdb_debug_config(
    session_id: str,
    source_substitutions: list[dict[str, str]] | None = None,
    debug_directories: list[str] | None = None,
    debuginfod: bool = False,
) -> dict[str, Any]:
    """Configure source maps and split-debug lookup; network fetch stays off by default."""
    substitutions = source_substitutions or []
    directories = debug_directories or []
    if not isinstance(substitutions, list) or len(substitutions) > 64:
        raise GdbMcpError(
            "source_substitutions must contain at most 64 mappings",
            code="invalid_argument",
        )
    if not isinstance(directories, list) or len(directories) > 64 or not all(
        isinstance(item, str) for item in directories
    ):
        raise GdbMcpError(
            "debug_directories must contain at most 64 paths",
            code="invalid_argument",
        )
    if not isinstance(debuginfod, bool):
        raise GdbMcpError("debuginfod must be boolean", code="invalid_argument")
    session = manager.get(session_id)
    replies: list[dict[str, Any]] = []
    normalized_substitutions: list[dict[str, str]] = []
    normalized_directories: list[str] = []
    with session.command_lock:
        for index, mapping in enumerate(substitutions):
            if not isinstance(mapping, dict) or set(mapping) != {"from", "to"}:
                raise GdbMcpError(
                    f"source substitution {index} must contain only from and to",
                    code="invalid_argument",
                )
            source = mapping.get("from")
            target = mapping.get("to")
            if not isinstance(source, str) or not isinstance(target, str):
                raise GdbMcpError(
                    f"source substitution {index} paths must be strings",
                    code="invalid_argument",
                )
            source = _require_single_line(source, "source path")
            target = str(
                Path(_require_single_line(target, "local source path"))
                .expanduser()
                .resolve()
            )
            replies.append(
                _reply(
                    session,
                    f"set substitute-path {cli_quote(source)} {cli_quote(target)}",
                    10,
                )
            )
            normalized_substitutions.append({"from": source, "to": target})
        if debug_directories is not None:
            for directory in directories:
                path = str(
                    Path(_require_single_line(directory, "debug directory"))
                    .expanduser()
                    .resolve()
                )
                normalized_directories.append(path)
            replies.append(
                _reply(
                    session,
                    f"set debug-file-directory {cli_quote(os.pathsep.join(normalized_directories))}",
                    10,
                )
            )
        replies.append(
            _reply(
                session,
                f"set debuginfod enabled {'on' if debuginfod else 'off'}",
                10,
            )
        )
        session.source_substitutions.extend(normalized_substitutions)
        if debug_directories is not None:
            session.debug_directories = normalized_directories
        session.debuginfod_enabled = debuginfod
    return {
        "source_substitutions": normalized_substitutions,
        "debug_directories": (
            normalized_directories if debug_directories is not None else None
        ),
        "debuginfod": debuginfod,
        "replies": replies,
    }


@gdb_tool(states=NOT_RUNNING, read_only=True, idempotent=True)
def gdb_debug_status(session_id: str) -> dict[str, Any]:
    """Show source substitution, debug directory, sysroot, and debuginfod state."""
    session = manager.get(session_id)
    with session.command_lock:
        return {
            "substitute_path": _reply(session, "show substitute-path", 10),
            "debug_file_directory": _reply(
                session, "show debug-file-directory", 10
            ),
            "sysroot": _reply(session, "show sysroot", 10),
            "debuginfod": _reply(session, "show debuginfod enabled", 10),
        }


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
